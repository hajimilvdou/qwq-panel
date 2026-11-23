// SPDX-License-Identifier: AGPL-3.0-only

package routingrules

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"
)

// AddrRange 表示闭区间 [Start, End] 的无重叠合并 IP 段（值类型、零指针，CPU Cache 友好）。
type AddrRange struct {
	Start netip.Addr
	End   netip.Addr
}

// BuildMergedRanges 在规则包加载阶段一次性将任意重叠、相邻或乱序的 CIDR 合并为互不相交的有序闭区间切片，
// 将查询复杂度严格收敛至 O(log N)。
func BuildMergedRanges(prefixes []netip.Prefix) []AddrRange {
	if len(prefixes) == 0 {
		return nil
	}
	raw := make([]AddrRange, 0, len(prefixes))
	for _, p := range prefixes {
		if !p.IsValid() {
			continue
		}
		mp := p.Masked()
		start := mp.Addr().Unmap()
		end := prefixLastAddr(mp)
		raw = append(raw, AddrRange{Start: start, End: end})
	}
	if len(raw) == 0 {
		return nil
	}

	slices.SortFunc(raw, func(a, b AddrRange) int {
		if c := a.Start.Compare(b.Start); c != 0 {
			return c
		}
		return b.End.Compare(a.End)
	})

	merged := make([]AddrRange, 0, len(raw))
	cur := raw[0]
	for _, next := range raw[1:] {
		if next.Start.Compare(cur.End) <= 0 || cur.End.Next() == next.Start {
			if next.End.Compare(cur.End) > 0 {
				cur.End = next.End
			}
			continue
		}
		merged = append(merged, cur)
		cur = next
	}
	merged = append(merged, cur)
	return slices.Clip(merged)
}

// MatchMergedRanges 以零堆分配、纯 O(log N) 二分查找判定目标 IP 是否命中合并区间集。
func MatchMergedRanges(addr netip.Addr, ranges []AddrRange) bool {
	if len(ranges) == 0 || !addr.IsValid() {
		return false
	}
	target := addr.Unmap()
	idx, exact := slices.BinarySearchFunc(ranges, target, func(r AddrRange, t netip.Addr) int {
		return r.Start.Compare(t)
	})
	if exact {
		return true
	}
	return idx > 0 && ranges[idx-1].End.Compare(target) >= 0
}

func prefixLastAddr(p netip.Prefix) netip.Addr {
	if p.Addr().Is4In6() {
		bits := p.Bits() - 96
		if bits < 0 {
			bits = 0
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), bits)
	}
	addr := p.Addr().Unmap()
	bits := p.Bits()
	if addr.Is4() {
		b := addr.As4()
		v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		if bits < 32 {
			mask := uint32(0xFFFFFFFF) >> bits
			v |= mask
		}
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	b := addr.As16()
	for bit := bits; bit < 128; bit++ {
		b[bit/8] |= 1 << (7 - (bit % 8))
	}
	return netip.AddrFrom16(b)
}

// CompactDomainSet 将域名列表压缩进单个只读连续字节池 + uint32 偏移表（零指针，零 GC 扫描开销）。
type CompactDomainSet struct {
	blob    string
	offsets []uint32
}

// NewCompactDomainSet 从去重或未去重的域名切片构建零指针紧凑域名集。
func NewCompactDomainSet(domains []string) CompactDomainSet {
	if len(domains) == 0 {
		return CompactDomainSet{}
	}
	norm := make([]string, 0, len(domains))
	for _, d := range domains {
		s := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if s != "" {
			norm = append(norm, s)
		}
	}
	slices.Sort(norm)
	norm = slices.Compact(norm)

	totalBytes := 0
	for _, s := range norm {
		totalBytes += len(s)
	}
	var sb strings.Builder
	sb.Grow(totalBytes)
	offsets := make([]uint32, len(norm)+1)
	pos := uint32(0)
	for i, s := range norm {
		offsets[i] = pos
		sb.WriteString(s)
		pos += uint32(len(s))
	}
	offsets[len(norm)] = pos
	return CompactDomainSet{
		blob:    sb.String(),
		offsets: offsets,
	}
}

// Len 返回集合中去重后的域名条目数。
func (s CompactDomainSet) Len() int {
	if len(s.offsets) == 0 {
		return 0
	}
	return len(s.offsets) - 1
}

// ContainsExact 零分配二分查找精确域名。
func (s CompactDomainSet) ContainsExact(domain string) bool {
	n := s.Len()
	if n == 0 || domain == "" {
		return false
	}
	lo, hi := 0, n-1
	for lo <= hi {
		mid := int(uint(lo+hi) >> 1)
		cand := s.blob[s.offsets[mid]:s.offsets[mid+1]]
		c := cmp.Compare(cand, domain)
		if c == 0 {
			return true
		}
		if c < 0 {
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return false
}

// MatchDomainOrParent 零分配逐级匹配域名本身或其父级后缀。
func (s CompactDomainSet) MatchDomainOrParent(host string) bool {
	if s.Len() == 0 {
		return false
	}
	cur := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	for cur != "" {
		if s.ContainsExact(cur) {
			return true
		}
		dot := strings.IndexByte(cur, '.')
		if dot < 0 {
			return false
		}
		cur = cur[dot+1:]
	}
	return false
}
