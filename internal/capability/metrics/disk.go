// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"strconv"
	"strings"
)

type diskCounters struct {
	name               string
	read, write, ticks uint64
}
type diskTable struct{ byName, byNumber map[string]diskCounters }

// parseDiskStats 保留 sector 原值（Linux 固定 512 B），不把它当作字节或速率。
func parseDiskStats(data []byte) diskTable {
	table := diskTable{byName: make(map[string]diskCounters), byNumber: make(map[string]diskCounters)}
	scanner := lines(data)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 14 || !validDeviceName(fields[2]) {
			continue
		}
		if _, err := strconv.ParseUint(fields[0], 10, 32); err != nil {
			continue
		}
		if _, err := strconv.ParseUint(fields[1], 10, 32); err != nil {
			continue
		}
		var values [3]uint64
		valid := true
		for index, field := range []int{5, 9, 12} {
			value, err := strconv.ParseUint(fields[field], 10, 64)
			if err != nil {
				valid = false
				break
			}
			values[index] = value
		}
		if !valid {
			continue
		}
		counter := diskCounters{name: fields[2], read: values[0], write: values[1], ticks: values[2]}
		table.byName[fields[2]] = counter
		table.byNumber[fields[0]+":"+fields[1]] = counter
		if len(table.byName) >= maxDevices {
			break
		}
	}
	if scanner.Err() != nil {
		return diskTable{}
	}
	return table
}

// parseMountInfo 按 major:minor 对应 dm/LVM 等设备；不以用户路径推测设备名。
// 返回值只用于匹配，实际 statfs 的路径始终来自受控 Mount 配置。
func parseMountInfo(data []byte) map[string]string {
	result := make(map[string]string)
	scanner := lines(data)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if separator < 6 || separator+3 >= len(fields) {
			continue
		}
		device := strings.Split(fields[2], ":")
		if len(device) != 2 {
			continue
		}
		if _, err := strconv.ParseUint(device[0], 10, 32); err != nil {
			continue
		}
		if _, err := strconv.ParseUint(device[1], 10, 32); err != nil {
			continue
		}
		mount := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(fields[4])
		result[mount] = fields[2]
		if len(result) >= maxDevices {
			break
		}
	}
	if scanner.Err() != nil {
		return nil
	}
	return result
}
