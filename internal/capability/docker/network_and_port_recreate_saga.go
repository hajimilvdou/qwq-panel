// SPDX-License-Identifier: AGPL-3.0-only

// 受控 Docker 网络热插拔与端口无损重建 Saga：
// 在不向沙箱插件开放原始 /containers/create（防止伪造 Privileged / 根目录挂载逃逸）的前提下，
// 在受控 root helper (qwq-capability) 内部安全实现：
//   1. Docker 网络白名单管理（枚举、新建隔离/纯内网 Bridge 网络、在线免重启挂载与解挂多网络、DNS 别名与静态 IP）；
//   2. 宿主机可绑定网卡 IP 探测与空闲高位端口防冲突分配；
//   3. 独立容器修改端口映射的「前置冲突预检 + 未挂卷可写层 SizeRw 保护 + 停旧改名热备 + 建新恢复多网络 + 验活失败自动回滚」五步无损事务。

package docker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

var (
	networkNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
	aliasNamePattern   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
)

// builtinProtectedNetworks 禁止被用户删除的 Docker 内置系统网络。
var builtinProtectedNetworks = map[string]bool{
	"bridge": true,
	"host":   true,
	"none":   true,
}

// ======================== 1. 扩展端点白名单辅助（供 service.go isAllowedDockerEndpoint 调用） ========================

// IsAllowedNetworkOrInspectEndpoint 补充只读网络查询、安全删除自定义网络与容器重命名白名单。
// 注意：`/networks/create`、`/networks/{id}/connect`、`/containers/create` 仍不走通用透传，
// 必须走下方带强参数结构校验的专用方法！
func IsAllowedNetworkOrInspectEndpoint(method, cleanPath string, segs []string) bool {
	switch method {
	case http.MethodGet:
		if cleanPath == "/networks" {
			return true
		}
		if len(segs) == 2 && segs[0] == "networks" && isValidContainerID(segs[1]) {
			return true
		}
		if len(segs) == 3 && segs[0] == "images" && isValidImageInspectSegment(segs[1]) && segs[2] == "json" {
			return true
		}
	case http.MethodPost:
		// 允许重命名容器（不含特权变更能力）
		if len(segs) == 3 && segs[0] == "containers" && isValidContainerID(segs[1]) && segs[2] == "rename" {
			return true
		}
	case http.MethodDelete:
		if len(segs) == 2 && segs[0] == "networks" && isValidContainerID(segs[1]) && !builtinProtectedNetworks[strings.ToLower(segs[1])] {
			return true
		}
	}
	return false
}

// ======================== 2. 宿主机可绑定网卡 IP 枚举与空闲端口分配 ========================

// HostBindableIP 描述宿主机上一个可供容器端口映射绑定的真实地址选项。
type HostBindableIP struct {
	IP        string `json:"ip"`
	Interface string `json:"interface"`
	Scope     string `json:"scope"` // "loopback" | "overlay_or_lan" | "public"
	IsIPv6    bool   `json:"is_ipv6"`
	Label     string `json:"label"`
}

// ListHostBindableIPs 枚举本机可用于端口映射的网卡地址（自动过滤 docker0 / br-* / veth* 临时虚拟网桥，保留 lo、Tailscale/WireGuard 组网网卡与物理网卡）。
func ListHostBindableIPs() ([]HostBindableIP, error) {
	out := []HostBindableIP{
		{IP: "127.0.0.1", Interface: "lo", Scope: "loopback", IsIPv6: false, Label: "127.0.0.1（仅本机回环 · 隐身推荐）"},
		{IP: "0.0.0.0", Interface: "*", Scope: "public", IsIPv6: false, Label: "0.0.0.0（所有 IPv4 网卡 · 公网直连）"},
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return out, nil
	}
	seen := map[string]bool{"127.0.0.1": true, "0.0.0.0": true}

	for _, iface := range ifaces {
		if (iface.Flags & net.FlagUp) == 0 {
			continue
		}
		name := iface.Name
		// 跳过容器临时虚拟网桥，避免绑定到随容器销毁而消失的接口
		if name == "docker0" || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "virbr") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, rawAddr := range addrs {
			var ipStr string
			switch v := rawAddr.(type) {
			case *net.IPNet:
				ipStr = v.IP.String()
			case *net.IPAddr:
				ipStr = v.IP.String()
			}
			addr, perr := netip.ParseAddr(ipStr)
			if perr != nil {
				continue
			}
			addr = addr.Unmap()
			if !addr.IsValid() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
				continue
			}
			canon := addr.String()
			if seen[canon] {
				continue
			}
			seen[canon] = true

			if addr.IsLoopback() {
				out = append(out, HostBindableIP{
					IP: canon, Interface: name, Scope: "loopback", IsIPv6: addr.Is6(),
					Label: fmt.Sprintf("%s（本机 IPv6 回环）", canon),
				})
				continue
			}
			scope := "public"
			desc := "公网网卡"
			if addr.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(addr) {
				scope = "overlay_or_lan"
				desc = "内网 / 组网接口 " + name
			} else {
				desc = "网卡 " + name
			}
			out = append(out, HostBindableIP{
				IP: canon, Interface: name, Scope: scope, IsIPv6: addr.Is6(),
				Label: fmt.Sprintf("%s（%s）", canon, desc),
			})
		}
	}
	return out, nil
}

// AllocateFreeHostPort 在 20000..60000 区间分配一个与宿主保留端口及现有 TCP/UDP 监听均不冲突的空闲端口。
func AllocateFreeHostPort(bindIP string, proto string, reserved map[uint16]bool) (uint16, error) {
	if bindIP == "" {
		bindIP = "127.0.0.1"
	}
	for attempt := 0; attempt < 96; attempt++ {
		var rnd [2]byte
		_, _ = rand.Read(rnd[:])
		cand := uint16(20000 + (int(binary.LittleEndian.Uint16(rnd[:])) % 40000))
		if reserved[cand] {
			continue
		}
		if isHostPortAvailable(bindIP, cand, proto) {
			return cand, nil
		}
	}
	return 0, errors.New("PORT_EXHAUSTED: 未能在 20000..60000 区间找到空闲端口，请手动指定")
}

func isHostPortAvailable(bindIP string, port uint16, proto string) bool {
	addr := net.JoinHostPort(bindIP, strconv.Itoa(int(port)))
	needTCP := proto == "" || proto == "tcp" || proto == "both"
	needUDP := proto == "udp" || proto == "both"

	if needTCP {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return false
		}
		_ = ln.Close()
	}
	if needUDP {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return false
		}
		_ = pc.Close()
	}
	return true
}

// ======================== 3. 受控 Docker 网络创建与在线免重启挂载/卸载 ========================

// CreateNetworkInput 是 docker.network.create 的受控入参。
type CreateNetworkInput struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver,omitempty"` // 仅允许 "" 或 "bridge"
	Internal   bool              `json:"internal"`         // true = 纯内网隔离（禁止容器主动出站连接公网，非常适合 MySQL/Redis！）
	EnableIPv6 bool              `json:"enable_ipv6"`      // 是否开启双栈容器子网
	SubnetCIDR string            `json:"subnet_cidr,omitempty"`
	GatewayIP  string            `json:"gateway_ip,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// CreateControlledBridgeNetwork 强制仅允许创建 `bridge` 驱动的隔离网络（拦截 `macvlan`/`host` 等接管物理网卡的高危驱动）。
func (r *ControlledDockerCapabilityRunner) CreateControlledBridgeNetwork(ctx context.Context, in CreateNetworkInput) (string, error) {
	name := strings.TrimSpace(in.Name)
	if !networkNamePattern.MatchString(name) || builtinProtectedNetworks[strings.ToLower(name)] {
		return "", errors.New("INVALID_NETWORK_NAME: 网络名称仅允许字母、数字、连字符和下划线，且不可与内置网络重名")
	}
	driver := strings.ToLower(strings.TrimSpace(in.Driver))
	if driver == "" {
		driver = "bridge"
	}
	if driver != "bridge" {
		return "", fmt.Errorf("UNSUPPORTED_NETWORK_DRIVER: 出于安全隔离策略，仅允许创建 bridge 网络，拒绝驱动 %q", driver)
	}

	labels := make(map[string]string, len(in.Labels)+1)
	for k, v := range in.Labels {
		k = strings.TrimSpace(k)
		if k == "" || strings.HasPrefix(strings.ToLower(k), "com.docker.") || len(k) > 128 || len(v) > 256 {
			continue
		}
		labels[k] = v
	}
	labels["com.qwq.managed"] = "true"

	reqBody := map[string]any{
		"Name":           name,
		"CheckDuplicate": true,
		"Driver":         "bridge",
		"Internal":       in.Internal,
		"EnableIPv6":     in.EnableIPv6,
		"Labels":         labels,
	}

	if strings.TrimSpace(in.SubnetCIDR) != "" {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(in.SubnetCIDR))
		if err != nil {
			return "", errors.New("INVALID_SUBNET: 子网 CIDR 格式无效（示例：172.28.0.0/16）")
		}
		cfgEntry := map[string]string{"Subnet": prefix.Masked().String()}
		if strings.TrimSpace(in.GatewayIP) != "" {
			gw, gerr := netip.ParseAddr(strings.TrimSpace(in.GatewayIP))
			if gerr != nil || !prefix.Contains(gw) {
				return "", errors.New("INVALID_GATEWAY: 网关 IP 必须位于所选子网 CIDR 内")
			}
			cfgEntry["Gateway"] = gw.String()
		}
		reqBody["IPAM"] = map[string]any{
			"Driver": "default",
			"Config": []map[string]string{cfgEntry},
		}
	}

	raw, _ := json.Marshal(reqBody)
	code, respBytes, err := r.doEngineRaw(ctx, http.MethodPost, "/networks/create", nil, raw, 15*time.Second)
	if err != nil {
		return "", err
	}
	if code < 200 || code >= 300 {
		return "", fmt.Errorf("DOCKER_NETWORK_CREATE_FAILED (%d): %s", code, extractDockerMessage(respBytes))
	}
	var created struct {
		ID string `json:"Id"`
	}
	_ = json.Unmarshal(respBytes, &created)
	return created.ID, nil
}

// NetworkMembershipInput 控制容器在线加入或离开某个 Docker 网络（无需重启容器！）。
type NetworkMembershipInput struct {
	ContainerID string   `json:"container_id"`
	NetworkID   string   `json:"network_id"` // 网络名或 ID
	Action      string   `json:"action"`     // "connect" | "disconnect"
	Aliases     []string `json:"aliases,omitempty"`
	IPv4Address string   `json:"ipv4_address,omitempty"`
	IPv6Address string   `json:"ipv6_address,omitempty"`
	Force       bool     `json:"force,omitempty"`
}

func (r *ControlledDockerCapabilityRunner) MutateContainerNetwork(ctx context.Context, in NetworkMembershipInput) error {
	if !isValidContainerID(in.ContainerID) || !isValidContainerID(in.NetworkID) {
		return errors.New("INVALID_ARGUMENT: 容器或网络标识非法")
	}
	if strings.EqualFold(in.NetworkID, "host") || strings.EqualFold(in.NetworkID, "none") {
		return errors.New("UNSUPPORTED_NETWORK_MODE: host 与 none 模式不支持动态热插拔网络")
	}

	// 先读取容器当前网络状态，防止在 host 模式下误操作或把容器唯一一条网络断开导致失联
	insp, err := r.inspectContainerRaw(ctx, in.ContainerID, false)
	if err != nil {
		return err
	}
	netMode := insp.HostConfig.NetworkMode
	if netMode == "host" || netMode == "none" || strings.HasPrefix(netMode, "container:") {
		return fmt.Errorf("NETWORK_MODE_LOCKED: 当前容器处于 %s 网络模式，无法挂载或卸载 Bridge 网络", netMode)
	}

	switch in.Action {
	case "connect":
		cleanAliases := make([]string, 0, len(in.Aliases))
		for _, a := range in.Aliases {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			if !aliasNamePattern.MatchString(a) {
				return fmt.Errorf("INVALID_ALIAS: 非法的容器网络 DNS 别名 %q", a)
			}
			cleanAliases = append(cleanAliases, a)
		}
		epCfg := map[string]any{}
		if len(cleanAliases) > 0 {
			epCfg["Aliases"] = cleanAliases
		}
		ipam := map[string]string{}
		if v4 := strings.TrimSpace(in.IPv4Address); v4 != "" {
			addr, perr := netip.ParseAddr(v4)
			if perr != nil || !addr.Is4() {
				return errors.New("INVALID_IPV4: 静态 IPv4 地址无效")
			}
			ipam["IPv4Address"] = addr.String()
		}
		if v6 := strings.TrimSpace(in.IPv6Address); v6 != "" {
			addr, perr := netip.ParseAddr(v6)
			if perr != nil || !addr.Is6() {
				return errors.New("INVALID_IPV6: 静态 IPv6 地址无效")
			}
			ipam["IPv6Address"] = addr.String()
		}
		if len(ipam) > 0 {
			epCfg["IPAMConfig"] = ipam
		}
		payload, _ := json.Marshal(map[string]any{
			"Container":      in.ContainerID,
			"EndpointConfig": epCfg,
		})
		code, resp, err := r.doEngineRaw(ctx, http.MethodPost, "/networks/"+url.PathEscape(in.NetworkID)+"/connect", nil, payload, 15*time.Second)
		if err != nil {
			return err
		}
		if code < 200 || code >= 300 {
			return fmt.Errorf("NETWORK_CONNECT_FAILED (%d): %s", code, extractDockerMessage(resp))
		}
		return nil

	case "disconnect":
		if len(insp.NetworkSettings.Networks) <= 1 {
			return errors.New("LAST_NETWORK_PROTECTED: 容器当前仅连接了 1 个网络，请先接入目标新网络再断开旧网络，避免容器断网")
		}
		payload, _ := json.Marshal(map[string]any{
			"Container": in.ContainerID,
			"Force":     in.Force,
		})
		code, resp, err := r.doEngineRaw(ctx, http.MethodPost, "/networks/"+url.PathEscape(in.NetworkID)+"/disconnect", nil, payload, 15*time.Second)
		if err != nil {
			return err
		}
		if code < 200 || code >= 300 {
			return fmt.Errorf("NETWORK_DISCONNECT_FAILED (%d): %s", code, extractDockerMessage(resp))
		}
		return nil

	default:
		return errors.New("INVALID_ACTION: action 仅支持 connect 或 disconnect")
	}
}

// ======================== 4. 独立容器修改端口映射的五步原子换名回滚重建 Saga ========================

// PortMappingRule 定义一条语义化的容器端口映射规则。
type PortMappingRule struct {
	// BindMode:
	//   - "loopback"    -> 仅绑定 127.0.0.1（隐身安全模式，仅供本机或 web.ingress 反代访问）
	//   - "public"      -> 绑定 0.0.0.0（可选附带 IPv6 ::，公网可通过 IP:Port 直连）
	//   - "specific_ip" -> 绑定 BindIP 指定的本机真实网卡 IP（如 Tailscale 100.x.y.z）
	BindMode      string `json:"bind_mode"`
	BindIP        string `json:"bind_ip,omitempty"`
	IncludeIPv6   bool   `json:"include_ipv6,omitempty"`
	HostPort      uint16 `json:"host_port"`      // 传 0 表示自动分配 20000..60000 空闲端口
	ContainerPort uint16 `json:"container_port"` // 1..65535
	Protocol      string `json:"protocol"`       // "tcp" | "udp" | "both"
}

// RecreatePortsInput 是宿主 `docker.recreate_ports` 能力的输入。
type RecreatePortsInput struct {
	ContainerID               string            `json:"container_id"`
	Rules                     []PortMappingRule `json:"rules"`
	CommitWritableLayer       bool              `json:"commit_writable_layer"`        // 若 SizeRw > 0，重建前自动 docker commit 快照镜像保留容器层修改
	AllowDiscardWritableLayer bool              `json:"allow_discard_writable_layer"` // 用户已确认无需保留未挂载可写层
	StartAfterRecreate        *bool             `json:"start_after_recreate,omitempty"`
	ReservedHostPorts         []uint16          `json:"reserved_host_ports,omitempty"` // 宿主 forwarder 注入的面板管理端口
}

// RecreatePortsOutput 返回重建后的新容器 ID 与最终生效的端口映射（含自动分配的随机端口）。
type RecreatePortsOutput struct {
	OldContainerID    string            `json:"old_container_id"`
	NewContainerID    string            `json:"new_container_id"`
	ContainerName     string            `json:"container_name"`
	AppliedRules      []PortMappingRule `json:"applied_rules"`
	CommittedSnapshot string            `json:"committed_snapshot,omitempty"`
	WritableSizeBytes int64             `json:"writable_size_bytes"`
}

// RecreateContainerWithPortBindings 在宿主特权侧安全重建独立容器以更新端口映射：
//   - 强制校验原容器非 Privileged，原样保留原容器自身 Config/Mounts/Resources/Networks，绝不接受插件传入任意 HostConfig/Binds（杜绝借重建提权）；
//   - 若新容器创建或启动失败，100% 自动将备份容器改回原名并恢复启动，保证业务零丢失。
func (r *ControlledDockerCapabilityRunner) RecreateContainerWithPortBindings(
	ctx context.Context,
	in RecreatePortsInput,
	preservedHostPorts []uint16,
) (RecreatePortsOutput, error) {
	if !isValidContainerID(in.ContainerID) {
		return RecreatePortsOutput{}, errors.New("INVALID_CONTAINER_ID")
	}
	if len(in.Rules) > 64 {
		return RecreatePortsOutput{}, errors.New("TOO_MANY_PORT_RULES: 单容器最多配置 64 条端口映射")
	}

	// 第 1 步：完整 Inspect（含 SizeRw 未持久化层字节检测）与零信任边界复核
	insp, err := r.inspectContainerRaw(ctx, in.ContainerID, true)
	if err != nil {
		return RecreatePortsOutput{}, err
	}
	if insp.HostConfig.Privileged {
		return RecreatePortsOutput{}, errors.New("PRIVILEGED_CONTAINER_REFUSED: 出于安全限制，面板拒绝操作特权模式 (privileged) 容器")
	}
	netMode := insp.HostConfig.NetworkMode
	if netMode == "host" || netMode == "none" || strings.HasPrefix(netMode, "container:") {
		return RecreatePortsOutput{}, fmt.Errorf("NETWORK_MODE_INCOMPATIBLE: 当前容器网络模式为 %s，Docker 不支持为其设置端口映射", netMode)
	}
	if stackProj := insp.Config.Labels["com.docker.compose.project"]; strings.HasPrefix(stackProj, "qwq_") {
		return RecreatePortsOutput{}, fmt.Errorf("MANAGED_COMPOSE_CONTAINER: 该容器归属于受管 Compose 栈 %q，请通过 Compose 端口同步通道修改以免编排漂移", strings.TrimPrefix(stackProj, "qwq_"))
	}

	// 未持久化可写层防丢数守卫！
	if insp.SizeRw > 0 && !in.CommitWritableLayer && !in.AllowDiscardWritableLayer {
		return RecreatePortsOutput{WritableSizeBytes: insp.SizeRw}, fmt.Errorf(
			"WRITABLE_LAYER_DIRTY: 检测到容器根文件系统内有 %.2f MiB 未挂载到数据卷的改动；请勾选「重建前自动打包保留当前容器层」或确认丢弃临时层后再执行",
			float64(insp.SizeRw)/(1024*1024),
		)
	}

	// 第 2 步：校验绑定 IP、排除宿主保留端口（SSH + 面板自身端口）并预检端口冲突（本容器当前已占用的端口除外）
	reservedMap := make(map[uint16]bool, len(preservedHostPorts))
	for _, p := range preservedHostPorts {
		if p > 0 {
			reservedMap[p] = true
		}
	}
	// 严禁抢占 80/443 若用户未显式知情？此处只强制硬锁面板与 SSH 保留端口，80/443 若被 web.ingress 占用会在可用性检查自动报已被占用。
	selfCurrentPorts := extractSelfHostPorts(insp.HostConfig.PortBindings)
	validLocalIPs, _ := ListHostBindableIPs()
	allowedIPSet := make(map[string]bool, len(validLocalIPs))
	for _, item := range validLocalIPs {
		allowedIPSet[item.IP] = true
	}

	appliedRules := make([]PortMappingRule, 0, len(in.Rules))
	portBindings := make(map[string][]dockerPortBinding)
	exposedPorts := make(map[string]struct{})
	// 保留原镜像自带的 ExposedPorts 声明
	for k := range insp.Config.ExposedPorts {
		exposedPorts[k] = struct{}{}
	}

	usedInRequest := make(map[string]bool)
	for idx, rule := range in.Rules {
		if rule.ContainerPort == 0 {
			return RecreatePortsOutput{}, fmt.Errorf("第 %d 条规则：容器内部端口必须在 1..65535 之间", idx+1)
		}
		proto := strings.ToLower(strings.TrimSpace(rule.Protocol))
		if proto == "" {
			proto = "tcp"
		}
		if proto != "tcp" && proto != "udp" && proto != "both" {
			return RecreatePortsOutput{}, fmt.Errorf("第 %d 条规则：协议仅支持 tcp、udp 或 both", idx+1)
		}

		var targetBindIP string
		switch rule.BindMode {
		case "", "loopback":
			rule.BindMode = "loopback"
			targetBindIP = "127.0.0.1"
		case "public":
			targetBindIP = "0.0.0.0"
		case "specific_ip":
			candIP := strings.TrimSpace(rule.BindIP)
			if !allowedIPSet[candIP] || candIP == "0.0.0.0" {
				return RecreatePortsOutput{}, fmt.Errorf("第 %d 条规则：指定的本机网卡 IP %q 不存在或未启用", idx+1, candIP)
			}
			targetBindIP = candIP
		default:
			return RecreatePortsOutput{}, fmt.Errorf("第 %d 条规则：未知绑定模式 %q", idx+1, rule.BindMode)
		}
		rule.BindIP = targetBindIP
		rule.Protocol = proto

		if rule.HostPort == 0 {
			allocated, aerr := AllocateFreeHostPort(targetBindIP, proto, reservedMap)
			if aerr != nil {
				return RecreatePortsOutput{}, aerr
			}
			rule.HostPort = allocated
		} else {
			if reservedMap[rule.HostPort] {
				return RecreatePortsOutput{}, fmt.Errorf("PORT_RESERVED_HOST: 宿主机端口 %d 为 SSH 或面板核心保留端口，禁止映射覆盖", rule.HostPort)
			}
			if !selfCurrentPorts[rule.HostPort] && !isHostPortAvailable(targetBindIP, rule.HostPort, proto) {
				return RecreatePortsOutput{}, fmt.Errorf("PORT_IN_USE: 宿主机 %s:%d (%s) 已被其他服务占用，请更换端口", targetBindIP, rule.HostPort, proto)
			}
		}
		reservedMap[rule.HostPort] = true

		expandProtos := []string{proto}
		if proto == "both" {
			expandProtos = []string{"tcp", "udp"}
		}
		for _, ep := range expandProtos {
			dedupKey := fmt.Sprintf("%s:%d/%s", targetBindIP, rule.HostPort, ep)
			if usedInRequest[dedupKey] {
				return RecreatePortsOutput{}, fmt.Errorf("DUPLICATE_PORT_RULE: 重复的宿主机端口绑定 %s", dedupKey)
			}
			usedInRequest[dedupKey] = true

			cKey := fmt.Sprintf("%d/%s", rule.ContainerPort, ep)
			exposedPorts[cKey] = struct{}{}
			hostPortStr := strconv.Itoa(int(rule.HostPort))
			portBindings[cKey] = append(portBindings[cKey], dockerPortBinding{
				HostIP:   targetBindIP,
				HostPort: hostPortStr,
			})
			if rule.IncludeIPv6 && (rule.BindMode == "loopback" || rule.BindMode == "public") {
				v6IP := "::1"
				if rule.BindMode == "public" {
					v6IP = "::"
				}
				portBindings[cKey] = append(portBindings[cKey], dockerPortBinding{
					HostIP:   v6IP,
					HostPort: hostPortStr,
				})
			}
		}
		appliedRules = append(appliedRules, rule)
	}

	cleanName := strings.TrimPrefix(insp.Name, "/")
	wasRunning := insp.State.Running
	shouldStart := wasRunning
	if in.StartAfterRecreate != nil {
		shouldStart = *in.StartAfterRecreate
	}

	// 第 3 步（可选）：若用户勾选了保留未挂载可写层，先执行本地快照 Commit
	targetImage := insp.Config.Image
	var committedImage string
	if in.CommitWritableLayer && insp.SizeRw > 0 {
		snapRepo := "qwq-port-snapshot/" + strings.ToLower(regexp.MustCompile(`[^a-zA-Z0-9_.-]`).ReplaceAllString(cleanName, "-"))
		snapTag := strconv.FormatInt(time.Now().Unix(), 10)
		q := url.Values{
			"container": []string{insp.ID},
			"repo":      []string{snapRepo},
			"tag":       []string{snapTag},
			"comment":   []string{"qwq automatic writable-layer snapshot before port mapping update"},
			"pause":     []string{"true"},
		}
		code, resp, cerr := r.doEngineRaw(ctx, http.MethodPost, "/commit", q, nil, 60*time.Second)
		if cerr != nil || code < 200 || code >= 300 {
			return RecreatePortsOutput{}, fmt.Errorf("COMMIT_SNAPSHOT_FAILED: 快照保存容器可写层失败 (%s)，已中止重建以保护原容器数据", extractDockerMessage(resp))
		}
		committedImage = snapRepo + ":" + snapTag
		targetImage = committedImage
	}

	// 第 4 步：停旧 -> 改名备份（绝不先删原容器！）
	if wasRunning {
		qStop := url.Values{"t": []string{"12"}}
		code, resp, serr := r.doEngineRaw(ctx, http.MethodPost, "/containers/"+url.PathEscape(insp.ID)+"/stop", qStop, nil, 25*time.Second)
		if serr != nil || (code != 204 && code != 304 && (code < 200 || code >= 300)) {
			return RecreatePortsOutput{}, fmt.Errorf("STOP_OLD_FAILED: 停止原容器失败 (%s)", extractDockerMessage(resp))
		}
	}

	backupName := fmt.Sprintf("%s-qwq-bak-%d", cleanName, time.Now().Unix())
	qRenameBak := url.Values{"name": []string{backupName}}
	if code, resp, rerr := r.doEngineRaw(ctx, http.MethodPost, "/containers/"+url.PathEscape(insp.ID)+"/rename", qRenameBak, nil, 10*time.Second); rerr != nil || (code < 200 || code >= 300) {
		if wasRunning {
			_, _, _ = r.doEngineRaw(context.Background(), http.MethodPost, "/containers/"+url.PathEscape(insp.ID)+"/start", nil, nil, 15*time.Second)
		}
		return RecreatePortsOutput{}, fmt.Errorf("RENAME_BACKUP_FAILED: 重命名原容器备份失败 (%s)", extractDockerMessage(resp))
	}

	// 准备自动回滚闭包：一旦后续任何一步失败，无条件删半成品新容器、把备份容器改回原名并恢复启动！
	var createdNewID string
	rollbackOld := func() {
		bg := context.Background()
		if createdNewID != "" {
			// v=false 绝对禁止连带清理任何关联匿名卷！
			qDel := url.Values{"force": []string{"true"}, "v": []string{"false"}}
			_, _, _ = r.doEngineRaw(bg, http.MethodDelete, "/containers/"+url.PathEscape(createdNewID), qDel, nil, 15*time.Second)
		}
		qRestore := url.Values{"name": []string{cleanName}}
		_, _, _ = r.doEngineRaw(bg, http.MethodPost, "/containers/"+url.PathEscape(insp.ID)+"/rename", qRestore, nil, 10*time.Second)
		if wasRunning {
			_, _, _ = r.doEngineRaw(bg, http.MethodPost, "/containers/"+url.PathEscape(insp.ID)+"/start", nil, nil, 15*time.Second)
		}
	}

	// 第 5 步：克隆完整容器规格并注入新 PortBindings 创建新容器 + 恢复所有附加自定义网络 + 启动验活
	createPayload, secondaryNets, buildErr := buildClonedCreatePayload(insp, targetImage, exposedPorts, portBindings)
	if buildErr != nil {
		rollbackOld()
		return RecreatePortsOutput{}, buildErr
	}

	qCreate := url.Values{"name": []string{cleanName}}
	code, createResp, cerr := r.doEngineRaw(ctx, http.MethodPost, "/containers/create", qCreate, createPayload, 25*time.Second)
	if cerr != nil || code < 200 || code >= 300 {
		rollbackOld()
		return RecreatePortsOutput{}, fmt.Errorf("CREATE_NEW_FAILED: 创建新端口容器失败，已自动回滚恢复原容器 (%s)", extractDockerMessage(createResp))
	}
	var createdObj struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(createResp, &createdObj); err != nil || createdObj.ID == "" {
		rollbackOld()
		return RecreatePortsOutput{}, errors.New("CREATE_PARSE_FAILED: 解析新容器 ID 失败，已自动回滚恢复原容器")
	}
	createdNewID = createdObj.ID

	// 重新挂载除主网络外的其余多网络（完整保留每个网络的 Aliases 与静态 IP）
	for netName, epCfg := range secondaryNets {
		connRaw, _ := json.Marshal(map[string]any{
			"Container":      createdNewID,
			"EndpointConfig": epCfg,
		})
		cCode, cResp, connErr := r.doEngineRaw(ctx, http.MethodPost, "/networks/"+url.PathEscape(netName)+"/connect", nil, connRaw, 15*time.Second)
		if connErr != nil || cCode < 200 || cCode >= 300 {
			rollbackOld()
			return RecreatePortsOutput{}, fmt.Errorf("REATTACH_NETWORK_FAILED: 恢复附加网络 %s 失败，已自动回滚原容器 (%s)", netName, extractDockerMessage(cResp))
		}
	}

	if shouldStart {
		sCode, sResp, startErr := r.doEngineRaw(ctx, http.MethodPost, "/containers/"+url.PathEscape(createdNewID)+"/start", nil, nil, 25*time.Second)
		if startErr != nil || (sCode != 204 && (sCode < 200 || sCode >= 300)) {
			rollbackOld()
			return RecreatePortsOutput{}, fmt.Errorf("START_NEW_FAILED: 启动新端口容器失败，已无损自动回滚恢复原容器 (%s)", extractDockerMessage(sResp))
		}
	}

	// 新容器已确认成功就绪，安全移除备份旧容器壳（v=false 绝不触碰任何数据卷！）
	qRemoveOld := url.Values{"v": []string{"false"}}
	_, _, _ = r.doEngineRaw(context.Background(), http.MethodDelete, "/containers/"+url.PathEscape(insp.ID), qRemoveOld, nil, 15*time.Second)

	return RecreatePortsOutput{
		OldContainerID:    insp.ID,
		NewContainerID:    createdNewID,
		ContainerName:     cleanName,
		AppliedRules:      appliedRules,
		CommittedSnapshot: committedImage,
		WritableSizeBytes: insp.SizeRw,
	}, nil
}

// ======================== 内部原始 Inspect 与克隆辅助结构 ========================

type dockerPortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

type rawContainerInspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	SizeRw int64  `json:"SizeRw"`
	State  struct {
		Running bool `json:"Running"`
	} `json:"State"`
	ConfigRaw     json.RawMessage `json:"Config"`
	HostConfigRaw json.RawMessage `json:"HostConfig"`
	Config        struct {
		Image        string                     `json:"Image"`
		Labels       map[string]string          `json:"Labels"`
		ExposedPorts map[string]json.RawMessage `json:"ExposedPorts"`
	}
	HostConfig struct {
		Privileged   bool                           `json:"Privileged"`
		NetworkMode  string                         `json:"NetworkMode"`
		PortBindings map[string][]dockerPortBinding `json:"PortBindings"`
	}
	NetworkSettings struct {
		Networks map[string]rawEndpointSettings `json:"Networks"`
	} `json:"NetworkSettings"`
}

type rawEndpointSettings struct {
	NetworkID  string            `json:"NetworkID"`
	Aliases    []string          `json:"Aliases"`
	IPAMConfig map[string]string `json:"IPAMConfig"`
}

func (r *ControlledDockerCapabilityRunner) inspectContainerRaw(ctx context.Context, id string, withSize bool) (rawContainerInspect, error) {
	var q url.Values
	if withSize {
		q = url.Values{"size": []string{"true"}}
	}
	code, raw, err := r.doEngineRaw(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/json", q, nil, 20*time.Second)
	if err != nil {
		return rawContainerInspect{}, err
	}
	if code < 200 || code >= 300 {
		return rawContainerInspect{}, fmt.Errorf("CONTAINER_NOT_FOUND (%d): %s", code, extractDockerMessage(raw))
	}
	var out rawContainerInspect
	if err := json.Unmarshal(raw, &out); err != nil {
		return rawContainerInspect{}, err
	}
	_ = json.Unmarshal(out.ConfigRaw, &out.Config)
	_ = json.Unmarshal(out.HostConfigRaw, &out.HostConfig)
	return out, nil
}

func buildClonedCreatePayload(
	insp rawContainerInspect,
	targetImage string,
	exposed map[string]struct{},
	bindings map[string][]dockerPortBinding,
) ([]byte, map[string]map[string]any, error) {
	var cfgMap map[string]any
	if err := json.Unmarshal(insp.ConfigRaw, &cfgMap); err != nil {
		return nil, nil, err
	}
	var hostCfgMap map[string]any
	if err := json.Unmarshal(insp.HostConfigRaw, &hostCfgMap); err != nil {
		return nil, nil, err
	}

	// 清理不应原样带入新容器的实例主机名（仅当原 Hostname 等于旧短 ID 时清除，保留用户自定义 Hostname）
	if hn, _ := cfgMap["Hostname"].(string); hn != "" && strings.HasPrefix(insp.ID, hn) {
		delete(cfgMap, "Hostname")
	}
	cfgMap["Image"] = targetImage
	expObj := make(map[string]any, len(exposed))
	for k := range exposed {
		expObj[k] = map[string]any{}
	}
	cfgMap["ExposedPorts"] = expObj

	// 强制清除任何特权位并替换为新 PortBindings（保留全部 Binds / Mounts / Memory / NanoCPUs / RestartPolicy 等！）
	hostCfgMap["Privileged"] = false
	hostCfgMap["PortBindings"] = bindings
	cfgMap["HostConfig"] = hostCfgMap

	// 拆分主网络（放入 create 的 NetworkingConfig）与附加网络（create 后逐一 connect）
	primaryNet := insp.HostConfig.NetworkMode
	if primaryNet == "" || primaryNet == "default" {
		primaryNet = "bridge"
	}
	primaryEndpoints := make(map[string]any)
	secondaryEndpoints := make(map[string]map[string]any)

	netNames := make([]string, 0, len(insp.NetworkSettings.Networks))
	for n := range insp.NetworkSettings.Networks {
		netNames = append(netNames, n)
	}
	slices.Sort(netNames)

	for _, netName := range netNames {
		ep := insp.NetworkSettings.Networks[netName]
		cleanEP := make(map[string]any)
		// 过滤掉旧容器自己的短 ID 默认别名
		var keptAliases []string
		for _, a := range ep.Aliases {
			if a != "" && !strings.HasPrefix(insp.ID, a) {
				keptAliases = append(keptAliases, a)
			}
		}
		if len(keptAliases) > 0 {
			cleanEP["Aliases"] = keptAliases
		}
		if len(ep.IPAMConfig) > 0 {
			cleanEP["IPAMConfig"] = ep.IPAMConfig
		}
		if netName == primaryNet || len(primaryEndpoints) == 0 {
			primaryEndpoints[netName] = cleanEP
		} else {
			secondaryEndpoints[netName] = cleanEP
		}
	}
	if len(primaryEndpoints) > 0 {
		cfgMap["NetworkingConfig"] = map[string]any{
			"EndpointsConfig": primaryEndpoints,
		}
	}
	outBytes, err := json.Marshal(cfgMap)
	return outBytes, secondaryEndpoints, err
}

func extractSelfHostPorts(bindings map[string][]dockerPortBinding) map[uint16]bool {
	out := make(map[uint16]bool)
	for _, list := range bindings {
		for _, b := range list {
			if p, err := strconv.ParseUint(b.HostPort, 10, 16); err == nil && p > 0 {
				out[uint16(p)] = true
			}
		}
	}
	return out
}

func (r *ControlledDockerCapabilityRunner) doEngineRaw(
	ctx context.Context,
	method, relPath string,
	query url.Values,
	body []byte,
	timeout time.Duration,
) (int, []byte, error) {
	u := &url.URL{Scheme: "http", Host: "docker", Path: "/v1.41" + relPath}
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	var rd *bytes.Reader
	var req *http.Request
	var err error
	if len(body) > 0 {
		rd = bytes.NewReader(body)
		req, err = http.NewRequestWithContext(ctx, method, u.String(), rd)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, u.String(), nil)
	}
	if err != nil {
		return 0, nil, err
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.dialClient(timeout).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(http.MaxBytesReader(nil, resp.Body, 2<<20))
	return resp.StatusCode, buf.Bytes(), nil
}

func extractDockerMessage(raw []byte) string {
	var msg struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &msg) == nil && msg.Message != "" {
		return msg.Message
	}
	s := strings.TrimSpace(string(raw))
	if len(s) > 240 {
		return s[:240] + "..."
	}
	if s == "" {
		return "unknown docker engine error"
	}
	return s
}
