package engine

// Router 分流决策核心。
//
// 职责：
//   - 持有「绝对分流」配置（热重载，RWMutex 保护）
//   - 持有 GeoMatcher（规则文件热重载时整体替换）
//   - 持有进程白名单（供 both 模式下 geo_priority=false 的进程优先级判定）
//   - 提供：
//       InterceptScope()  —— 拦截器判断某进程是否纳入分流管控
//       Decide()          —— TProxy 对单条连接做出 直连/代理 最终决策
//       IsForeignIP()     —— UDP 拦截判断（国外 UDP 一律丢弃，零泄漏）
//
// 优先级（Decide）：
//   1. 自定义规则（custom_direct / custom_proxy，先域名后 IP）
//   2. both + geo_priority=false 时，非白名单进程 -> 直连旁路
//   3. geosite:cn（SNI 域名优先），未命中再 geoip:cn（目标 IP）
//   4. 命中 CN -> cn_direct 决定直连/代理；未命中 -> foreign_proxy 决定代理/直连
//   5. 规则文件缺失时 fail-safe：一律按国外处理（走代理，绝不泄漏）

import (
	"log"
	"net"
	"strings"
	"sync"

	"github.com/CFM503/goPass/internal/config"
)

// Decision 分流结果。
type Decision int

const (
	// DecisionProxy 走上游代理。
	DecisionProxy Decision = iota
	// DecisionDirect 直连。
	DecisionDirect
)

// RouteResult 单条连接的分流决策。
type RouteResult struct {
	Decision Decision
	Reason   string
}

// Router 分流路由器（线程安全，支持热重载）。
type Router struct {
	mu        sync.RWMutex
	resolved  config.ResolvedSplit
	matcher   *GeoMatcher
	whitelist map[string]struct{}
}

// NewRouter 创建路由器并加载规则。
// baseDir 用于解析相对路径的规则文件；为空则使用当前工作目录。
func NewRouter(resolved config.ResolvedSplit, baseDir string) (*Router, error) {
	r := &Router{
		resolved:  resolved,
		whitelist: make(map[string]struct{}),
	}
	matcher, err := LoadGeoMatcher(resolved, baseDir)
	if err != nil {
		log.Printf("[Router] ⚠️ 规则加载部分失败（fail-safe：未命中 CN 的一律走代理）: %v", err)
	}
	r.matcher = matcher
	return r, nil
}

// Update 热更新分流配置并重新加载规则文件（失败时保留旧规则）。
func (r *Router) Update(resolved config.ResolvedSplit, baseDir string) {
	newMatcher, err := LoadGeoMatcher(resolved, baseDir)
	if err != nil {
		log.Printf("[Router] ⚠️ 规则重载失败，保留旧规则: %v", err)
	}
	r.mu.Lock()
	if err == nil {
		r.matcher = newMatcher
	}
	r.resolved = resolved
	r.mu.Unlock()
}

// SetWhitelist 更新进程白名单（供 both 模式进程优先级判定）。
func (r *Router) SetWhitelist(names []string) {
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		if n != "" {
			set[strings.ToLower(n)] = struct{}{}
		}
	}
	r.mu.Lock()
	r.whitelist = set
	r.mu.Unlock()
}

func (r *Router) isWhitelistedLocked(name string) bool {
	_, ok := r.whitelist[strings.ToLower(name)]
	return ok
}

// SplitEnabled 分流总开关。
func (r *Router) SplitEnabled() bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.resolved.Enabled
}

// BlockIPv6 是否屏蔽全部出站 IPv6。
func (r *Router) BlockIPv6() bool {
	if r == nil {
		return true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.resolved.BlockIPv6
}

// DNSRelayPort 本地 DNS 中继端口（0=关闭 DNS 劫持）。
func (r *Router) DNSRelayPort() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.resolved.Enabled {
		return 0
	}
	return r.resolved.DNSRelayPort
}

// BlockForeignUDP 是否拦截国外 UDP。
func (r *Router) BlockForeignUDP() bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.resolved.Enabled && r.resolved.BlockForeignUDP
}

// InterceptScope 判定某进程是否纳入分流管控（拦截器据此决定是否劫持）。
func (r *Router) InterceptScope(processName string) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.resolved.Enabled {
		return false
	}
	switch r.resolved.Mode {
	case "geo":
		return true
	case "both":
		if r.resolved.GeoPriority {
			return true
		}
		return r.isWhitelistedLocked(processName)
	case "process":
		return r.isWhitelistedLocked(processName)
	}
	return false
}

// Decide 对单条连接做出最终分流决策。
// domain 为 SNI 嗅探得到的域名（可空），ip 为目标 IP，processName 为发起进程。
func (r *Router) Decide(domain string, ip net.IP, processName string) RouteResult {
	if r == nil {
		return RouteResult{Decision: DecisionProxy, Reason: "router-unavailable"}
	}
	r.mu.RLock()
	resolved := r.resolved
	matcher := r.matcher
	whitelisted := r.isWhitelistedLocked(processName)
	r.mu.RUnlock()

	if !resolved.Enabled {
		return RouteResult{Decision: DecisionProxy, Reason: "split-off"}
	}
	// process 模式 = 纯进程白名单（geo 不生效），保持原有行为
	if resolved.Mode == "process" {
		return RouteResult{Decision: DecisionProxy, Reason: "whitelist"}
	}

	domain = normalizeDomain(domain)

	// 1. 自定义规则（最高优先级）
	if matcher != nil {
		if matcher.MatchCustomDirect(domain, ip) {
			return RouteResult{Decision: DecisionDirect, Reason: "custom:direct"}
		}
		if matcher.MatchCustomProxy(domain, ip) {
			return RouteResult{Decision: DecisionProxy, Reason: "custom:proxy"}
		}
	}

	// 2. 进程优先级（both + geo_priority=false）：非白名单进程直连旁路
	if resolved.Mode == "both" && !resolved.GeoPriority && !whitelisted {
		return RouteResult{Decision: DecisionDirect, Reason: "process:bypass"}
	}

	// 3. 地理判定：SNI 域名优先（权威），无 SNI 时才回退目标 IP
	isCN := false
	if matcher != nil {
		if domain != "" {
			// 域名已知 CN -> 直连；域名不在 geosite:cn（国外或未知）-> 一律按国外处理（fail-safe）
			isCN = matcher.IsCNDomain(domain)
		} else if ip != nil {
			isCN = matcher.IsCNIP(ip)
		}
	}

	if isCN {
		if resolved.CNDirect {
			return RouteResult{Decision: DecisionDirect, Reason: "geo:cn"}
		}
		return RouteResult{Decision: DecisionProxy, Reason: "geo:cn-proxied"}
	}

	// 4. 国外（或无法判定 -> fail-safe 按国外处理，绝不直连泄漏）
	if resolved.ForeignProxy {
		return RouteResult{Decision: DecisionProxy, Reason: "geo:foreign"}
	}
	return RouteResult{Decision: DecisionDirect, Reason: "geo:foreign-direct"}
}

// IsForeignIP UDP 拦截判定：非 CN 且非自定义直连即视为国外（fail-safe）。
func (r *Router) IsForeignIP(ip net.IP) bool {
	if r == nil || ip == nil {
		return true
	}
	r.mu.RLock()
	matcher := r.matcher
	r.mu.RUnlock()
	if matcher == nil {
		return true
	}
	return matcher.IsForeignIP(ip)
}

// Resolved 返回当前解析后的分流配置快照。
func (r *Router) Resolved() config.ResolvedSplit {
	if r == nil {
		return config.ResolvedSplit{}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.resolved
}

// MatcherStats 返回规则加载统计（供 API）。
func (r *Router) MatcherStats() GeoMatcherStats {
	if r == nil {
		return GeoMatcherStats{}
	}
	r.mu.RLock()
	m := r.matcher
	r.mu.RUnlock()
	if m == nil {
		return GeoMatcherStats{}
	}
	return m.Stats()
}

// Matcher 返回当前规则匹配器（供 DNS 中继等组件只读使用）。
func (r *Router) Matcher() *GeoMatcher {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.matcher
}
