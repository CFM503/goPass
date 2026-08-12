package engine

import (
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/CFM503/goPass/internal/config"
)

// Engine 是 GoPass 透明代理的核心
type Engine struct {
	cfg         *config.Config
	cfgMu       sync.RWMutex
	tracker     *ConnTracker
	tproxy      *TProxy
	interceptor *Interceptor

	// 绝对分流路由器（热重载）
	router *Router

	// DNS 中继（零 DNS 泄漏）
	dnsMu    sync.Mutex
	dnsRelay *DNSRelay

	// 规则文件自动更新
	autoStop chan struct{}

	// 规则文件在线更新进度（供前端轮询）
	updateTracker *UpdateTracker

	// 运行时统计（供 API 层读取）
	Stats *Stats
}

// Stats 保存引擎运行状态
type Stats struct {
	PID         int
	Connections int
	RxBytes     int64
	TxBytes     int64
	Active      []map[string]interface{}
	mu          sync.Mutex

	// 记录直连程序：ID -> {Process, Target, LastSeen, LastReported}
	directItems map[string]map[string]interface{}
	cfg         *config.Config
}

// AddActiveConn 增加一个活动代理连接
func (s *Stats) AddActiveConn(connInfo map[string]interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Connections++
	if s.Active == nil {
		s.Active = make([]map[string]interface{}, 0)
	}
	s.Active = append(s.Active, connInfo)
}

// RemoveActiveConn 移除一个活动代理连接
func (s *Stats) RemoveActiveConn(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	activeLen := len(s.Active)
	for i := 0; i < activeLen; i++ {
		if s.Active[i]["id"] == id {
			s.Connections--
			s.Active[i] = s.Active[activeLen-1]
			s.Active[activeLen-1] = nil // 显式置空，帮助 GC
			s.Active = s.Active[:activeLen-1]
			break
		}
	}
}

// ReportDirect 上报直连连接 (增加频率限制，每 5 秒针对同一个 ID 仅处理一次)
func (s *Stats) ReportDirect(id, process, target, host string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.directItems == nil {
		s.directItems = make(map[string]map[string]interface{})
	}

	now := time.Now()
	// 频率限制：如果该连接在 5 秒内报送过，则跳过锁竞争激烈的后续逻辑
	if item, ok := s.directItems[id]; ok {
		lastReported, _ := item["lastSeen"].(time.Time)
		if now.Sub(lastReported) < 5*time.Second {
			// 仅更新最后可见时间，不产生新的渲染负担
			item["lastSeen"] = now
			return
		}
	}

	s.directItems[id] = map[string]interface{}{
		"id":       id,
		"process":  process,
		"target":   target,
		"host":     host,
		"policy":   "DIRECT",
		"lastSeen": now,
	}
}

// GetActive 返回合并后的活动连接（代理 + 直连）并清理过期直连
func (s *Stats) GetActive() []map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	var result []map[string]interface{}
	for _, item := range s.Active {
		copyItem := make(map[string]interface{})
		for k, v := range item {
			copyItem[k] = v
		}
		result = append(result, copyItem)
	}

	// [v1.2.6 Config] 根据核心配置读取显示开关，并截断
	if s.cfg != nil && s.cfg.API.ShowDirectConns {
		var dItems []map[string]interface{}
		for _, item := range s.directItems {
			copyItem := make(map[string]interface{})
			for k, v := range item {
				copyItem[k] = v
			}
			dItems = append(dItems, copyItem)
		}

		// Sort by lastSeen descending
		sort.Slice(dItems, func(i, j int) bool {
			timeI, okI := dItems[i]["lastSeen"].(time.Time)
			timeJ, okJ := dItems[j]["lastSeen"].(time.Time)
			if okI && okJ {
				return timeI.After(timeJ)
			}
			return false
		})

		limit := s.cfg.API.DirectConnsLimit
		if limit <= 0 {
			limit = 20
		}
		if len(dItems) > limit {
			dItems = dItems[:limit]
		}
		result = append(result, dItems...)
	}

	return result
}

// New 创建引擎实例
func New(cfg *config.Config) (*Engine, error) {
	stats := &Stats{
		PID:         os.Getpid(),
		directItems: make(map[string]map[string]interface{}),
		cfg:         cfg,
	}

	// 启动独立的僵尸连接垃圾回收器，彻底与前端请求解绑
	go stats.startGC()

	// 初始化绝对分流路由器（规则文件缺失时 fail-safe）
	router, _ := NewRouter(cfg.Split.Resolve(), "")

	return &Engine{
		cfg:           cfg,
		tracker:       NewConnTracker(cfg.System.ConnTrackGCInterval, cfg.System.ConnTrackTTL),
		router:        router,
		updateTracker: NewUpdateTracker(),
		Stats:         stats,
	}, nil
}

// startGC 确保后台挂机（没有用户打开界面调用 GetActive）时，不会造成 directItems 内存 OOM
func (s *Stats) startGC() {
	ticker := time.NewTicker(5 * time.Second)
	for range ticker.C {
		now := time.Now()

		// [v1.2.6 Config] 抽取内存清理超时触发时间
		var ttl time.Duration = 5 * time.Second
		if s.cfg != nil && s.cfg.System.DirectConnsTTL > 0 {
			ttl = time.Duration(s.cfg.System.DirectConnsTTL) * time.Second
		}

		s.mu.Lock()
		for id, item := range s.directItems {
			lastSeen, ok := item["lastSeen"].(time.Time)
			if ok && now.Sub(lastSeen) > ttl {
				delete(s.directItems, id)
			}
		}
		s.mu.Unlock()
	}
}

// Start 启动透明代理内核
func (e *Engine) Start() error {
	log.Printf("[Engine] GoPass 启动，PID=%d", e.Stats.PID)

	// 找到第一个支持的代理服务器地址 (SOCKS5 或 HTTP)
	proxyAddr := ""
	proxyType := ""
	for _, srv := range e.cfg.Outbounds.Servers {
		if srv.Type == "socks5" || srv.Type == "http" {
			proxyAddr = fmt.Sprintf("%s:%d", srv.Address, srv.Port)
			proxyType = srv.Type
			break
		}
	}
	if proxyAddr == "" {
		return fmt.Errorf("配置中没有找到 socks5 或 http 类型的代理服务器")
	}
	log.Printf("[Engine] 上游代理 [%s]: %s", proxyType, proxyAddr)

	// 收集进程白名单
	var whitelist []string
	for _, rule := range e.cfg.Routing.Rules {
		if rule.Type == "process" {
			whitelist = append(whitelist, rule.Payload)
		}
	}
	if len(whitelist) == 0 {
		log.Println("[Engine] 警告：配置中没有进程白名单规则，将不拦截任何流量")
	} else {
		log.Printf("[Engine] 进程白名单: %v", whitelist)
	}

	// 解析代理 IP 和端口（用于排除回环）
	proxyHost, proxyPort, err := parseAddr(proxyAddr)
	if err != nil {
		return fmt.Errorf("解析代理地址失败: %w", err)
	}

	// 启动本地透明代理监听器
	tproxy, err := NewTProxy(e.tracker, proxyType, proxyAddr, e.Stats, e.cfg.Performance, e.cfg.System.TProxyPort, e.router)
	if err != nil {
		return fmt.Errorf("TProxy 启动失败: %w", err)
	}
	e.tproxy = tproxy
	go tproxy.Accept()

	// 同步进程白名单到分流路由器（供 both 模式进程优先级判定）
	if e.router != nil {
		e.router.SetWhitelist(whitelist)
	}

	// 先启动 DNS 中继（零 DNS 泄漏），再启动拦截器，
	// 确保拦截器启动时即具备正确的 DNS 中继端口
	e.startDNSRelay()

	// 启动 WinDivert 拦截器（纯 Go syscall，无 CGo）
	interceptor := NewInterceptor(e.cfg.Routing.Mode, whitelist, e.tracker, proxyHost, uint16(proxyPort), uint16(e.cfg.System.TProxyPort), e.Stats, e.router)
	e.interceptor = interceptor
	go interceptor.Start()

	// 启动规则文件自动更新
	e.startAutoUpdate()

	log.Println("[Engine] 所有组件启动完毕，开始透明代理...")
	return nil
}

// UpdatePerformance 热更性能设置（立即对新连接生效）
func (e *Engine) UpdatePerformance(perf config.PerformanceConfig) {
	e.cfgMu.Lock()
	e.cfg.Performance = perf
	e.cfgMu.Unlock()
	if e.tproxy != nil {
		e.tproxy.UpdatePerformance(perf)
	}
}

// UpdateUpstream 供 API 调用，用于热更上游代理
func (e *Engine) UpdateUpstream(pType, addr string, port int, saveFile string) {
	newAddr := fmt.Sprintf("%s:%d", addr, port)

	// 更新内存配置
	e.cfgMu.Lock()
	if len(e.cfg.Outbounds.Servers) > 0 {
		e.cfg.Outbounds.Servers[0].Type = pType
		e.cfg.Outbounds.Servers[0].Address = addr
		e.cfg.Outbounds.Servers[0].Port = port
	} else {
		e.cfg.Outbounds.Servers = append(e.cfg.Outbounds.Servers, config.Server{
			Tag:     "proxy",
			Type:    pType,
			Address: addr,
			Port:    port,
		})
	}
	e.cfgMu.Unlock()

	// 通知 TProxy 热切
	if e.tproxy != nil {
		e.tproxy.UpdateUpstream(pType, newAddr)
	}

	// 持久化配置文件
	if saveFile != "" {
		e.cfgMu.RLock()
		err := e.cfg.Save(saveFile)
		e.cfgMu.RUnlock()
		if err != nil {
			log.Printf("[Engine] ⚠️ 保存配置失败: %v", err)
		} else {
			log.Printf("[Engine] ✅ 已保存配置至 %s", saveFile)
		}
	}
}

// Stop 停止引擎
func (e *Engine) Stop() {
	// 停止规则自动更新
	e.stopAutoUpdate()
	// 停止 DNS 中继
	e.dnsMu.Lock()
	if e.dnsRelay != nil {
		e.dnsRelay.Close()
		e.dnsRelay = nil
	}
	e.dnsMu.Unlock()
	if e.interceptor != nil {
		e.interceptor.Close()
	}
	if e.tproxy != nil {
		e.tproxy.listener.Close() // TProxy 本身没有 Close 方法，需要关也是关 listener
	}
	// 彻底清理 WinDivert 驱动和文件，防止下次启动时遇到残留锁定
	CleanUpOnShutdown()
}

// UpdateMode 更新代理模式并保存配置
func (e *Engine) UpdateMode(mode string, configPath string) error {
	e.cfgMu.Lock()
	e.cfg.Routing.Mode = mode
	e.cfgMu.Unlock()
	if e.interceptor != nil {
		e.interceptor.SetMode(mode)
	}
	if configPath != "" {
		e.cfgMu.RLock()
		defer e.cfgMu.RUnlock()
		return e.cfg.Save(configPath)
	}
	return nil
}

// UpdateRules 更新白名单规则并保存配置
func (e *Engine) UpdateRules(rules []config.Rule, configPath string) error {
	e.cfgMu.Lock()
	e.cfg.Routing.Rules = rules
	e.cfgMu.Unlock()

	// 重新收集进程白名单
	var whitelist []string
	for _, rule := range rules {
		if rule.Type == "process" {
			whitelist = append(whitelist, rule.Payload)
		}
	}

	if e.interceptor != nil {
		e.interceptor.SetWhitelist(whitelist)
	}
	if e.router != nil {
		e.router.SetWhitelist(whitelist)
	}

	if configPath != "" {
		e.cfgMu.RLock()
		defer e.cfgMu.RUnlock()
		return e.cfg.Save(configPath)
	}
	return nil
}

// UpdateUIConfig 更新 Web 界面专属的配置选项
func (e *Engine) UpdateUIConfig(wsInterval, connLimit int, showDirect bool, directLimit int) {
	e.cfgMu.Lock()
	defer e.cfgMu.Unlock()
	e.cfg.API.WSRefreshInterval = wsInterval
	e.cfg.API.UIConnLimit = connLimit
	e.cfg.API.ShowDirectConns = showDirect
	e.cfg.API.DirectConnsLimit = directLimit
}

// =============================================================================
// 绝对分流（Split）控制
// =============================================================================

// GetSplit 返回分流配置 + 规则加载状态（供 API/UI）。
func (e *Engine) GetSplit() map[string]interface{} {
	e.cfgMu.RLock()
	resolved := e.cfg.Split.Resolve()
	sc := e.cfg.Split
	e.cfgMu.RUnlock()

	var stats GeoMatcherStats
	if e.router != nil {
		stats = e.router.MatcherStats()
	}

	return map[string]interface{}{
		"enabled":           resolved.Enabled,
		"mode":              resolved.Mode,
		"geo_priority":      resolved.GeoPriority,
		"cn_direct":         resolved.CNDirect,
		"foreign_proxy":     resolved.ForeignProxy,
		"block_ipv6":        resolved.BlockIPv6,
		"block_foreign_udp": resolved.BlockForeignUDP,
		"dns_relay_port":    resolved.DNSRelayPort,
		"system_dns":        resolved.SystemDNS,
		"dot_server":        resolved.DoTServer,
		"dot_sni":           resolved.DoTSNI,
		"auto_update_hours": resolved.AutoUpdateHours,
		"custom_direct":     resolved.CustomDirect,
		"custom_proxy":      resolved.CustomProxy,
		"rule_files": map[string]string{
			"geosite": sc.RuleFiles.GeoSite,
			"geoip":   sc.RuleFiles.GeoIP,
		},
		"update_urls": map[string]string{
			"geosite": sc.UpdateURLs.GeoSite,
			"geoip":   sc.UpdateURLs.GeoIP,
		},
		"status": stats,
	}
}

// UpdateSplit 热更新分流配置：重新加载规则、重启 DNS 中继、更新拦截器。
func (e *Engine) UpdateSplit(sc config.SplitConfig, configPath string) error {
	sc = config.NormalizeSplit(sc)
	e.cfgMu.Lock()
	e.cfg.Split = sc
	e.cfgMu.Unlock()

	resolved := sc.Resolve()

	// 1. 更新路由器（重新加载规则文件；失败保留旧规则）
	if e.router != nil {
		e.router.Update(resolved, "")
	}

	// 2. 重启 DNS 中继（同时同步拦截器 DNS 中继端口）
	e.startDNSRelay()

	// 3. 重启自动更新
	e.startAutoUpdate()

	// 5. 持久化
	if configPath != "" {
		e.cfgMu.RLock()
		err := e.cfg.Save(configPath)
		e.cfgMu.RUnlock()
		if err != nil {
			log.Printf("[Engine] ⚠️ 保存分流配置失败: %v", err)
		}
	}
	log.Printf("[Engine] 🔀 分流配置已热更新: mode=%s enabled=%v geo_priority=%v cn_direct=%v foreign_proxy=%v",
		resolved.Mode, resolved.Enabled, resolved.GeoPriority, resolved.CNDirect, resolved.ForeignProxy)
	return nil
}

// UpdateRuleFiles 在线更新规则文件并热重载（供 API 调用，带并发保护与进度跟踪）。
func (e *Engine) UpdateRuleFiles() *RuleUpdateResult {
	e.cfgMu.RLock()
	geositeURL := e.cfg.Split.UpdateURLs.GeoSite
	geoipURL := e.cfg.Split.UpdateURLs.GeoIP
	geositePath := e.cfg.Split.RuleFiles.GeoSite
	geoipPath := e.cfg.Split.RuleFiles.GeoIP
	e.cfgMu.RUnlock()

	if !e.updateTracker.Begin() {
		return &RuleUpdateResult{UpdatedAt: nowStr(), Error: "规则更新正在进行中，请稍候"}
	}
	res := UpdateRuleFiles(geositeURL, geositePath, geoipURL, geoipPath, e.updateTracker)

	// 更新成功后立即热重载规则
	if (res.GeoSiteOK || res.GeoIPOK) && e.router != nil {
		e.cfgMu.RLock()
		resolved := e.cfg.Split.Resolve()
		e.cfgMu.RUnlock()
		e.router.Update(resolved, "")
	}
	return res
}

// GetUpdateProgress 返回规则文件下载进度快照（供 API GET 轮询）。
func (e *Engine) GetUpdateProgress() UpdateTracker {
	if e.updateTracker == nil {
		return UpdateTracker{Status: "idle"}
	}
	return e.updateTracker.Snapshot()
}

// ResetConfig 将全部配置复位为出厂默认值，并热应用到运行中的组件。
func (e *Engine) ResetConfig(configPath string) error {
	def := config.DefaultConfig()
	e.cfgMu.Lock()
	e.cfg = def
	e.cfgMu.Unlock()

	// 热应用：性能参数 + 上游代理
	if e.tproxy != nil {
		e.tproxy.UpdatePerformance(def.Performance)
		for _, srv := range def.Outbounds.Servers {
			if srv.Type == "socks5" || srv.Type == "http" {
				e.tproxy.UpdateUpstream(srv.Type, fmt.Sprintf("%s:%d", srv.Address, srv.Port))
				break
			}
		}
	}

	// 热应用：模式 + 进程白名单
	var whitelist []string
	for _, rule := range def.Routing.Rules {
		if rule.Type == "process" {
			whitelist = append(whitelist, rule.Payload)
		}
	}
	if e.interceptor != nil {
		e.interceptor.SetMode(def.Routing.Mode)
		e.interceptor.SetWhitelist(whitelist)
	}
	if e.router != nil {
		e.router.SetWhitelist(whitelist)
		e.router.Update(def.Split.Resolve(), "")
	}

	// 热应用：DNS 中继 + 规则自动更新
	e.startDNSRelay()
	e.startAutoUpdate()

	if configPath != "" {
		e.cfgMu.RLock()
		err := e.cfg.Save(configPath)
		e.cfgMu.RUnlock()
		if err != nil {
			log.Printf("[Engine] ⚠️ 保存复位配置失败: %v", err)
			return err
		}
	}
	log.Printf("[Engine] ♻️ 配置已复位为出厂默认值")
	return nil
}

// startDNSRelay 按当前配置启动/重启 DNS 中继。
func (e *Engine) startDNSRelay() {
	e.cfgMu.RLock()
	resolved := e.cfg.Split.Resolve()
	e.cfgMu.RUnlock()

	e.dnsMu.Lock()
	defer e.dnsMu.Unlock()

	// 先停旧的
	if e.dnsRelay != nil {
		e.dnsRelay.Close()
		e.dnsRelay = nil
	}

	// 同步 DNS 中继端口到拦截器（0=关闭 DNS 劫持）
	var relayPort uint16
	if resolved.Enabled && resolved.DNSRelayPort > 0 {
		relayPort = uint16(resolved.DNSRelayPort)
	}
	if e.interceptor != nil {
		e.interceptor.SetDNSRelayPort(relayPort)
	}

	if !resolved.Enabled || resolved.DNSRelayPort <= 0 {
		return
	}
	if e.tproxy == nil || e.tproxy.upstream == nil {
		log.Printf("[Engine] TProxy 未就绪，DNS 中继延后启动")
		return
	}
	relay := NewDNSRelay(e.router, e.tracker, e.tproxy.upstream, resolved)
	if err := relay.Start(resolved.DNSRelayPort); err != nil {
		log.Printf("[Engine] ⚠️ DNS 中继启动失败（DNS 劫持将关闭）: %v", err)
		return
	}
	e.dnsRelay = relay
}

// startAutoUpdate 启动规则文件自动更新协程（幂等：重复调用会先停旧的）。
func (e *Engine) startAutoUpdate() {
	e.cfgMu.RLock()
	hours := e.cfg.Split.Resolve().AutoUpdateHours
	e.cfgMu.RUnlock()

	e.stopAutoUpdate()
	if hours <= 0 {
		return
	}
	e.autoStop = make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Duration(hours) * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-e.autoStop:
				return
			case <-ticker.C:
				log.Printf("[Engine] 🔄 开始自动更新规则文件...")
				res := e.UpdateRuleFiles()
				if res.Error != "" {
					log.Printf("[Engine] ⚠️ 规则自动更新部分失败: %s", res.Error)
				} else {
					log.Printf("[Engine] ✅ 规则自动更新完成")
				}
			}
		}
	}()
	log.Printf("[Engine] 🔄 规则文件自动更新已启用（每 %d 小时）", hours)
}

// stopAutoUpdate 停止规则自动更新协程。
func (e *Engine) stopAutoUpdate() {
	if e.autoStop != nil {
		select {
		case <-e.autoStop:
		default:
			close(e.autoStop)
		}
		e.autoStop = nil
	}
}

// GetConfig 返回当前配置的安全快照副件，完全根除前端序列化的线程抢占问题
func (e *Engine) GetConfig() *config.Config {
	e.cfgMu.RLock()
	defer e.cfgMu.RUnlock()

	clone := &config.Config{
		API: e.cfg.API,
		DNS: e.cfg.DNS,
		Routing: config.RoutingConfig{
			Mode: e.cfg.Routing.Mode,
		},
		Outbounds:   config.OutboundConfig{},
		Performance: e.cfg.Performance,
		Split:       e.cfg.Split,
	}

	if len(e.cfg.Routing.Rules) > 0 {
		clone.Routing.Rules = make([]config.Rule, len(e.cfg.Routing.Rules))
		copy(clone.Routing.Rules, e.cfg.Routing.Rules)
	}

	if len(e.cfg.Outbounds.Servers) > 0 {
		clone.Outbounds.Servers = make([]config.Server, len(e.cfg.Outbounds.Servers))
		copy(clone.Outbounds.Servers, e.cfg.Outbounds.Servers)
	}

	return clone
}

// SaveConfig 线程安全地保存当前内部配置到文件
func (e *Engine) SaveConfig(path string) error {
	e.cfgMu.RLock()
	defer e.cfgMu.RUnlock()
	return e.cfg.Save(path)
}

func parseAddr(addr string) (string, int, error) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			host := addr[:i]
			var port int
			fmt.Sscanf(addr[i+1:], "%d", &port)
			return host, port, nil
		}
	}
	return "", 0, fmt.Errorf("invalid address: %s", addr)
}
