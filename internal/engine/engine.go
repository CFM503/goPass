package engine

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/yourusername/gopass/internal/config"
)

// Engine 是 GoPass 透明代理的核心
type Engine struct {
	cfg         *config.Config
	cfgMu       sync.RWMutex
	tracker     *ConnTracker
	tproxy      *TProxy
	interceptor *Interceptor

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

	now := time.Now()
	var result []map[string]interface{}
	for _, item := range s.Active {
		copyItem := make(map[string]interface{})
		for k, v := range item {
			copyItem[k] = v
		}
		result = append(result, copyItem)
	}

	// 合并并清理直连项 (5秒没动静的就踢掉，再次减少内存压力)
	for id, item := range s.directItems {
		lastSeen := item["lastSeen"].(time.Time)
		if now.Sub(lastSeen) > 5*time.Second {
			delete(s.directItems, id)
			continue
		}
		copyItem := make(map[string]interface{})
		for k, v := range item {
			copyItem[k] = v
		}
		result = append(result, copyItem)
	}

	return result
}

// New 创建引擎实例
func New(cfg *config.Config) (*Engine, error) {
	return &Engine{
		cfg:     cfg,
		tracker: NewConnTracker(),
		Stats: &Stats{
			PID:         os.Getpid(),
			directItems: make(map[string]map[string]interface{}),
		},
	}, nil
}

// Start 启动透明代理内核
func (e *Engine) Start() error {
	log.Printf("[Engine] GoPass 启动，PID=%d", e.Stats.PID)

	// 找到第一个支持的代理服务器地址 (SOCKS5 或 HTTP)
	proxyAddr := ""
	proxyType := ""
	for _, srv := range e.cfg.Outbound.Servers {
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
	tproxy, err := NewTProxy(e.tracker, proxyType, proxyAddr, e.Stats)
	if err != nil {
		return fmt.Errorf("TProxy 启动失败: %w", err)
	}
	e.tproxy = tproxy
	go tproxy.Accept()

	// 启动 WinDivert 拦截器（纯 Go syscall，无 CGo）
	interceptor := NewInterceptor(e.cfg.Routing.Mode, whitelist, e.tracker, proxyHost, uint16(proxyPort), e.Stats)
	e.interceptor = interceptor
	go interceptor.Start()

	log.Println("[Engine] 所有组件启动完毕，开始透明代理...")
	return nil
}

// UpdateUpstream 供 API 调用，用于热更上游代理
func (e *Engine) UpdateUpstream(pType, addr string, port int, saveFile string) {
	newAddr := fmt.Sprintf("%s:%d", addr, port)

	// 更新内存配置
	e.cfgMu.Lock()
	if len(e.cfg.Outbound.Servers) > 0 {
		e.cfg.Outbound.Servers[0].Type = pType
		e.cfg.Outbound.Servers[0].Address = addr
		e.cfg.Outbound.Servers[0].Port = port
	} else {
		e.cfg.Outbound.Servers = append(e.cfg.Outbound.Servers, config.Server{
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
	if e.interceptor != nil {
		e.interceptor.Close()
	}
	if e.tproxy != nil {
		e.tproxy.listener.Close() // TProxy 本身没有 Close 方法，需要关也是关 listener
	}
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

	if configPath != "" {
		e.cfgMu.RLock()
		defer e.cfgMu.RUnlock()
		return e.cfg.Save(configPath)
	}
	return nil
}

// UpdateUIConfig 更新 Web 界面专属的配置选项
func (e *Engine) UpdateUIConfig(wsInterval, connLimit int) {
	e.cfgMu.Lock()
	defer e.cfgMu.Unlock()
	e.cfg.API.WSRefreshInterval = wsInterval
	e.cfg.API.UIConnLimit = connLimit
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
		Outbound: config.OutboundConfig{},
	}

	if len(e.cfg.Routing.Rules) > 0 {
		clone.Routing.Rules = make([]config.Rule, len(e.cfg.Routing.Rules))
		copy(clone.Routing.Rules, e.cfg.Routing.Rules)
	}

	if len(e.cfg.Outbound.Servers) > 0 {
		clone.Outbound.Servers = make([]config.Server, len(e.cfg.Outbound.Servers))
		copy(clone.Outbound.Servers, e.cfg.Outbound.Servers)
	}

	return clone
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
