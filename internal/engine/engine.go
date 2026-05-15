package engine

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
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

	Stats *Stats
}

// ConnInfo 替代 map[string]interface{}，零分配、类型安全
type ConnInfo struct {
	ID      string `json:"id"`
	Process string `json:"process"`
	Target  string `json:"target"`
	Host    string `json:"host"`
	Policy  string `json:"policy"`
}

// directKey uses [4]byte + uint16 to avoid string allocations
type directKey struct {
	srcIP   [4]byte
	srcPort uint16
}

// directItem 内部结构，避免 map[string]interface{} 分配
type directItem struct {
	ID       string
	Process  string
	Target   string
	Host     string
	Policy   string
	LastSeen int64 // unix nano, avoids time.Time alloc
}

// byLastSeen implements sort.Interface for []directItem
type byLastSeen []directItem

func (a byLastSeen) Len() int           { return len(a) }
func (a byLastSeen) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byLastSeen) Less(i, j int) bool { return a[i].LastSeen > a[j].LastSeen }

// Stats 保存引擎运行状态（性能优化版）
type Stats struct {
	PID         int
	Connections int32
	RxBytes     int64
	TxBytes     int64

	active   map[string]ConnInfo
	activeMu sync.RWMutex

	directItems map[directKey]directItem
	directMu    sync.RWMutex

	cfg *config.Config
}

// AddActiveConn O(1) 添加，无锁竞争（使用独立 mutex）
func (s *Stats) AddActiveConn(connInfo ConnInfo) {
	s.activeMu.Lock()
	s.active[connInfo.ID] = connInfo
	s.activeMu.Unlock()
	atomic.AddInt32(&s.Connections, 1)
}

// RemoveActiveConn O(1) 删除，无线性扫描
func (s *Stats) RemoveActiveConn(id string) {
	s.activeMu.Lock()
	if _, ok := s.active[id]; ok {
		delete(s.active, id)
		atomic.AddInt32(&s.Connections, -1)
	}
	s.activeMu.Unlock()
}

// ReportDirect 上报直连连接（优化：[4]byte key 避免 string 分配，int64 时间戳避免 time.Time 分配）
func (s *Stats) ReportDirect(srcIP [4]byte, srcPort uint16, process string, host [4]byte, dstPort uint16) {
	now := time.Now().UnixNano()

	s.directMu.Lock()
	defer s.directMu.Unlock()

	key := directKey{srcIP: srcIP, srcPort: srcPort}
	if item, ok := s.directItems[key]; ok {
		if now-item.LastSeen < 5_000_000_000 {
			item.LastSeen = now
			s.directItems[key] = item
			return
		}
	}

	hostStr := ip4String(host)
	s.directItems[key] = directItem{
		ID:       ip4String(srcIP) + ":" + strconv.Itoa(int(srcPort)),
		Process:  process,
		Target:   hostStr + ":" + strconv.Itoa(int(dstPort)),
		Host:     hostStr,
		Policy:   "DIRECT",
		LastSeen: now,
	}
}

// GetActive 返回合并后的活动连接（快照模式，缩短锁持有时间）
func (s *Stats) GetActive() []ConnInfo {
	s.activeMu.RLock()
	activeLen := len(s.active)
	s.activeMu.RUnlock()

	s.directMu.RLock()
	showDirect := s.cfg != nil && s.cfg.API.ShowDirectConns
	directLen := 0
	directLimit := 20
	if showDirect {
		if s.cfg.API.DirectConnsLimit > 0 {
			directLimit = s.cfg.API.DirectConnsLimit
		}
		directLen = len(s.directItems)
	}
	s.directMu.RUnlock()

	cap := activeLen
	if showDirect && directLen < directLimit {
		cap += directLen
	} else if showDirect {
		cap += directLimit
	}
	result := make([]ConnInfo, 0, cap)

	s.activeMu.RLock()
	for _, item := range s.active {
		result = append(result, item)
	}
	s.activeMu.RUnlock()

	if showDirect && directLen > 0 {
		s.directMu.RLock()
		dItems := make([]directItem, 0, directLen)
		for _, item := range s.directItems {
			dItems = append(dItems, item)
		}
		s.directMu.RUnlock()

		sort.Sort(byLastSeen(dItems))

		if len(dItems) > directLimit {
			dItems = dItems[:directLimit]
		}

		for _, item := range dItems {
			result = append(result, ConnInfo{
				ID:      item.ID,
				Process: item.Process,
				Target:  item.Target,
				Host:    item.Host,
				Policy:  item.Policy,
			})
		}
	}

	return result
}

// New 创建引擎实例
func New(cfg *config.Config) (*Engine, error) {
	stats := &Stats{
		PID:         os.Getpid(),
		active:      make(map[string]ConnInfo),
		directItems: make(map[directKey]directItem),
		cfg:         cfg,
	}

	go stats.startGC()

	return &Engine{
		cfg:     cfg,
		tracker: NewConnTracker(cfg.System.ConnTrackGCInterval, cfg.System.ConnTrackTTL),
		Stats:   stats,
	}, nil
}

// startGC 后台清理过期直连记录
func (s *Stats) startGC() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var cachedTTL int64 = 5_000_000_000

	for range ticker.C {
		s.directMu.RLock()
		if s.cfg != nil && s.cfg.System.DirectConnsTTL > 0 {
			newTTL := int64(s.cfg.System.DirectConnsTTL) * 1_000_000_000
			if newTTL != cachedTTL {
				cachedTTL = newTTL
			}
		}
		s.directMu.RUnlock()

		now := time.Now().UnixNano()
		s.directMu.Lock()
		for key, item := range s.directItems {
			if now-item.LastSeen > cachedTTL {
				delete(s.directItems, key)
			}
		}
		s.directMu.Unlock()
	}
}

// Start 启动透明代理内核
func (e *Engine) Start() error {
	log.Printf("[Engine] GoPass 启动，PID=%d", e.Stats.PID)

	proxyAddr := ""
	proxyType := ""
	for _, srv := range e.cfg.Outbounds.Servers {
		if srv.Type == "socks5" || srv.Type == "http" {
			proxyAddr = srv.Address + ":" + strconv.Itoa(srv.Port)
			proxyType = srv.Type
			break
		}
	}
	if proxyAddr == "" {
		return fmt.Errorf("配置中没有找到 socks5 或 http 类型的代理服务器")
	}
	log.Printf("[Engine] 上游代理 [%s]: %s", proxyType, proxyAddr)

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

	proxyHost, proxyPort, err := parseAddr(proxyAddr)
	if err != nil {
		return fmt.Errorf("解析代理地址失败: %w", err)
	}

	tproxy, err := NewTProxy(e.tracker, proxyType, proxyAddr, e.Stats, e.cfg.Performance, e.cfg.System.TProxyPort)
	if err != nil {
		return fmt.Errorf("TProxy 启动失败: %w", err)
	}
	e.tproxy = tproxy
	go tproxy.Accept()

	interceptor := NewInterceptor(e.cfg.Routing.Mode, whitelist, e.tracker, proxyHost, uint16(proxyPort), uint16(e.cfg.System.TProxyPort), e.Stats)
	e.interceptor = interceptor
	go interceptor.Start()

	log.Println("[Engine] 所有组件启动完毕，开始透明代理...")
	return nil
}

// UpdatePerformance 热更性能设置
func (e *Engine) UpdatePerformance(perf config.PerformanceConfig) {
	e.cfgMu.Lock()
	e.cfg.Performance = perf
	e.cfgMu.Unlock()
	if e.tproxy != nil {
		e.tproxy.UpdatePerformance(perf)
	}
}

// UpdateUpstream 热更上游代理
func (e *Engine) UpdateUpstream(pType, addr string, port int, saveFile string) {
	newAddr := addr + ":" + strconv.Itoa(port)

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

	if e.tproxy != nil {
		e.tproxy.UpdateUpstream(pType, newAddr)
	}

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
		e.tproxy.listener.Close()
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

// UpdateUIConfig 更新 Web 界面专属配置
func (e *Engine) UpdateUIConfig(wsInterval, connLimit int, showDirect bool, directLimit int) {
	e.cfgMu.Lock()
	defer e.cfgMu.Unlock()
	e.cfg.API.WSRefreshInterval = wsInterval
	e.cfg.API.UIConnLimit = connLimit
	e.cfg.API.ShowDirectConns = showDirect
	e.cfg.API.DirectConnsLimit = directLimit
}

// GetConfig 返回当前配置的安全快照
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
			port, err := strconv.Atoi(addr[i+1:])
			return host, port, err
		}
	}
	return "", 0, fmt.Errorf("invalid address: %s", addr)
}
