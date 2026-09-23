package engine

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/CFM503/goPass/internal/config"
	"github.com/CFM503/goPass/internal/version"
)

type Engine struct {
	cfg *config.Config
	cfgMu sync.RWMutex
	tracker *ConnTracker
	tproxy *TProxy
	interceptor *Interceptor
	Stats *Stats
}

type Stats struct {
	PID int
	Connections int
	mu sync.RWMutex
	active map[string]map[string]interface{}
}

type ProcessStatus struct {
	Process string `json:"process"`
	PID uint32 `json:"pid"`
	Status string `json:"status"`
	Connections int `json:"connections"`
	Targets []string `json:"targets"`
}

func (s *Stats) AddActiveConn(info map[string]interface{}) {
	id, _ := info["id"].(string)
	s.mu.Lock()
	if s.active == nil { s.active = make(map[string]map[string]interface{}) }
	if _, ok := s.active[id]; !ok { s.Connections++ }
	s.active[id] = info
	s.mu.Unlock()
}

func (s *Stats) RemoveActiveConn(id string) {
	s.mu.Lock()
	if _, ok := s.active[id]; ok {
		delete(s.active, id)
		if s.Connections > 0 { s.Connections-- }
	}
	s.mu.Unlock()
}

func New(cfg *config.Config) (*Engine, error) {
	stats := &Stats{PID: os.Getpid(), active: make(map[string]map[string]interface{})}
	return &Engine{
		cfg: cfg,
		tracker: NewConnTracker(cfg.System.ConnTrackGCInterval, cfg.System.ConnTrackTTL, uint16(cfg.System.TProxyPort)),
		Stats: stats,
	}, nil
}

// Start deliberately keeps the historical YouTube-compatible interception path:
// one primary WinDivert handle handles IPv4 TCP plus outbound IPv6, while UDP/443
// is left completely alone. Chromium/Windows then performs its normal QUIC
// failure/fallback behavior instead of being silently intercepted by another
// WinDivert handle.
func (e *Engine) Start() error {
	log.Printf("[Engine] GoPass %s starting, PID=%d", version.Version, e.Stats.PID)

	proxyAddr, proxyType, proxyUser, proxyPass := "", "", "", ""
	for _, srv := range e.cfg.Outbounds.Servers {
		if srv.Type == "socks5" || srv.Type == "http" {
			proxyAddr = fmt.Sprintf("%s:%d", srv.Address, srv.Port)
			proxyType = srv.Type
			// 上游账号密码必须一起带过去，否则 config.json 里配的认证
			// 会被静默忽略，上游要求认证时白名单程序全部断网且无提示。
			proxyUser, proxyPass = srv.Username, srv.Password
			break
		}
	}
	if proxyAddr == "" { return fmt.Errorf("no socks5 or http upstream configured") }

	proxyHost, proxyPort, err := parseAddr(proxyAddr)
	if err != nil { return fmt.Errorf("invalid upstream address: %w", err) }

	tp, err := NewTProxy(e.tracker, proxyType, proxyAddr, proxyUser, proxyPass, e.Stats, e.cfg.Performance, e.cfg.System.TProxyPort)
	if err != nil { return fmt.Errorf("TProxy 初始化失败：%w", err) }

	i := NewInterceptor(e.tracker, proxyFilterIP(proxyHost), uint16(proxyPort), uint16(e.cfg.System.TProxyPort), e.cfg.ProcessWhitelist)
	if err := i.preflight(); err != nil { _ = tp.Close(); return err }

	e.tproxy = tp
	e.interceptor = i
	go tp.Accept()
	go func() {
		if err := i.Start(); err != nil { log.Printf("[WinDivert] runtime stopped: %v", err) }
	}()

	log.Printf("[Engine] ready: upstream=%s tproxy=%d whitelist=%v", proxyAddr, e.cfg.System.TProxyPort, e.cfg.ProcessWhitelist)
	return nil
}

func (e *Engine) UpdatePerformance(p config.PerformanceConfig) {
	p.BufferSize = config.ClampBufferSize(p.BufferSize)
	e.cfgMu.Lock()
	e.cfg.Performance = p
	e.cfgMu.Unlock()
	if e.tproxy != nil { e.tproxy.UpdatePerformance(p) }
}

func (e *Engine) UpdateUpstream(pt, addr string, port int, save string) {
	newAddr := fmt.Sprintf("%s:%d", addr, port)
	// 设置页只提交 type/address/port，所以这里只覆写这三项、保留原有凭据，
	// 再把保留下来的凭据回灌给 TProxy——否则热更新会把认证清掉。
	user, pass := "", ""
	e.cfgMu.Lock()
	if len(e.cfg.Outbounds.Servers) == 0 {
		e.cfg.Outbounds.Servers = []config.Server{{Tag: "proxy", Type: pt, Address: addr, Port: port}}
	} else {
		e.cfg.Outbounds.Servers[0].Type = pt
		e.cfg.Outbounds.Servers[0].Address = addr
		e.cfg.Outbounds.Servers[0].Port = port
	}
	if len(e.cfg.Outbounds.Servers) > 0 {
		user, pass = e.cfg.Outbounds.Servers[0].Username, e.cfg.Outbounds.Servers[0].Password
	}
	e.cfgMu.Unlock()
	if e.tproxy != nil { e.tproxy.UpdateUpstream(pt, newAddr, user, pass) }
	if e.interceptor != nil { e.interceptor.SetProxyAddr(proxyFilterIP(addr), uint16(port)) }
	if save != "" { _ = e.SaveConfig(save) }
}

// normalizeWhitelist 清洗白名单：去空白、转小写、去重（保持首次出现的顺序）。
func normalizeWhitelist(list []string) []string {
	clean := make([]string, 0, len(list))
	seen := map[string]struct{}{}
	for _, n := range list {
		n = strings.TrimSpace(strings.ToLower(n))
		if n == "" { continue }
		if _, ok := seen[n]; ok { continue }
		seen[n] = struct{}{}
		clean = append(clean, n)
	}
	return clean
}

// mutateWhitelist 在同一把 cfgMu 里完成"读-改-写"：fn 拿到当前白名单的副本，
// 返回的新列表立刻落进 cfg，锁在 fn 返回后才放开。
//
// 这是白名单唯一的写入口。此前 API 处理器先 GetProcessWhitelist() 拷一份出来、
// 改完再写回整份列表：两个并发请求会基于同一份快照各改各的，后写者整份覆盖
// 先写者，静默丢掉一次变更（连同那次的保存）。把改动收进锁内之后，
// 并发增删各自累加，不再互相覆盖。
//
// 放锁之后才 SetWhitelist / SaveConfig：SaveConfig 会再取 cfgMu 的读锁，
// 持锁调用会自锁死。
func (e *Engine) mutateWhitelist(save string, fn func(cur []string) []string) []string {
	e.cfgMu.Lock()
	clean := fn(append([]string(nil), e.cfg.ProcessWhitelist...))
	e.cfg.ProcessWhitelist = clean
	e.cfgMu.Unlock()
	if e.interceptor != nil { e.interceptor.SetWhitelist(clean) }
	if save != "" { _ = e.SaveConfig(save) }
	return append([]string(nil), clean...)
}

// AddProcess 把一个进程加入白名单（大小写不敏感去重），返回更新后的完整列表。
func (e *Engine) AddProcess(name, save string) []string {
	name = strings.TrimSpace(name)
	if name == "" { return e.GetProcessWhitelist() }
	return e.mutateWhitelist(save, func(cur []string) []string {
		for _, p := range cur {
			if strings.EqualFold(p, name) { return normalizeWhitelist(cur) }
		}
		return normalizeWhitelist(append(cur, name))
	})
}

// RemoveProcess 按大小写不敏感匹配移除一个进程，返回更新后的完整列表。
// 名字为空或不存在时列表不变，仍按清洗后的结果返回。
func (e *Engine) RemoveProcess(name, save string) []string {
	name = strings.TrimSpace(name)
	return e.mutateWhitelist(save, func(cur []string) []string {
		if name == "" { return normalizeWhitelist(cur) }
		filtered := make([]string, 0, len(cur))
		for _, p := range cur {
			if !strings.EqualFold(p, name) { filtered = append(filtered, p) }
		}
		return normalizeWhitelist(filtered)
	})
}

func (e *Engine) GetProcessWhitelist() []string {
	e.cfgMu.RLock()
	defer e.cfgMu.RUnlock()
	return append([]string(nil), e.cfg.ProcessWhitelist...)
}

func (e *Engine) GetProcessStatuses() []ProcessStatus {
	if e.interceptor == nil { return []ProcessStatus{} }
	return e.interceptor.ProcessStatuses()
}

// InterceptorState 返回拦截器真实运行状态：stopped / running / error，
// 以及错误详情。/api/status 用它避免"界面显示运行中但拦截其实没生效"。
func (e *Engine) InterceptorState() (string, string) {
	if e.interceptor == nil {
		return "stopped", "拦截器未启动"
	}
	return e.interceptor.State()
}

func (e *Engine) GetConfig() *config.Config {
	e.cfgMu.RLock()
	defer e.cfgMu.RUnlock()
	clone := *e.cfg
	clone.Outbounds.Servers = append([]config.Server(nil), e.cfg.Outbounds.Servers...)
	clone.ProcessWhitelist = append([]string(nil), e.cfg.ProcessWhitelist...)
	return &clone
}

func (e *Engine) SaveConfig(path string) error {
	e.cfgMu.RLock()
	defer e.cfgMu.RUnlock()
	return e.cfg.Save(path)
}

func (e *Engine) Stop() {
	if e.interceptor != nil { e.interceptor.Close() }
	if e.tproxy != nil { _ = e.tproxy.Close() }
	if e.tracker != nil { e.tracker.Close() }
	CleanUpOnShutdown()
}

func parseAddr(addr string) (string, int, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil { return "", 0, err }
	p, err := strconv.Atoi(port)
	if err != nil || p <= 0 || p > 65535 { return "", 0, fmt.Errorf("invalid port: %s", port) }
	return host, p, nil
}

func proxyFilterIP(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil && !ip.IsLoopback() { return ip.To4().String() }
	ips, err := net.LookupIP(host)
	if err != nil { return "" }
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil && !v4.IsLoopback() { return v4.String() }
	}
	return ""
}
