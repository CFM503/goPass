package engine

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/CFM503/goPass/internal/config"
	"github.com/CFM503/goPass/internal/controller"
)

type Engine struct {
	cfg         *config.Config
	cfgMu       sync.RWMutex
	tracker     *ConnTracker
	tproxy      *TProxy
	interceptor *Interceptor
	controller  *controller.RouteController
	Stats       *Stats
}

type Stats struct {
	PID         int
	Connections int
	RxBytes     int64
	TxBytes     int64
	mu          sync.RWMutex
	active      map[string]map[string]interface{}
}

func (s *Stats) AddActiveConn(connInfo map[string]interface{}) {
	id, _ := connInfo["id"].(string)
	s.mu.Lock()
	if s.active == nil { s.active = make(map[string]map[string]interface{}) }
	if _, exists := s.active[id]; !exists { s.Connections++ }
	s.active[id] = connInfo
	s.mu.Unlock()
}

func (s *Stats) RemoveActiveConn(id string) {
	s.mu.Lock()
	if _, exists := s.active[id]; exists {
		delete(s.active, id)
		if s.Connections > 0 { s.Connections-- }
	}
	s.mu.Unlock()
}

func (s *Stats) GetActive() []map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]map[string]interface{}, 0, len(s.active))
	for _, item := range s.active {
		copyItem := make(map[string]interface{}, len(item))
		for k, v := range item { copyItem[k] = v }
		result = append(result, copyItem)
	}
	return result
}

func New(cfg *config.Config) (*Engine, error) {
	stats := &Stats{PID: os.Getpid(), active: make(map[string]map[string]interface{})}
	eng := &Engine{cfg: cfg, tracker: NewConnTracker(cfg.System.ConnTrackGCInterval, cfg.System.ConnTrackTTL), Stats: stats}
	eng.controller = controller.NewRouteController(cfg.AutomaticRoute, func(r *controller.Route) {
		eng.UpdateUpstream(r.Protocol, r.Address, r.Port, "")
	})
	return eng, nil
}

func (e *Engine) Controller() *controller.RouteController { return e.controller }

func (e *Engine) Start() error {
	log.Printf("[Engine] GoPass v1.6.7 starting, PID=%d", e.Stats.PID)
	proxyAddr, proxyType := "", ""
	for _, srv := range e.cfg.Outbounds.Servers {
		if srv.Type == "socks5" || srv.Type == "http" {
			proxyAddr, proxyType = fmt.Sprintf("%s:%d", srv.Address, srv.Port), srv.Type
			break
		}
	}
	if proxyAddr == "" { return fmt.Errorf("no socks5 or http upstream configured") }
	proxyHost, proxyPort, err := parseAddr(proxyAddr)
	if err != nil { return fmt.Errorf("invalid upstream address: %w", err) }
	tproxy, err := NewTProxy(e.tracker, proxyType, proxyAddr, e.Stats, e.cfg.Performance, e.cfg.System.TProxyPort)
	if err != nil { return fmt.Errorf("TProxy start failed: %w", err) }
	e.tproxy = tproxy
	go tproxy.Accept()
	interceptor := NewInterceptor(e.tracker, proxyHost, uint16(proxyPort), uint16(e.cfg.System.TProxyPort))
	e.interceptor = interceptor
	go interceptor.Start()
	if e.controller != nil {
		if err := e.controller.Start(); err != nil { log.Printf("[Engine] route controller start error: %v", err) }
	}
	log.Printf("[Engine] ready: upstream=%s tproxy=%d", proxyAddr, e.cfg.System.TProxyPort)
	return nil
}

func (e *Engine) UpdatePerformance(perf config.PerformanceConfig) {
	perf.BufferSize = config.ClampBufferSize(perf.BufferSize)
	e.cfgMu.Lock(); e.cfg.Performance = perf; e.cfgMu.Unlock()
	if e.tproxy != nil { e.tproxy.UpdatePerformance(perf) }
}

func (e *Engine) UpdateUpstream(pType, addr string, port int, saveFile string) {
	newAddr := fmt.Sprintf("%s:%d", addr, port)
	e.cfgMu.Lock()
	if len(e.cfg.Outbounds.Servers) == 0 {
		e.cfg.Outbounds.Servers = append(e.cfg.Outbounds.Servers, config.Server{Tag: "proxy", Type: pType, Address: addr, Port: port})
	} else {
		e.cfg.Outbounds.Servers[0].Type, e.cfg.Outbounds.Servers[0].Address, e.cfg.Outbounds.Servers[0].Port = pType, addr, port
	}
	e.cfgMu.Unlock()
	if e.tproxy != nil { e.tproxy.UpdateUpstream(pType, newAddr) }
	if e.interceptor != nil { e.interceptor.SetProxyAddr(addr, uint16(port)) }
	if saveFile != "" {
		e.cfgMu.RLock(); err := e.cfg.Save(saveFile); e.cfgMu.RUnlock()
		if err != nil { log.Printf("[Engine] save config failed: %v", err) }
	}
}

func (e *Engine) UpdateUIConfig(wsInterval, connLimit int) {
	if wsInterval < 1 { wsInterval = 5 }
	if connLimit < 1 { connLimit = 20 }
	e.cfgMu.Lock(); e.cfg.API.WSRefreshInterval, e.cfg.API.UIConnLimit = wsInterval, connLimit; e.cfgMu.Unlock()
}

func (e *Engine) ResetConfig(configPath string) error {
	def := config.DefaultConfig()
	e.cfgMu.Lock(); e.cfg = def; e.cfgMu.Unlock()
	if e.tproxy != nil {
		e.tproxy.UpdatePerformance(def.Performance)
		for _, srv := range def.Outbounds.Servers {
			if srv.Type == "socks5" || srv.Type == "http" {
				e.tproxy.UpdateUpstream(srv.Type, fmt.Sprintf("%s:%d", srv.Address, srv.Port))
				if e.interceptor != nil { e.interceptor.SetProxyAddr(srv.Address, uint16(srv.Port)) }
				break
			}
		}
	}
	if configPath != "" { return e.SaveConfig(configPath) }
	return nil
}

func (e *Engine) GetConfig() *config.Config {
	e.cfgMu.RLock(); defer e.cfgMu.RUnlock()
	clone := *e.cfg
	clone.Outbounds.Servers = append([]config.Server(nil), e.cfg.Outbounds.Servers...)
	clone.AutomaticRoute.Routes = append([]config.RouteConfig(nil), e.cfg.AutomaticRoute.Routes...)
	return &clone
}

func (e *Engine) SaveConfig(path string) error { e.cfgMu.RLock(); defer e.cfgMu.RUnlock(); return e.cfg.Save(path) }

func (e *Engine) Stop() {
	if e.controller != nil { e.controller.Stop() }
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
