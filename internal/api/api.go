package api

import (
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/CFM503/goPass/internal/config"
	"github.com/CFM503/goPass/internal/engine"
	"github.com/CFM503/goPass/web"
)

// Server 的 configPath 必须与启动时 -config 指定的文件一致，
// 否则 UI 保存会写到另一个文件，下次启动配置回滚。
type Server struct {
	engine     *engine.Engine
	configPath string
}

// guard 把 /api/* 限制为本地、同源调用：
//   - Origin 存在时必须与 Host 同源 → 阻断网页 CSRF（跨源 POST 改上游/白名单）；
//   - Host 必须是回环地址（或与监听地址一致）→ 阻断 DNS Rebinding 读取状态。
// 静态资源（/、/css、/js）不经过校验，本机 UI 行为不变。
func guard(listenAddr string, next http.Handler) http.Handler {
	listenHost := ""
	if h, _, err := net.SplitHostPort(listenAddr); err == nil {
		listenHost = strings.ToLower(h)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || !strings.EqualFold(u.Host, r.Host) {
				http.Error(w, "forbidden: cross-origin request", http.StatusForbidden)
				return
			}
		}
		if !allowedAPIHost(listenHost, r.Host) {
			http.Error(w, "forbidden: host", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func allowedAPIHost(listenHost, hostHeader string) bool {
	hostname := hostHeader
	if h, _, err := net.SplitHostPort(hostHeader); err == nil {
		hostname = h
	}
	hostname = strings.ToLower(strings.Trim(hostname, "[]"))
	if hostname == "" {
		return false
	}
	// 本机调用（默认场景）：127.0.0.1 / localhost / ::1
	if hostname == "localhost" {
		return true
	}
	if ip := net.ParseIP(hostname); ip != nil && ip.IsLoopback() {
		return true
	}
	// 显式绑定到某个地址时，只接受该地址本身
	if listenHost != "" && listenHost != "0.0.0.0" && listenHost != "::" {
		return strings.EqualFold(hostname, listenHost)
	}
	// 绑定通配地址（用户主动暴露到局域网）：接受 IP 字面量，拒绝域名
	// （DNS Rebinding 的 Host 永远是域名，这里被挡住）
	return net.ParseIP(hostname) != nil
}

func StartServer(addr string, eng *engine.Engine, configPath string) error {
	s := &Server{engine: eng, configPath: configPath}
	mux := http.NewServeMux()
	subFS, err := fs.Sub(web.FS, ".")
	if err != nil { return err }
	mux.Handle("/", http.FileServer(http.FS(subFS)))
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/upstream", s.handleUpstream)
	mux.HandleFunc("/api/performance", s.handlePerformance)
	mux.HandleFunc("/api/process-whitelist", s.handleProcessWhitelist)
	return http.ListenAndServe(addr, guard(addr, mux))
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
	pid, conns := 0, 0
	statuses := []engine.ProcessStatus{}
	if s.engine != nil && s.engine.Stats != nil { pid, conns = s.engine.Stats.PID, s.engine.Stats.Connections; statuses = s.engine.GetProcessStatuses() }
	proxyPrograms, directPrograms, proxyConnections, directConnections := 0, 0, 0, 0
	for _, p := range statuses { if p.Status == "proxy" { proxyPrograms++; proxyConnections += p.Connections } else { directPrograms++; directConnections += p.Connections } }
	istate, imsg := "stopped", "拦截器未启动"
	if s.engine != nil { istate, imsg = s.engine.InterceptorState() }
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"status":"running","interceptor":istate,"interceptor_msg":imsg,"pid":pid,"connections":conns,"proxy_programs":proxyPrograms,"direct_programs":directPrograms,"proxy_connections":proxyConnections,"direct_connections":directConnections,"processes":statuses})
}

func (s *Server) handleUpstream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.engine == nil { http.Error(w, "engine not ready", http.StatusServiceUnavailable); return }
	switch r.Method {
	case http.MethodGet:
		c := s.engine.GetConfig(); if len(c.Outbounds.Servers)==0 { _=json.NewEncoder(w).Encode(map[string]interface{}{"type":"","address":"","port":0}); return }
		x:=c.Outbounds.Servers[0]; _=json.NewEncoder(w).Encode(map[string]interface{}{"type":x.Type,"address":x.Address,"port":x.Port})
	case http.MethodPost:
		var req struct{Type string `json:"type"`; Address string `json:"address"`; Port int `json:"port"`}
		if err:=json.NewDecoder(r.Body).Decode(&req); err!=nil || (req.Type!="socks5" && req.Type!="http") || strings.TrimSpace(req.Address)=="" || req.Port<1 || req.Port>65535 { http.Error(w,"invalid upstream",http.StatusBadRequest); return }
		s.engine.UpdateUpstream(req.Type,strings.TrimSpace(req.Address),req.Port,s.configPath); _=json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok"})
	default: http.Error(w,"method not allowed",http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePerformance(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.engine == nil { http.Error(w,"engine not ready",http.StatusServiceUnavailable); return }
	switch r.Method {
	case http.MethodGet:
		p:=s.engine.GetConfig().Performance; _=json.NewEncoder(w).Encode(map[string]interface{}{"buffer_size":config.ClampBufferSize(p.BufferSize)})
	case http.MethodPost:
		var req struct{BufferSize int `json:"buffer_size"`}
		if err:=json.NewDecoder(r.Body).Decode(&req); err!=nil { http.Error(w,"invalid request",http.StatusBadRequest); return }
		size:=config.ClampBufferSize(req.BufferSize); s.engine.UpdatePerformance(config.PerformanceConfig{BufferSize:size})
		if err:=s.engine.SaveConfig(s.configPath); err!=nil { http.Error(w,"save failed",http.StatusInternalServerError); return }
		_=json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok","buffer_size":size})
	default: http.Error(w,"method not allowed",http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleProcessWhitelist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.engine == nil { http.Error(w,"engine not ready",http.StatusServiceUnavailable); return }
	switch r.Method {
	case http.MethodGet:
		_=json.NewEncoder(w).Encode(map[string]interface{}{"processes":s.engine.GetProcessWhitelist()})
	case http.MethodPost, http.MethodDelete:
		var req struct{Process string `json:"process"`}
		if err:=json.NewDecoder(r.Body).Decode(&req); err!=nil || strings.TrimSpace(req.Process)=="" { http.Error(w,"process is required",http.StatusBadRequest); return }
		process:=strings.TrimSpace(req.Process)
		list:=s.engine.GetProcessWhitelist()
		if r.Method==http.MethodPost {
			already:=false
			for _, p:=range list { if strings.EqualFold(p,process) { already=true; break } }
			if !already { list=append(list,process) }
		} else {
			filtered:=make([]string,0,len(list)); for _,p:=range list { if !strings.EqualFold(p,process){filtered=append(filtered,p)} }; list=filtered
		}
		s.engine.UpdateProcessWhitelist(list,s.configPath); _=json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok","processes":s.engine.GetProcessWhitelist()})
	default: http.Error(w,"method not allowed",http.StatusMethodNotAllowed)
	}
}
