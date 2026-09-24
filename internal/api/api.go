package api

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

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

// StartServer 先绑定端口，成功后在后台 goroutine 上服务并立即返回；
// 返回的 *http.Server 交给调用方在退出时做优雅关闭。
//
// 绑定失败仍以错误返回（端口被占用要能让调用方看清楚）；服务期间出错只记日志，
// 与旧行为一致——这是控制台，不该因为一次读写错误就带走整个代理。
//
// 直接返回 http.ListenAndServe 的话调用方拿不到 *http.Server，进程退出只能靠
// OS 兜底：正在跑的请求（比如正在写 config.json 的保存）会被拦腰截断。
func StartServer(addr string, eng *engine.Engine, configPath string) (*http.Server, error) {
	s := &Server{engine: eng, configPath: configPath}
	mux := http.NewServeMux()
	subFS, err := fs.Sub(web.FS, ".")
	if err != nil { return nil, err }
	mux.Handle("/", http.FileServer(http.FS(subFS)))
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/upstream", s.handleUpstream)
	mux.HandleFunc("/api/performance", s.handlePerformance)
	mux.HandleFunc("/api/process-whitelist", s.handleProcessWhitelist)
	ln, err := net.Listen("tcp", addr)
	if err != nil { return nil, err }
	// 进站设超时，出站不设。
	//
	// http.Server 这四个字段默认全是 0（无限），等于把连接的生命周期完全交给
	// 对端，本机上任何能连到这个端口的进程（或畸形客户端）都能无限期占着
	// goroutine 和 socket：
	//
	//   - 缺 ReadHeaderTimeout → Slowloris：连接开着、请求头一个字节一个字节
	//     地送。Go 文档点名要这个字段来防，是四者里唯一真正致命的。
	//   - 缺 ReadTimeout       → 请求体慢慢滴灌，handler 卡在 Decode 上不回来。
	//   - 缺 IdleTimeout       → keep-alive 连接空闲多久都不回收。
	//
	// 这三项都只约束"读"，本机 UI 不可能踩到：浏览器的请求头和几百字节的 JSON
	// 体都是瞬间写完的；状态轮询每 3 秒一次，远够不到 60 秒空闲上限，即便标签
	// 页进后台导致轮询暂停、连接被回收，下一次 fetch 也只是悄悄新开一条，页面
	// 无感知。
	//
	// WriteTimeout 刻意保持 0：它约束"handler 执行 + 回包"的总时长，设了就等于
	// 允许把响应拦腰切断——磁盘卡顿时会出现配置已写成功、界面却报"保存失败"
	// 的矛盾。本服务的响应只有几百字节，内核缓冲区直接收下，慢读的客户端占不
	// 到什么便宜，拿这种风险去换一层几乎无收益的防护不划算。
	srv := &http.Server{
		Addr:              addr,
		Handler:           guard(addr, mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("API 服务器错误: %v", err)
		}
	}()
	return srv, nil
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
		// 增删整段交给引擎在一把锁里做"读-改-写"，响应直接用这次落定的结果。
		// 此处先 Get 再 Update 的话，两个并发请求会基于同一份快照各改各的，
		// 后写者整份覆盖先写者，静默丢掉一次变更。
		process:=strings.TrimSpace(req.Process)
		list:=s.engine.AddProcess(process,s.configPath)
		if r.Method==http.MethodDelete { list=s.engine.RemoveProcess(process,s.configPath) }
		_=json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok","processes":list})
	default: http.Error(w,"method not allowed",http.StatusMethodNotAllowed)
	}
}
