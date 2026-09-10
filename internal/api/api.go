package api

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"

	"github.com/CFM503/goPass/internal/config"
	"github.com/CFM503/goPass/internal/engine"
	"github.com/CFM503/goPass/web"
)

type Server struct{ engine *engine.Engine }

func StartServer(addr string, eng *engine.Engine) error {
	s := &Server{engine: eng}
	mux := http.NewServeMux()
	subFS, err := fs.Sub(web.FS, ".")
	if err != nil { return err }
	mux.Handle("/", http.FileServer(http.FS(subFS)))
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/upstream", s.handleUpstream)
	mux.HandleFunc("/api/performance", s.handlePerformance)
	mux.HandleFunc("/api/process-whitelist", s.handleProcessWhitelist)
	return http.ListenAndServe(addr, mux)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
	pid, conns := 0, 0
	statuses := []engine.ProcessStatus{}
	if s.engine != nil && s.engine.Stats != nil { pid, conns = s.engine.Stats.PID, s.engine.Stats.Connections; statuses = s.engine.GetProcessStatuses() }
	proxyPrograms, directPrograms, proxyConnections, directConnections := 0, 0, 0, 0
	for _, p := range statuses { if p.Status == "proxy" { proxyPrograms++; proxyConnections += p.Connections } else { directPrograms++; directConnections += p.Connections } }
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"status":"running","pid":pid,"connections":conns,"proxy_programs":proxyPrograms,"direct_programs":directPrograms,"proxy_connections":proxyConnections,"direct_connections":directConnections,"processes":statuses})
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
		s.engine.UpdateUpstream(req.Type,strings.TrimSpace(req.Address),req.Port,"config.json"); _=json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok"})
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
		if err:=s.engine.SaveConfig("config.json"); err!=nil { http.Error(w,"save failed",http.StatusInternalServerError); return }
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
		s.engine.UpdateProcessWhitelist(list,"config.json"); _=json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok","processes":s.engine.GetProcessWhitelist()})
	default: http.Error(w,"method not allowed",http.StatusMethodNotAllowed)
	}
}
