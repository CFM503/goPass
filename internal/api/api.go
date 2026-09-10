package api

import (
	"encoding/json"
	"io/fs"
	"log"
	"net/http"

	"github.com/CFM503/goPass/internal/config"
	"github.com/CFM503/goPass/internal/controller"
	"github.com/CFM503/goPass/internal/engine"
	"github.com/CFM503/goPass/web"
)

type Server struct {
	engine *engine.Engine
}

func StartServer(addr string, eng *engine.Engine) error {
	s := &Server{engine: eng}
	mux := http.NewServeMux()
	ws := NewWSServer(eng)
	subFS, err := fs.Sub(web.FS, ".")
	if err != nil {
		return err
	}
	mux.Handle("/", http.FileServer(http.FS(subFS)))
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/settings", s.handleSettings)
	mux.HandleFunc("/api/rules", s.handleRules)
	mux.HandleFunc("/api/upstream", s.handleUpstream)
	mux.HandleFunc("/api/performance", s.handlePerformance)
	mux.HandleFunc("/api/split", s.handleSplit)
	mux.HandleFunc("/api/split/update-rules", s.handleSplitUpdateRules)
	mux.HandleFunc("/api/config/reset", s.handleConfigReset)
	mux.HandleFunc("/api/routes", s.handleRoutes)
	mux.HandleFunc("/api/routes/current", s.handleRoutesCurrent)
	mux.HandleFunc("/api/routes/standby", s.handleRoutesStandby)
	mux.HandleFunc("/api/routes/metrics", s.handleRoutesMetrics)
	mux.HandleFunc("/api/routes/switch", s.handleRoutesSwitch)
	mux.HandleFunc("/api/routes/enable", s.handleRoutesEnable)
	mux.HandleFunc("/api/routes/disable", s.handleRoutesDisable)
	mux.HandleFunc("/api/routes/report", s.handleRoutesReport)
	mux.HandleFunc("/ws", ws.HandleWS)
	log.Printf("Web UI and API server listening on http://%s\n", addr)
	return http.ListenAndServe(addr, mux)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	pid := 0
	conns := 0
	if s.engine != nil && s.engine.Stats != nil {
		pid = s.engine.Stats.PID
		conns = s.engine.Stats.Connections
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "running", "pid": pid, "connections": conns})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		mode := "whitelist"
		interval := 5
		connLimit := 100
		showDirect := false
		directLimit := 20
		if s.engine != nil && s.engine.GetConfig() != nil {
			cfg := s.engine.GetConfig()
			mode = cfg.Routing.Mode
			interval = cfg.API.WSRefreshInterval
			if cfg.API.UIConnLimit > 0 {
				connLimit = cfg.API.UIConnLimit
			}
			showDirect = cfg.API.ShowDirectConns
			if cfg.API.DirectConnsLimit > 0 {
				directLimit = cfg.API.DirectConnsLimit
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"mode": mode, "ws_refresh_interval": interval, "ui_conn_limit": connLimit,
			"show_direct_conns": showDirect, "direct_conns_limit": directLimit,
		})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	var req struct {
		Mode              string `json:"mode"`
		WSRefreshInterval int    `json:"ws_refresh_interval"`
		UIConnLimit       int    `json:"ui_conn_limit"`
		ShowDirectConns   bool   `json:"show_direct_conns"`
		DirectConnsLimit  int    `json:"direct_conns_limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.WSRefreshInterval < 1 {
		req.WSRefreshInterval = 5
	}
	if req.UIConnLimit < 1 {
		req.UIConnLimit = 100
	}
	if req.DirectConnsLimit < 1 {
		req.DirectConnsLimit = 20
	}
	if s.engine != nil {
		s.engine.UpdateUIConfig(req.WSRefreshInterval, req.UIConnLimit, req.ShowDirectConns, req.DirectConnsLimit)
		s.engine.UpdateMode(req.Mode, "config.json")
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		var rules interface{} = []interface{}{}
		if s.engine != nil && s.engine.GetConfig() != nil {
			rules = s.engine.GetConfig().Routing.Rules
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"rules": rules})
		return
	}
	if r.Method == http.MethodPost {
		var req struct { Rules []config.Rule `json:"rules"` }
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			if s.engine != nil { s.engine.UpdateRules(req.Rules, "config.json") }
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
			return
		}
	}
	http.Error(w, "invalid request", http.StatusBadRequest)
}

func (s *Server) handleUpstream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		var pType, pAddr string
		var pPort int
		if s.engine != nil && s.engine.GetConfig() != nil && len(s.engine.GetConfig().Outbounds.Servers) > 0 {
			srv := s.engine.GetConfig().Outbounds.Servers[0]
			pType, pAddr, pPort = srv.Type, srv.Address, srv.Port
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"type": pType, "address": pAddr, "port": pPort})
		return
	}
	if r.Method == http.MethodPost {
		var req struct { Type string `json:"type"`; Address string `json:"address"`; Port int `json:"port"` }
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			if s.engine != nil { s.engine.UpdateUpstream(req.Type, req.Address, req.Port, "config.json") }
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
			return
		}
	}
	http.Error(w, "invalid request", http.StatusBadRequest)
}

func (s *Server) handlePerformance(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		var perf config.PerformanceConfig
		if s.engine != nil && s.engine.GetConfig() != nil { perf = s.engine.GetConfig().Performance }
		// Socket buffer is intentionally fixed at 0 for v1.6.6.
		perf.TCPSocketBuffer = 0
		json.NewEncoder(w).Encode(perf)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	var perf config.PerformanceConfig
	if err := json.NewDecoder(r.Body).Decode(&perf); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	perf.BufferSize = config.ClampBufferSize(perf.BufferSize)
	perf.TCPSocketBuffer = 0
	if perf.KeepAlivePeriod < 1 || perf.KeepAlivePeriod > 3600 { perf.KeepAlivePeriod = 15 }
	perf.TCPLinger = -1
	if s.engine != nil {
		s.engine.UpdatePerformance(perf)
		s.engine.SaveConfig("config.json")
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "buffer_size": perf.BufferSize, "tcp_socket_buffer": 0})
}

func (s *Server) handleSplit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		data := map[string]interface{}{}
		if s.engine != nil { data = s.engine.GetSplit() }
		json.NewEncoder(w).Encode(data)
		return
	}
	if r.Method == http.MethodPost {
		var sc config.SplitConfig
		if err := json.NewDecoder(r.Body).Decode(&sc); err == nil {
			if s.engine != nil { s.engine.UpdateSplit(sc, "config.json") }
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
			return
		}
	}
	http.Error(w, "invalid request", http.StatusBadRequest)
}

func (s *Server) handleSplitUpdateRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.engine == nil { http.Error(w, "engine not ready", http.StatusInternalServerError); return }
	if r.Method == http.MethodGet { json.NewEncoder(w).Encode(s.engine.GetUpdateProgress()); return }
	if r.Method != http.MethodPost { http.Error(w, "invalid request", http.StatusBadRequest); return }
	json.NewEncoder(w).Encode(s.engine.UpdateRuleFiles())
}

func (s *Server) handleConfigReset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost { http.Error(w, "invalid request", http.StatusBadRequest); return }
	if s.engine == nil { http.Error(w, "engine not ready", http.StatusInternalServerError); return }
	if err := s.engine.ResetConfig("config.json"); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "error": err.Error()}); return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
}

func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.engine == nil || s.engine.Controller() == nil { http.Error(w, `{"error":"controller not ready"}`, http.StatusServiceUnavailable); return }
	ctrl := s.engine.Controller()
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(map[string]interface{}{"routes": ctrl.GetRoutes(), "auto_enabled": ctrl.IsAutoEnabled()})
	case http.MethodPost:
		var req struct { ID string `json:"id"`; Name string `json:"name"`; Address string `json:"address"`; Port int `json:"port"`; Protocol string `json:"protocol"`; Type string `json:"type"` }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" { http.Error(w, `{"error":"id is required"}`, http.StatusBadRequest); return }
		if err := ctrl.RegisterRoute(controller.NewRoute(req.ID, req.Name, req.Address, req.Port, req.Protocol, req.Type)); err != nil { json.NewEncoder(w).Encode(map[string]interface{}{"status":"error","error":err.Error()}); return }
		json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok"})
	case http.MethodDelete:
		var req struct { ID string `json:"id"` }; _ = json.NewDecoder(r.Body).Decode(&req); if req.ID == "" { req.ID = r.URL.Query().Get("id") }; if req.ID == "" { http.Error(w, `{"error":"id is required"}`, http.StatusBadRequest); return }
		if err := ctrl.UnregisterRoute(req.ID); err != nil { json.NewEncoder(w).Encode(map[string]interface{}{"status":"error","error":err.Error()}); return }
		json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok"})
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRoutesCurrent(w http.ResponseWriter, r *http.Request) { w.Header().Set("Content-Type", "application/json"); if s.engine == nil || s.engine.Controller() == nil { http.Error(w, `{"error":"controller not ready"}`, http.StatusServiceUnavailable); return }; json.NewEncoder(w).Encode(map[string]interface{}{"current": s.engine.Controller().GetCurrentRoute()}) }
func (s *Server) handleRoutesStandby(w http.ResponseWriter, r *http.Request) { w.Header().Set("Content-Type", "application/json"); if s.engine == nil || s.engine.Controller() == nil { http.Error(w, `{"error":"controller not ready"}`, http.StatusServiceUnavailable); return }; json.NewEncoder(w).Encode(map[string]interface{}{"standby": s.engine.Controller().GetStandbyRoutes()}) }
func (s *Server) handleRoutesMetrics(w http.ResponseWriter, r *http.Request) { w.Header().Set("Content-Type", "application/json"); if s.engine == nil || s.engine.Controller() == nil { http.Error(w, `{"error":"controller not ready"}`, http.StatusServiceUnavailable); return }; if r.Method == http.MethodPost { s.handleRoutesReport(w, r); return }; json.NewEncoder(w).Encode(map[string]interface{}{"metrics": s.engine.Controller().GetMetrics()}) }
func (s *Server) handleRoutesSwitch(w http.ResponseWriter, r *http.Request) { w.Header().Set("Content-Type", "application/json"); if r.Method != http.MethodPost || s.engine == nil || s.engine.Controller() == nil { http.Error(w, `{"error":"controller not ready"}`, http.StatusServiceUnavailable); return }; var req struct { ID string `json:"id"` }; if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" { http.Error(w, `{"error":"id is required"}`, http.StatusBadRequest); return }; if err := s.engine.Controller().SwitchTo(req.ID, true); err != nil { json.NewEncoder(w).Encode(map[string]interface{}{"status":"error","error":err.Error()}); return }; json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok","current":s.engine.Controller().GetCurrentRoute()}) }
func (s *Server) handleRoutesEnable(w http.ResponseWriter, r *http.Request) { w.Header().Set("Content-Type", "application/json"); if r.Method != http.MethodPost || s.engine == nil || s.engine.Controller() == nil { http.Error(w, `{"error":"controller not ready"}`, http.StatusServiceUnavailable); return }; s.engine.Controller().EnableAuto(); json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok","auto_enabled":true}) }
func (s *Server) handleRoutesDisable(w http.ResponseWriter, r *http.Request) { w.Header().Set("Content-Type", "application/json"); if r.Method != http.MethodPost || s.engine == nil || s.engine.Controller() == nil { http.Error(w, `{"error":"controller not ready"}`, http.StatusServiceUnavailable); return }; s.engine.Controller().DisableAuto(); json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok","auto_enabled":false}) }

func (s *Server) handleRoutesReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost || s.engine == nil || s.engine.Controller() == nil { http.Error(w, `{"error":"controller not ready"}`, http.StatusServiceUnavailable); return }
	var raw json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil { http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest); return }
	var reports []controller.RouteMetricReport
	if err := json.Unmarshal(raw, &reports); err != nil { var single controller.RouteMetricReport; if errSingle := json.Unmarshal(raw, &single); errSingle != nil { http.Error(w, `{"error":"invalid payload format"}`, http.StatusBadRequest); return }; reports = append(reports, single) }
	s.engine.Controller().ReportMetrics(reports)
	json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok","ingested":len(reports)})
}
