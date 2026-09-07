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

	// [v1.2.6 Config] 真正的单文件运行机制：直接从内嵌的二进制内存文件系统中读取 web 界面
	subFS, err := fs.Sub(web.FS, ".")
	if err != nil {
		return err
	}
	mux.Handle("/", http.FileServer(http.FS(subFS)))

	// API endpoints
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/settings", s.handleSettings)
	mux.HandleFunc("/api/rules", s.handleRules)
	mux.HandleFunc("/api/upstream", s.handleUpstream)
	mux.HandleFunc("/api/performance", s.handlePerformance)
	mux.HandleFunc("/api/split", s.handleSplit)
	mux.HandleFunc("/api/split/update-rules", s.handleSplitUpdateRules)
	mux.HandleFunc("/api/config/reset", s.handleConfigReset)

	// Dynamic Route Controller endpoints
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
	if s.engine != nil && s.engine.Stats != nil {
		pid = s.engine.Stats.PID
	}
	conns := 0
	if s.engine != nil && s.engine.Stats != nil {
		conns = s.engine.Stats.Connections
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "running",
		"pid":         pid,
		"connections": conns,
	})
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
			mode = s.engine.GetConfig().Routing.Mode
			interval = s.engine.GetConfig().API.WSRefreshInterval
			if s.engine.GetConfig().API.UIConnLimit > 0 {
				connLimit = s.engine.GetConfig().API.UIConnLimit
			}
			showDirect = s.engine.GetConfig().API.ShowDirectConns
			if s.engine.GetConfig().API.DirectConnsLimit > 0 {
				directLimit = s.engine.GetConfig().API.DirectConnsLimit
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"mode":                mode,
			"ws_refresh_interval": interval,
			"ui_conn_limit":       connLimit,
			"show_direct_conns":   showDirect,
			"direct_conns_limit":  directLimit,
		})
		return
	} else if r.Method == http.MethodPost {
		var req struct {
			Mode              string `json:"mode"`
			WSRefreshInterval int    `json:"ws_refresh_interval"`
			UIConnLimit       int    `json:"ui_conn_limit"`
			ShowDirectConns   bool   `json:"show_direct_conns"`
			DirectConnsLimit  int    `json:"direct_conns_limit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			if s.engine != nil && s.engine.GetConfig() != nil {
				if req.WSRefreshInterval < 1 {
					req.WSRefreshInterval = 5
				}
				if req.UIConnLimit < 1 {
					req.UIConnLimit = 100
				}
				if req.DirectConnsLimit < 1 {
					req.DirectConnsLimit = 20
				}
				s.engine.UpdateUIConfig(req.WSRefreshInterval, req.UIConnLimit, req.ShowDirectConns, req.DirectConnsLimit)
			}
			s.engine.UpdateMode(req.Mode, "config.json")
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
			return
		}
	}
	http.Error(w, "invalid request", http.StatusBadRequest)
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		var rules interface{} = []interface{}{}
		if s.engine != nil && s.engine.GetConfig() != nil {
			rules = s.engine.GetConfig().Routing.Rules
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"rules": rules,
		})
		return
	} else if r.Method == http.MethodPost {
		var req struct {
			Rules []config.Rule `json:"rules"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			if s.engine != nil {
				s.engine.UpdateRules(req.Rules, "config.json")
			}
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
			pType = srv.Type
			pAddr = srv.Address
			pPort = srv.Port
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"type":    pType,
			"address": pAddr,
			"port":    pPort,
		})
		return
	} else if r.Method == http.MethodPost {
		var req struct {
			Type    string `json:"type"`
			Address string `json:"address"`
			Port    int    `json:"port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			if s.engine != nil {
				s.engine.UpdateUpstream(req.Type, req.Address, req.Port, "config.json")
			}
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
		if s.engine != nil && s.engine.GetConfig() != nil {
			perf = s.engine.GetConfig().Performance
		}
		json.NewEncoder(w).Encode(perf)
		return
	} else if r.Method == http.MethodPost {
		var perf config.PerformanceConfig
		if err := json.NewDecoder(r.Body).Decode(&perf); err == nil {
			if perf.BufferSize < 4096 {
				perf.BufferSize = 4096
			}
			if perf.BufferSize > 524288 {
				perf.BufferSize = 524288
			}
			if s.engine != nil {
				s.engine.UpdatePerformance(perf)
				s.engine.SaveConfig("config.json")
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
			return
		}
	}
	http.Error(w, "invalid request", http.StatusBadRequest)
}

// handleSplit 获取 / 更新「绝对分流」配置（热重载）。
func (s *Server) handleSplit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		var data map[string]interface{} = map[string]interface{}{}
		if s.engine != nil {
			data = s.engine.GetSplit()
		}
		json.NewEncoder(w).Encode(data)
		return
	} else if r.Method == http.MethodPost {
		var sc config.SplitConfig
		if err := json.NewDecoder(r.Body).Decode(&sc); err == nil {
			if s.engine != nil {
				s.engine.UpdateSplit(sc, "config.json")
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
			return
		}
	}
	http.Error(w, "invalid request", http.StatusBadRequest)
}

// handleSplitUpdateRules 在线更新规则文件并热重载。
// GET  -> 返回下载进度快照（供前端轮询进度条）
// POST -> 启动规则文件更新
func (s *Server) handleSplitUpdateRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.engine == nil {
		http.Error(w, "engine not ready", http.StatusInternalServerError)
		return
	}
	if r.Method == http.MethodGet {
		json.NewEncoder(w).Encode(s.engine.GetUpdateProgress())
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	res := s.engine.UpdateRuleFiles()
	json.NewEncoder(w).Encode(res)
}

// handleConfigReset 将全部配置复位为出厂默认值并热应用。
func (s *Server) handleConfigReset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if s.engine == nil {
		http.Error(w, "engine not ready", http.StatusInternalServerError)
		return
	}
	if err := s.engine.ResetConfig("config.json"); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
}

// =============================================================================
// Dynamic Route Controller Handlers
// =============================================================================

func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.engine == nil || s.engine.Controller() == nil {
		http.Error(w, `{"error":"controller not ready"}`, http.StatusServiceUnavailable)
		return
	}
	ctrl := s.engine.Controller()

	switch r.Method {
	case http.MethodGet:
		routes := ctrl.GetRoutes()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"routes":       routes,
			"auto_enabled": ctrl.IsAutoEnabled(),
		})

	case http.MethodPost:
		var req struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Address  string `json:"address"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Type     string `json:"type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}
		if req.ID == "" {
			http.Error(w, `{"error":"id is required"}`, http.StatusBadRequest)
			return
		}
		route := controller.NewRoute(req.ID, req.Name, req.Address, req.Port, req.Protocol, req.Type)
		if err := ctrl.RegisterRoute(route); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})

	case http.MethodDelete:
		var req struct {
			ID string `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.ID == "" {
			req.ID = r.URL.Query().Get("id")
		}
		if req.ID == "" {
			http.Error(w, `{"error":"id is required"}`, http.StatusBadRequest)
			return
		}
		if err := ctrl.UnregisterRoute(req.ID); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})

	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRoutesCurrent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.engine == nil || s.engine.Controller() == nil {
		http.Error(w, `{"error":"controller not ready"}`, http.StatusServiceUnavailable)
		return
	}
	curr := s.engine.Controller().GetCurrentRoute()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"current": curr,
	})
}

func (s *Server) handleRoutesStandby(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.engine == nil || s.engine.Controller() == nil {
		http.Error(w, `{"error":"controller not ready"}`, http.StatusServiceUnavailable)
		return
	}
	standby := s.engine.Controller().GetStandbyRoutes()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"standby": standby,
	})
}

func (s *Server) handleRoutesMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.engine == nil || s.engine.Controller() == nil {
		http.Error(w, `{"error":"controller not ready"}`, http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodPost {
		s.handleRoutesReport(w, r)
		return
	}
	metrics := s.engine.Controller().GetMetrics()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"metrics": metrics,
	})
}

func (s *Server) handleRoutesSwitch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if s.engine == nil || s.engine.Controller() == nil {
		http.Error(w, `{"error":"controller not ready"}`, http.StatusServiceUnavailable)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, `{"error":"id is required"}`, http.StatusBadRequest)
		return
	}
	if err := s.engine.Controller().SwitchTo(req.ID, true); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"current": s.engine.Controller().GetCurrentRoute(),
	})
}

func (s *Server) handleRoutesEnable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if s.engine == nil || s.engine.Controller() == nil {
		http.Error(w, `{"error":"controller not ready"}`, http.StatusServiceUnavailable)
		return
	}
	s.engine.Controller().EnableAuto()
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "auto_enabled": true})
}

func (s *Server) handleRoutesDisable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if s.engine == nil || s.engine.Controller() == nil {
		http.Error(w, `{"error":"controller not ready"}`, http.StatusServiceUnavailable)
		return
	}
	s.engine.Controller().DisableAuto()
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "auto_enabled": false})
}

// handleRoutesReport 接收外部 CFST / 探测脚本上报的数据 (支持单个对象或数组)
func (s *Server) handleRoutesReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if s.engine == nil || s.engine.Controller() == nil {
		http.Error(w, `{"error":"controller not ready"}`, http.StatusServiceUnavailable)
		return
	}

	var raw json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	var reports []controller.RouteMetricReport
	// 先尝试按数组反序列化
	if err := json.Unmarshal(raw, &reports); err != nil {
		// 再尝试按单对象反序列化
		var single controller.RouteMetricReport
		if errSingle := json.Unmarshal(raw, &single); errSingle != nil {
			http.Error(w, `{"error":"invalid payload format"}`, http.StatusBadRequest)
			return
		}
		reports = append(reports, single)
	}

	s.engine.Controller().ReportMetrics(reports)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"ingested": len(reports),
	})
}
