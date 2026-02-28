package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/yourusername/gopass/internal/config"
	"github.com/yourusername/gopass/internal/engine"
)

type Server struct {
	engine *engine.Engine
}

func StartServer(addr string, eng *engine.Engine) error {
	s := &Server{engine: eng}

	mux := http.NewServeMux()

	ws := NewWSServer(eng)

	// Serve static web UI
	mux.Handle("/", http.FileServer(http.Dir("./web")))

	// API endpoints
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/settings", s.handleSettings)
	mux.HandleFunc("/api/rules", s.handleRules)
	mux.HandleFunc("/api/upstream", s.handleUpstream)
	mux.HandleFunc("/api/performance", s.handlePerformance)
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
		connLimit := 20
		if s.engine != nil && s.engine.GetConfig() != nil {
			mode = s.engine.GetConfig().Routing.Mode
			interval = s.engine.GetConfig().API.WSRefreshInterval
			if s.engine.GetConfig().API.UIConnLimit > 0 {
				connLimit = s.engine.GetConfig().API.UIConnLimit
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"mode":                mode,
			"ws_refresh_interval": interval,
			"ui_conn_limit":       connLimit,
		})
		return
	} else if r.Method == http.MethodPost {
		var req struct {
			Mode              string `json:"mode"`
			WSRefreshInterval int    `json:"ws_refresh_interval"`
			UIConnLimit       int    `json:"ui_conn_limit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			if s.engine != nil && s.engine.GetConfig() != nil {
				if req.WSRefreshInterval < 1 {
					req.WSRefreshInterval = 5
				}
				if req.UIConnLimit < 1 {
					req.UIConnLimit = 20
				}
				s.engine.UpdateUIConfig(req.WSRefreshInterval, req.UIConnLimit)
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
		if s.engine != nil && s.engine.GetConfig() != nil && len(s.engine.GetConfig().Outbound.Servers) > 0 {
			srv := s.engine.GetConfig().Outbound.Servers[0]
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
			if perf.BufferSize < 4096 { perf.BufferSize = 4096 }
			if perf.BufferSize > 524288 { perf.BufferSize = 524288 }
			if s.engine != nil {
				s.engine.UpdatePerformance(perf)
				if cfg := s.engine.GetConfig(); cfg != nil {
					cfg.Save("config.json")
				}
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
			return
		}
	}
	http.Error(w, "invalid request", http.StatusBadRequest)
}
