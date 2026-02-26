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
		if s.engine != nil && s.engine.GetConfig() != nil {
			mode = s.engine.GetConfig().Routing.Mode
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"mode": mode,
		})
		return
	} else if r.Method == http.MethodPost {
		var req struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
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
