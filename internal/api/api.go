package api

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"sync"

	"github.com/yourusername/gopass/internal/config"
	"github.com/yourusername/gopass/internal/engine"
	"github.com/yourusername/gopass/web"
)

var jsonBufPool = sync.Pool{
	New: func() interface{} {
		buf := &bytes.Buffer{}
		buf.Grow(512)
		return buf
	},
}

var jsonEncPool = sync.Pool{
	New: func() interface{} {
		buf := &bytes.Buffer{}
		buf.Grow(512)
		enc := json.NewEncoder(buf)
		return struct {
			buf *bytes.Buffer
			enc *json.Encoder
		}{buf, enc}
	},
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	item := jsonEncPool.Get().(struct {
		buf *bytes.Buffer
		enc *json.Encoder
	})
	defer jsonEncPool.Put(item)

	item.buf.Reset()
	w.Header().Set("Content-Type", "application/json")
	item.enc.Encode(v)
	w.Write(item.buf.Bytes())
}

// Typed response structs to eliminate map[string]interface{} allocations
type statusResp struct {
	Status      string `json:"status"`
	PID         int    `json:"pid"`
	Connections int32  `json:"connections"`
}

type settingsResp struct {
	Mode              string `json:"mode"`
	WSRefreshInterval int    `json:"ws_refresh_interval"`
	UIConnLimit       int    `json:"ui_conn_limit"`
	ShowDirectConns   bool   `json:"show_direct_conns"`
	DirectConnsLimit  int    `json:"direct_conns_limit"`
}

type rulesResp struct {
	Rules []config.Rule `json:"rules"`
}

type upstreamResp struct {
	Type    string `json:"type"`
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type okResp struct {
	Status string `json:"status"`
}

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
	mux.HandleFunc("/ws", ws.HandleWS)

	log.Printf("Web UI and API server listening on http://%s\n", addr)
	return http.ListenAndServe(addr, mux)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	resp := statusResp{Status: "running"}
	if s.engine != nil && s.engine.Stats != nil {
		resp.PID = s.engine.Stats.PID
		resp.Connections = s.engine.Stats.Connections
	}
	writeJSON(w, resp)
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		resp := settingsResp{
			Mode:             "whitelist",
			WSRefreshInterval: 5,
			UIConnLimit:      100,
			DirectConnsLimit: 20,
		}
		if cfg := s.engine.GetConfig(); cfg != nil {
			resp.Mode = cfg.Routing.Mode
			resp.WSRefreshInterval = cfg.API.WSRefreshInterval
			if cfg.API.UIConnLimit > 0 {
				resp.UIConnLimit = cfg.API.UIConnLimit
			}
			resp.ShowDirectConns = cfg.API.ShowDirectConns
			if cfg.API.DirectConnsLimit > 0 {
				resp.DirectConnsLimit = cfg.API.DirectConnsLimit
			}
		}
		writeJSON(w, resp)
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
				if err := s.engine.UpdateMode(req.Mode, "config.json"); err != nil {
					log.Printf("[API] ⚠️ 保存配置失败: %v", err)
				} else {
					log.Printf("[API] ✅ 已保存设置")
				}
			}
			writeJSON(w, okResp{Status: "ok"})
			return
		}
	}
	http.Error(w, "invalid request", http.StatusBadRequest)
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		resp := rulesResp{Rules: []config.Rule{}}
		if cfg := s.engine.GetConfig(); cfg != nil {
			resp.Rules = cfg.Routing.Rules
		}
		writeJSON(w, resp)
		return
	} else if r.Method == http.MethodPost {
		var req struct {
			Rules []config.Rule `json:"rules"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			if s.engine != nil {
				s.engine.UpdateRules(req.Rules, "config.json")
			}
			writeJSON(w, okResp{Status: "ok"})
			return
		}
	}
	http.Error(w, "invalid request", http.StatusBadRequest)
}

func (s *Server) handleUpstream(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		resp := upstreamResp{}
		if cfg := s.engine.GetConfig(); cfg != nil && len(cfg.Outbounds.Servers) > 0 {
			srv := cfg.Outbounds.Servers[0]
			resp.Type = srv.Type
			resp.Address = srv.Address
			resp.Port = srv.Port
		}
		writeJSON(w, resp)
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
			writeJSON(w, okResp{Status: "ok"})
			return
		}
	}
	http.Error(w, "invalid request", http.StatusBadRequest)
}

func (s *Server) handlePerformance(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		var perf config.PerformanceConfig
		if cfg := s.engine.GetConfig(); cfg != nil {
			perf = cfg.Performance
		}
		writeJSON(w, perf)
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
			writeJSON(w, okResp{Status: "ok"})
			return
		}
	}
	http.Error(w, "invalid request", http.StatusBadRequest)
}
