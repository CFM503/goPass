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

type Server struct { engine *engine.Engine }

func StartServer(addr string, eng *engine.Engine) error {
    s := &Server{engine: eng}
    mux := http.NewServeMux()
    ws := NewWSServer(eng)
    subFS, err := fs.Sub(web.FS, ".")
    if err != nil { return err }
    mux.Handle("/", http.FileServer(http.FS(subFS)))
    mux.HandleFunc("/api/status", s.handleStatus)
    mux.HandleFunc("/api/settings", s.handleSettings)
    mux.HandleFunc("/api/upstream", s.handleUpstream)
    mux.HandleFunc("/api/performance", s.handlePerformance)
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
    log.Printf("Web UI and API server listening on http://%s", addr)
    return http.ListenAndServe(addr, mux)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    pid, conns := 0, 0
    if s.engine != nil && s.engine.Stats != nil { pid, conns = s.engine.Stats.PID, s.engine.Stats.Connections }
    _ = json.NewEncoder(w).Encode(map[string]interface{}{"status":"running","pid":pid,"connections":conns})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    if r.Method == http.MethodGet {
        interval, connLimit := 5, 20
        if s.engine != nil { cfg := s.engine.GetConfig(); interval = cfg.API.WSRefreshInterval; connLimit = cfg.API.UIConnLimit }
        _ = json.NewEncoder(w).Encode(map[string]interface{}{"ws_refresh_interval":interval,"ui_conn_limit":connLimit})
        return
    }
    if r.Method != http.MethodPost { http.Error(w,"invalid request",http.StatusBadRequest); return }
    var req struct { WSRefreshInterval int `json:"ws_refresh_interval"`; UIConnLimit int `json:"ui_conn_limit"` }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil { http.Error(w,"invalid request",http.StatusBadRequest); return }
    if s.engine != nil { s.engine.UpdateUIConfig(req.WSRefreshInterval, req.UIConnLimit); _ = s.engine.SaveConfig("config.json") }
    _ = json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok"})
}

func (s *Server) handleUpstream(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    if r.Method == http.MethodGet {
        var pType, pAddr string; var pPort int
        if s.engine != nil { cfg := s.engine.GetConfig(); if len(cfg.Outbounds.Servers) > 0 { srv := cfg.Outbounds.Servers[0]; pType,pAddr,pPort=srv.Type,srv.Address,srv.Port } }
        _ = json.NewEncoder(w).Encode(map[string]interface{}{"type":pType,"address":pAddr,"port":pPort}); return
    }
    if r.Method == http.MethodPost {
        var req struct { Type string `json:"type"`; Address string `json:"address"`; Port int `json:"port"` }
        if err := json.NewDecoder(r.Body).Decode(&req); err == nil && s.engine != nil && (req.Type == "socks5" || req.Type == "http") && req.Address != "" && req.Port >= 1 && req.Port <= 65535 {
            s.engine.UpdateUpstream(req.Type, req.Address, req.Port, "config.json")
            _ = json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok"}); return
        }
    }
    http.Error(w,"invalid request",http.StatusBadRequest)
}

func (s *Server) handlePerformance(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    if r.Method == http.MethodGet {
        var perf config.PerformanceConfig
        if s.engine != nil { perf = s.engine.GetConfig().Performance }
        _ = json.NewEncoder(w).Encode(perf); return
    }
    if r.Method != http.MethodPost { http.Error(w,"invalid request",http.StatusBadRequest); return }
    var perf config.PerformanceConfig
    if err := json.NewDecoder(r.Body).Decode(&perf); err != nil { http.Error(w,"invalid request",http.StatusBadRequest); return }
    if perf.BufferSize == 0 { perf.BufferSize = config.DefaultConfig().Performance.BufferSize } else { perf.BufferSize = config.ClampBufferSize(perf.BufferSize) }
    if perf.KeepAlivePeriod < 1 || perf.KeepAlivePeriod > 3600 { perf.KeepAlivePeriod = 15 }
    perf.TCPLinger = -1
    if s.engine != nil { s.engine.UpdatePerformance(perf); _ = s.engine.SaveConfig("config.json") }
    _ = json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok","buffer_size":perf.BufferSize})
}

func (s *Server) handleConfigReset(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    if r.Method != http.MethodPost { http.Error(w,"invalid request",http.StatusBadRequest); return }
    if s.engine == nil { http.Error(w,"engine not ready",http.StatusInternalServerError); return }
    if err := s.engine.ResetConfig("config.json"); err != nil { _ = json.NewEncoder(w).Encode(map[string]interface{}{"status":"error","error":err.Error()}); return }
    _ = json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok"})
}

func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    if s.engine == nil || s.engine.Controller() == nil { http.Error(w,"controller not ready",http.StatusServiceUnavailable); return }
    ctrl := s.engine.Controller()
    switch r.Method {
    case http.MethodGet:
        _ = json.NewEncoder(w).Encode(map[string]interface{}{"routes":ctrl.GetRoutes(),"auto_enabled":ctrl.IsAutoEnabled()})
    case http.MethodPost:
        var req struct { ID string `json:"id"`; Name string `json:"name"`; Address string `json:"address"`; Port int `json:"port"`; Protocol string `json:"protocol"`; Type string `json:"type"` }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" { http.Error(w,"id is required",http.StatusBadRequest); return }
        if err := ctrl.RegisterRoute(controller.NewRoute(req.ID,req.Name,req.Address,req.Port,req.Protocol,req.Type)); err != nil { _ = json.NewEncoder(w).Encode(map[string]interface{}{"status":"error","error":err.Error()}); return }
        _ = json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok"})
    case http.MethodDelete:
        var req struct { ID string `json:"id"` }; _ = json.NewDecoder(r.Body).Decode(&req); if req.ID == "" { req.ID=r.URL.Query().Get("id") }; if req.ID=="" { http.Error(w,"id is required",http.StatusBadRequest); return }
        if err := ctrl.UnregisterRoute(req.ID); err != nil { _ = json.NewEncoder(w).Encode(map[string]interface{}{"status":"error","error":err.Error()}); return }
        _ = json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok"})
    default: http.Error(w,"method not allowed",http.StatusMethodNotAllowed)
    }
}

func (s *Server) handleRoutesCurrent(w http.ResponseWriter, r *http.Request) { w.Header().Set("Content-Type","application/json"); if s.engine==nil||s.engine.Controller()==nil { http.Error(w,"controller not ready",503); return }; _=json.NewEncoder(w).Encode(map[string]interface{}{"current":s.engine.Controller().GetCurrentRoute()}) }
func (s *Server) handleRoutesStandby(w http.ResponseWriter, r *http.Request) { w.Header().Set("Content-Type","application/json"); if s.engine==nil||s.engine.Controller()==nil { http.Error(w,"controller not ready",503); return }; _=json.NewEncoder(w).Encode(map[string]interface{}{"standby":s.engine.Controller().GetStandbyRoutes()}) }
func (s *Server) handleRoutesMetrics(w http.ResponseWriter, r *http.Request) { w.Header().Set("Content-Type","application/json"); if s.engine==nil||s.engine.Controller()==nil { http.Error(w,"controller not ready",503); return }; if r.Method==http.MethodPost { s.handleRoutesReport(w,r); return }; _=json.NewEncoder(w).Encode(map[string]interface{}{"metrics":s.engine.Controller().GetMetrics()}) }
func (s *Server) handleRoutesSwitch(w http.ResponseWriter, r *http.Request) { w.Header().Set("Content-Type","application/json"); if r.Method!=http.MethodPost||s.engine==nil||s.engine.Controller()==nil { http.Error(w,"controller not ready",503); return }; var req struct{ ID string `json:"id"` }; if err:=json.NewDecoder(r.Body).Decode(&req);err!=nil||req.ID==""{http.Error(w,"id is required",400);return};if err:=s.engine.Controller().SwitchTo(req.ID,true);err!=nil{_=json.NewEncoder(w).Encode(map[string]interface{}{"status":"error","error":err.Error()});return};_=json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok","current":s.engine.Controller().GetCurrentRoute()}) }
func (s *Server) handleRoutesEnable(w http.ResponseWriter,r *http.Request){w.Header().Set("Content-Type","application/json");if r.Method!=http.MethodPost||s.engine==nil||s.engine.Controller()==nil{http.Error(w,"controller not ready",503);return};s.engine.Controller().EnableAuto();_=json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok","auto_enabled":true})}
func (s *Server) handleRoutesDisable(w http.ResponseWriter,r *http.Request){w.Header().Set("Content-Type","application/json");if r.Method!=http.MethodPost||s.engine==nil||s.engine.Controller()==nil{http.Error(w,"controller not ready",503);return};s.engine.Controller().DisableAuto();_=json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok","auto_enabled":false})}
func(s *Server)handleRoutesReport(w http.ResponseWriter,r *http.Request){w.Header().Set("Content-Type","application/json");if r.Method!=http.MethodPost||s.engine==nil||s.engine.Controller()==nil{http.Error(w,"controller not ready",503);return};var raw json.RawMessage;if err:=json.NewDecoder(r.Body).Decode(&raw);err!=nil{http.Error(w,"invalid json",400);return};var reports []controller.RouteMetricReport;if err:=json.Unmarshal(raw,&reports);err!=nil{var one controller.RouteMetricReport;if err2:=json.Unmarshal(raw,&one);err2!=nil{http.Error(w,"invalid payload",400);return};reports=[]controller.RouteMetricReport{one}};s.engine.Controller().ReportMetrics(reports);_=json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok","ingested":len(reports)})}
