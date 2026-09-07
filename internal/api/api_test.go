package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CFM503/goPass/internal/config"
	"github.com/CFM503/goPass/internal/controller"
	"github.com/CFM503/goPass/internal/engine"
)

func setupTestEngine(t *testing.T) (*engine.Engine, *Server) {
	cfg := config.DefaultConfig()
	cfg.AutomaticRoute.Enabled = true
	cfg.AutomaticRoute.Routes = []config.RouteConfig{
		{ID: "r1", Name: "R1", Address: "127.0.0.1", Port: 8001, Protocol: "socks5"},
		{ID: "r2", Name: "R2", Address: "127.0.0.1", Port: 8002, Protocol: "socks5"},
	}

	eng, err := engine.New(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	s := &Server{engine: eng}
	return eng, s
}

func TestAPIRouteEndpoints(t *testing.T) {
	_, s := setupTestEngine(t)

	// 1. GET /api/routes
	req := httptest.NewRequest(http.MethodGet, "/api/routes", nil)
	w := httptest.NewRecorder()
	s.handleRoutes(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/routes status = %d", w.Code)
	}
	var routesResp struct {
		Routes      []controller.Route `json:"routes"`
		AutoEnabled bool               `json:"auto_enabled"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &routesResp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(routesResp.Routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(routesResp.Routes))
	}

	// 2. POST /api/routes/report (外部 CFST 上报数据)
	handshake := true
	reportJSON := `[
		{"id":"r1","download_speed":15000000,"stability":0.95,"packet_loss":0.01,"jitter":2.0,"rtt":40.0,"handshake_success":true},
		{"id":"r2","download_speed":30000000,"stability":0.98,"packet_loss":0.0,"jitter":1.0,"rtt":30.0,"handshake_success":true}
	]`
	req = httptest.NewRequest(http.MethodPost, "/api/routes/report", bytes.NewBufferString(reportJSON))
	w = httptest.NewRecorder()
	s.handleRoutesReport(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/routes/report status = %d", w.Code)
	}

	// 3. GET /api/routes/metrics
	req = httptest.NewRequest(http.MethodGet, "/api/routes/metrics", nil)
	w = httptest.NewRecorder()
	s.handleRoutesMetrics(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/routes/metrics status = %d", w.Code)
	}

	// 4. POST /api/routes/switch (手动切换)
	switchReq := `{"id":"r2"}`
	req = httptest.NewRequest(http.MethodPost, "/api/routes/switch", bytes.NewBufferString(switchReq))
	w = httptest.NewRecorder()
	s.handleRoutesSwitch(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/routes/switch status = %d", w.Code)
	}

	// 5. GET /api/routes/current
	req = httptest.NewRequest(http.MethodGet, "/api/routes/current", nil)
	w = httptest.NewRecorder()
	s.handleRoutesCurrent(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/routes/current status = %d", w.Code)
	}
	var currResp struct {
		Current *controller.Route `json:"current"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &currResp); err != nil || currResp.Current == nil {
		t.Fatalf("expected current route, got %v", currResp.Current)
	}
	if currResp.Current.ID != "r2" {
		t.Fatalf("expected current route to be r2, got %s", currResp.Current.ID)
	}

	// 6. POST /api/routes/disable
	req = httptest.NewRequest(http.MethodPost, "/api/routes/disable", nil)
	w = httptest.NewRecorder()
	s.handleRoutesDisable(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/routes/disable status = %d", w.Code)
	}

	// 7. POST /api/routes/enable
	req = httptest.NewRequest(http.MethodPost, "/api/routes/enable", nil)
	w = httptest.NewRecorder()
	s.handleRoutesEnable(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/routes/enable status = %d", w.Code)
	}

	// 8. POST /api/routes (新增线路)
	newRoute := `{"id":"r3","name":"Route 3","address":"127.0.0.1","port":8003,"protocol":"socks5"}`
	req = httptest.NewRequest(http.MethodPost, "/api/routes", bytes.NewBufferString(newRoute))
	w = httptest.NewRecorder()
	s.handleRoutes(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/routes status = %d", w.Code)
	}

	// 9. DELETE /api/routes (删除线路)
	delRoute := `{"id":"r3"}`
	req = httptest.NewRequest(http.MethodDelete, "/api/routes", bytes.NewBufferString(delRoute))
	w = httptest.NewRecorder()
	s.handleRoutes(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE /api/routes status = %d", w.Code)
	}
	_ = handshake
}
