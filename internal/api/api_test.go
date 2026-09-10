package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CFM503/goPass/internal/config"
	"github.com/CFM503/goPass/internal/engine"
)

func setupTestEngine(t *testing.T) (*engine.Engine, *Server) {
	t.Helper()
	cfg := config.DefaultConfig()
	eng, err := engine.New(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	return eng, &Server{engine: eng}
}

func TestAPISettingsAndPerformanceEndpoints(t *testing.T) {
	_, s := setupTestEngine(t)

	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	w := httptest.NewRecorder()
	s.handleSettings(w, req)
	if w.Code != http.StatusOK { t.Fatalf("GET /api/settings status = %d", w.Code) }

	req = httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewBufferString(`{"ws_refresh_interval":2,"ui_conn_limit":30}`))
	w = httptest.NewRecorder(); s.handleSettings(w, req)
	if w.Code != http.StatusOK { t.Fatalf("POST /api/settings status = %d", w.Code) }

	req = httptest.NewRequest(http.MethodPost, "/api/performance", bytes.NewBufferString(`{"buffer_size":2097152,"tcp_nodelay":true,"tcp_keep_alive":true,"keep_alive_period":15,"tcp_linger":-1}`))
	w = httptest.NewRecorder(); s.handlePerformance(w, req)
	if w.Code != http.StatusOK { t.Fatalf("POST /api/performance status = %d", w.Code) }
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil { t.Fatal(err) }
	if int(resp["buffer_size"].(float64)) != 1024*1024 { t.Fatalf("buffer should be capped at 1MB, got %v", resp["buffer_size"]) }
}

func TestRemovedSplitEndpointIsNotRegistered(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.New(cfg)
	if err != nil { t.Fatal(err) }

	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", (&Server{engine: eng}).handleStatus)
	req := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
	w := httptest.NewRecorder(); mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound { t.Fatalf("expected /api/rules to be removed, got %d", w.Code) }
}
