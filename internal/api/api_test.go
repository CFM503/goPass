package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	// 用临时目录，避免测试把 config.json 写进仓库
	return eng, &Server{engine: eng, configPath: filepath.Join(t.TempDir(), "config.json")}
}

func TestAPIPerformanceEndpoint(t *testing.T) {
	_, s := setupTestEngine(t)

	req := httptest.NewRequest(http.MethodGet, "/api/performance", nil)
	w := httptest.NewRecorder()
	s.handlePerformance(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/performance status=%d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/performance", bytes.NewBufferString(`{"buffer_size":2097152,"tcp_nodelay":true,"tcp_keep_alive":true,"keep_alive_period":15,"tcp_linger":-1}`))
	w = httptest.NewRecorder()
	s.handlePerformance(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/performance status=%d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if int(resp["buffer_size"].(float64)) != 1024*1024 {
		t.Fatalf("buffer should be capped at 1MB, got %v", resp["buffer_size"])
	}
}

func TestStatusReportsInterceptorState(t *testing.T) {
	eng, s := setupTestEngine(t)
	if st, _ := eng.InterceptorState(); st != "stopped" {
		t.Fatalf("engine not started should be stopped, got %q", st)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	w := httptest.NewRecorder()
	s.handleStatus(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["interceptor"] != "stopped" {
		t.Fatalf("interceptor=%v, want stopped", resp["interceptor"])
	}
	if _, ok := resp["interceptor_msg"]; !ok {
		t.Fatal("interceptor_msg missing from /api/status")
	}
	if resp["status"] != "running" {
		t.Fatalf("status=%v", resp["status"])
	}
}

func TestRemovedSplitEndpointIsNotRegistered(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{engine: eng, configPath: filepath.Join(t.TempDir(), "config.json")}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", s.handleStatus)
	req := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected /api/rules to be removed, got %d", w.Code)
	}
}
