package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
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

// B5 回归：并发 POST 白名单不能丢变更。
//
// 处理器此前是"先 GetProcessWhitelist 拷一份 → 就地改 → 写回整份列表"：两个并发
// 请求会基于同一份快照各改各的，后写者整份覆盖先写者，先到的那次增删静默消失。
// 把读-改-写收进引擎的一把锁之后，N 个并发增删必须留下 N 条。
func TestConcurrentWhitelistEditsAreNotLost(t *testing.T) {
	_, s := setupTestEngine(t)

	const n = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // 让 n 个请求尽量同时进入处理器，制造真实的读-改-写交叠
			body := bytes.NewBufferString(fmt.Sprintf(`{"process":"proc%02d.exe"}`, i))
			req := httptest.NewRequest(http.MethodPost, "/api/process-whitelist", body)
			w := httptest.NewRecorder()
			s.handleProcessWhitelist(w, req)
			if w.Code != http.StatusOK {
				t.Errorf("POST #%d status=%d", i, w.Code)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	got := s.engine.GetProcessWhitelist()
	if len(got) != n {
		t.Fatalf("whitelist kept %d of %d concurrent additions: %v", len(got), n, got)
	}
	seen := map[string]bool{}
	for _, p := range got {
		seen[p] = true
	}
	for i := 0; i < n; i++ {
		if want := fmt.Sprintf("proc%02d.exe", i); !seen[want] {
			t.Fatalf("lost update: %s missing from %v", want, got)
		}
	}
}
