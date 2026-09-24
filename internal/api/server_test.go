package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// S2 回归：StartServer 必须给进站方向设超时。
//
// http.Server 的四个超时字段默认全 0（无限），等于把连接的生命周期交给对端：
// 缺 ReadHeaderTimeout 挡不住 Slowloris（Go 文档点名要这个字段来防），缺
// ReadTimeout 让请求体可以无限滴灌、handler 卡在 Decode 上，缺 IdleTimeout
// 让 keep-alive 连接永远不回收。
//
// WriteTimeout 反过来刻意保持 0：它约束“handler 执行 + 回包”的总时长，设了
// 就等于允许把响应拦腰切断，磁盘卡顿时会出现配置已写成功、界面却报“保存失败”
// 的矛盾。下面断言的正是这个取舍本身，不是随手抄的数字——把它改成非 0 同样
// 会红。
func TestStartServerSetsInboundTimeouts(t *testing.T) {
	srv, err := StartServer("127.0.0.1:0", nil, filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("StartServer: %v", err)
	}
	defer func() { _ = srv.Close() }()

	if srv.ReadHeaderTimeout <= 0 {
		t.Error("ReadHeaderTimeout = 0：连接生命周期交给对端，Slowloris 挡不住")
	}
	if srv.ReadTimeout <= 0 {
		t.Error("ReadTimeout = 0：请求体可以无限滴灌，handler 卡在 Decode 上")
	}
	if srv.IdleTimeout <= 0 {
		t.Error("IdleTimeout = 0：keep-alive 连接空闲多久都不回收")
	}
	if srv.WriteTimeout != 0 {
		t.Errorf("WriteTimeout = %v：出站刻意不设超时，设了会允许把响应拦腰切断", srv.WriteTimeout)
	}
}

// 顺带钉住 guard 确实接到了返回的 *http.Server 上。guard_test.go 只直接调
// guard 函数，StartServer 里少写一层包装那边发现不了——而真正对外服务的
// 恰恰是这个 handler。
func TestStartServerWrapsHandlerWithGuard(t *testing.T) {
	srv, err := StartServer("127.0.0.1:0", nil, filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("StartServer: %v", err)
	}
	defer func() { _ = srv.Close() }()

	req := httptest.NewRequest(http.MethodPost, "/api/process-whitelist", nil)
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "http://evil.example")
	w := httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("跨源 POST 经 StartServer 的 handler = %d, want 403", w.Code)
	}
}
