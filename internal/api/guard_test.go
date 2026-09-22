package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func serveGuard(t *testing.T, listenAddr, method, path, host, origin string) int {
	t.Helper()
	h := guard(listenAddr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(method, path, nil)
	if host != "" {
		req.Host = host
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code
}

func TestGuardBlocksCrossOriginWrite(t *testing.T) {
	// 网页 CSRF：Origin 是攻击者站点，Host 是本机 API
	for _, path := range []string{"/api/upstream", "/api/process-whitelist", "/api/performance"} {
		code := serveGuard(t, "127.0.0.1:8080", http.MethodPost, path,
			"127.0.0.1:8080", "http://evil.example")
		if code != http.StatusForbidden {
			t.Fatalf("%s cross-origin POST = %d, want 403", path, code)
		}
	}
}

func TestGuardAllowsLocalSameOrigin(t *testing.T) {
	cases := []struct{ name, host, origin string }{
		{"浏览器同源 POST", "127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"localhost 同源", "localhost:8080", "http://localhost:8080"},
		{"无 Origin（curl/本机客户端）", "127.0.0.1:8080", ""},
		{"IPv6 回环", "[::1]:8080", ""},
	}
	for _, c := range cases {
		if code := serveGuard(t, "127.0.0.1:8080", http.MethodPost, "/api/upstream", c.host, c.origin); code != http.StatusOK {
			t.Fatalf("%s: POST = %d, want 200", c.name, code)
		}
	}
}

func TestGuardBlocksDNSRebinding(t *testing.T) {
	// Rebinding 时 Origin 与 Host 同源（都是恶意域名），必须靠 Host 规则挡住
	code := serveGuard(t, "127.0.0.1:8080", http.MethodGet, "/api/status",
		"evil.example:8080", "http://evil.example:8080")
	if code != http.StatusForbidden {
		t.Fatalf("rebinding GET /api/status = %d, want 403", code)
	}
}

func TestGuardExplicitListenAddr(t *testing.T) {
	// 绑定到局域网地址：只接受该地址本身（回环始终放行）
	if code := serveGuard(t, "192.168.1.5:8080", http.MethodPost, "/api/upstream", "192.168.1.5:8080", ""); code != http.StatusOK {
		t.Fatalf("own LAN addr = %d, want 200", code)
	}
	if code := serveGuard(t, "192.168.1.5:8080", http.MethodPost, "/api/upstream", "10.0.0.9:8080", ""); code != http.StatusForbidden {
		t.Fatalf("other host = %d, want 403", code)
	}
}

func TestGuardWildcardListenAddr(t *testing.T) {
	// 0.0.0.0：允许用 IP 直接访问 UI，但拒绝域名 Host（rebinding）
	if code := serveGuard(t, "0.0.0.0:8080", http.MethodPost, "/api/upstream", "192.168.1.5:8080", ""); code != http.StatusOK {
		t.Fatalf("wildcard + IP host = %d, want 200", code)
	}
	if code := serveGuard(t, "0.0.0.0:8080", http.MethodPost, "/api/upstream", "evil.example:8080", ""); code != http.StatusForbidden {
		t.Fatalf("wildcard + domain host = %d, want 403", code)
	}
}

func TestGuardSkipsStaticAssets(t *testing.T) {
	for _, path := range []string{"/", "/css/style.css", "/js/app.js", "/index.html"} {
		if code := serveGuard(t, "127.0.0.1:8080", http.MethodGet, path, "evil.example:8080", "http://evil.example"); code != http.StatusOK {
			t.Fatalf("static %s = %d, want 200", path, code)
		}
	}
}
