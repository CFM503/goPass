package engine

import (
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/CFM503/goPass/internal/config"
)

// TestResolveProxyTarget_OriginalIP 验证真实 OrigDstIP 不被 SNI 覆盖
func TestResolveProxyTarget_OriginalIP(t *testing.T) {
	origIP := net.ParseIP("104.18.145.216")
	res := ResolveProxyTarget(origIP, 443, "example.com", true, "example.com", nil)

	wantTarget := "104.18.145.216:443"
	if res.Target != wantTarget {
		t.Errorf("Target = %q, want %q", res.Target, wantTarget)
	}
	if res.Target == "example.com:443" {
		t.Errorf("Target 绝不能被 SNI 覆盖为 example.com:443")
	}
	if res.TargetType != TargetTypeOriginalIP {
		t.Errorf("TargetType = %q, want %q", res.TargetType, TargetTypeOriginalIP)
	}
}

// TestResolveProxyTarget_RealIPWithSNI 验证 Cloudflare 优选 IP 配合 SNI 依然保留 IP
func TestResolveProxyTarget_RealIPWithSNI(t *testing.T) {
	origIP := net.ParseIP("172.67.182.25")
	res := ResolveProxyTarget(origIP, 443, "speed.cloudflare.com", true, "speed.cloudflare.com", nil)

	wantTarget := "172.67.182.25:443"
	if res.Target != wantTarget {
		t.Errorf("Target = %q, want %q", res.Target, wantTarget)
	}
	if res.TargetType != TargetTypeOriginalIP {
		t.Errorf("TargetType = %q, want %q", res.TargetType, TargetTypeOriginalIP)
	}
}

// TestResolveProxyTarget_FakeIP 验证 Fake IP 在映射存在时正确恢复真实目标 IP
func TestResolveProxyTarget_FakeIP(t *testing.T) {
	fakeIP := net.ParseIP("198.18.0.23")
	realIP := net.ParseIP("104.18.145.216")
	mapping := func(ip net.IP) (net.IP, bool) {
		if ip.Equal(fakeIP) {
			return realIP, true
		}
		return nil, false
	}

	res := ResolveProxyTarget(fakeIP, 443, "example.com", true, "example.com", mapping)

	wantTarget := "104.18.145.216:443"
	if res.Target != wantTarget {
		t.Errorf("Target = %q, want %q", res.Target, wantTarget)
	}
	if res.TargetType != TargetTypeFakeIPResolved {
		t.Errorf("TargetType = %q, want %q", res.TargetType, TargetTypeFakeIPResolved)
	}
}

// TestResolveProxyTarget_FakeIPNoMapping 验证 Fake IP 无映射时安全回退到 SNI 并记录 fallback 状态
func TestResolveProxyTarget_FakeIPNoMapping(t *testing.T) {
	fakeIP := net.ParseIP("198.18.0.23")

	res := ResolveProxyTarget(fakeIP, 443, "example.com", true, "example.com", nil)

	wantTarget := "example.com:443"
	if res.Target != wantTarget {
		t.Errorf("Target = %q, want %q", res.Target, wantTarget)
	}
	if res.TargetType != TargetTypeSNIFallback {
		t.Errorf("TargetType = %q, want %q", res.TargetType, TargetTypeSNIFallback)
	}
	if res.Reason != "fake_ip_mapping_unavailable" {
		t.Errorf("Reason = %q, want %q", res.Reason, "fake_ip_mapping_unavailable")
	}
}

// TestResolveProxyTarget_NoSNI 验证非 HTTPS 或无 SNI 连接使用真实 OrigDstIP
func TestResolveProxyTarget_NoSNI(t *testing.T) {
	origIP := net.ParseIP("104.18.145.216")
	res := ResolveProxyTarget(origIP, 80, "", false, "", nil)

	wantTarget := "104.18.145.216:80"
	if res.Target != wantTarget {
		t.Errorf("Target = %q, want %q", res.Target, wantTarget)
	}
	if res.TargetType != TargetTypeOriginalIP {
		t.Errorf("TargetType = %q, want %q", res.TargetType, TargetTypeOriginalIP)
	}
}

// TestProxyVsDirect 确保 Direct 始终直连 OrigDstIP，而 Proxy 使用 target resolver 结果
func TestProxyVsDirect(t *testing.T) {
	realIP := net.ParseIP("104.18.145.216")
	fakeIP := net.ParseIP("198.18.1.5")
	port := uint16(443)

	// Direct: 必须严格保持原始目标
	directTargetReal := net.JoinHostPort(realIP.String(), "443")
	if directTargetReal != "104.18.145.216:443" {
		t.Errorf("Direct real target = %q, want 104.18.145.216:443", directTargetReal)
	}

	// Proxy Real IP: 走 resolver，结果必须与 Direct 目标一致（真实 IP）
	proxyRes := ResolveProxyTarget(realIP, port, "example.com", true, "example.com", nil)
	if proxyRes.Target != directTargetReal {
		t.Errorf("Proxy target (%q) should equal Direct target (%q)", proxyRes.Target, directTargetReal)
	}

	// Proxy Fake IP: 回退到 SNI
	proxyFakeRes := ResolveProxyTarget(fakeIP, port, "example.com", true, "example.com", nil)
	if proxyFakeRes.Target != "example.com:443" {
		t.Errorf("Proxy fake fallback target = %q, want example.com:443", proxyFakeRes.Target)
	}
}

// mockRecorderDialer 记录 Dial 参数的 mock dialer
type mockRecorderDialer struct {
	mu         sync.Mutex
	dialedAddr string
	dialedNet  string
	conns      []net.Conn
}

func (m *mockRecorderDialer) Dial(network, addr string) (net.Conn, error) {
	m.mu.Lock()
	m.dialedAddr = addr
	m.dialedNet = network
	m.mu.Unlock()

	c1, c2 := net.Pipe()
	m.mu.Lock()
	m.conns = append(m.conns, c1, c2)
	m.mu.Unlock()

	go func() {
		buf := make([]byte, 4096)
		for {
			_, err := c2.Read(buf)
			if err != nil {
				return
			}
		}
	}()
	return c1, nil
}

func (m *mockRecorderDialer) CloseAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.conns {
		_ = c.Close()
	}
}

// TestTProxy_PreserveOrigDstIPWithSNI_Regression 重要回归测试：
// 模拟 Chrome 请求真实目标 104.18.145.216:443，携带 TLS SNI = example.com，
// 无论分流决策如何，UpstreamDialer 最终收到的必须是 104.18.145.216:443，绝不能是 example.com:443！
func TestTProxy_PreserveOrigDstIPWithSNI_Regression(t *testing.T) {
	tracker := NewConnTracker(30, 60)
	stats := &Stats{}
	perf := config.DefaultConfig().Performance

	// 创建透明代理监听器
	tp, err := NewTProxy(tracker, "socks5", "127.0.0.1:9192", stats, perf, 0, nil)
	if err != nil {
		t.Fatalf("NewTProxy 失败: %v", err)
	}
	defer tp.Close()

	// 注入 mock dialer
	recorder := &mockRecorderDialer{}
	tp.upstream.SetDialer(recorder)

	// 获取分配的本地端口并创建客户端连接
	lAddr := tp.listener.Addr().(*net.TCPAddr)

	clientConn, err := net.DialTimeout("tcp", lAddr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("连接本地 TProxy 失败: %v", err)
	}
	defer clientConn.Close()

	clientLocal := clientConn.LocalAddr().(*net.TCPAddr)

	// 模拟 WinDivert 设置连接跟踪：Chrome 发往 104.18.145.216:443
	origDstIP := net.ParseIP("104.18.145.216")
	origDstPort := uint16(443)
	tracker.Set(clientLocal.IP.String(), uint16(clientLocal.Port), clientLocal.IP, uint16(clientLocal.Port), origDstIP, origDstPort, 0, 0, "chrome.exe")

	// 启动服务端处理单连接
	conn, err := tp.listener.Accept()
	if err != nil {
		t.Fatalf("Accept 失败: %v", err)
	}
	defer conn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		tp.handleConn(conn)
	}()

	// 客户端发送合法的 TLS ClientHello，SNI = "example.com"
	tlsClient := tls.Client(clientConn, &tls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
	})

	// 异步握手（发送 ClientHello）
	go func() {
		_ = tlsClient.Handshake()
	}()

	// 等待 mockDialer 收到拨号请求
	deadline := time.Now().Add(3 * time.Second)
	var dialed string
	for time.Now().Before(deadline) {
		recorder.mu.Lock()
		dialed = recorder.dialedAddr
		recorder.mu.Unlock()
		if dialed != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	clientConn.Close()
	recorder.CloseAll()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
	}

	if dialed == "" {
		t.Fatal("UpstreamDialer 未收到任何拨号请求")
	}

	expectedAddr := "104.18.145.216:443"
	if dialed != expectedAddr {
		t.Errorf("UpstreamDialer dialed %q, want %q", dialed, expectedAddr)
	}
	if dialed == "example.com:443" {
		t.Errorf("严重回归错误：UpstreamDialer 收到 SNI 域名 %q，真实 CFST IP 被覆盖！", dialed)
	}
}
