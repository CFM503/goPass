package engine

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// startMockEchoServer 启动本地回显服务
func startMockEchoServer(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 1024)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					resp := fmt.Sprintf("[Echo]%s", string(buf[:n]))
					if _, errWrite := conn.Write([]byte(resp)); errWrite != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln
}

// startMockSOCKS5Server 启动一个完全本地的轻量级 SOCKS5 Mock 代理服务器
func startMockSOCKS5Server(t *testing.T, tag string) (net.Listener, *int32) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var connCount int32

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&connCount, 1)
			go handleMockSOCKS5(c, tag)
		}
	}()
	return ln, &connCount
}

func handleMockSOCKS5(c net.Conn, tag string) {
	defer c.Close()
	// 1. SOCKS5 协商握手
	header := make([]byte, 2)
	if _, err := io.ReadFull(c, header); err != nil || header[0] != 0x05 {
		return
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	// 回复无需认证: [0x05, 0x00]
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. CONNECT 请求: [0x05, CMD=0x01, RSV=0x00, ATYP, ADDR, PORT]
	reqHead := make([]byte, 4)
	if _, err := io.ReadFull(c, reqHead); err != nil || reqHead[0] != 0x05 || reqHead[1] != 0x01 {
		return
	}
	var destAddr string
	switch reqHead[3] {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(c, ip); err != nil {
			return
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(c, portBytes); err != nil {
			return
		}
		port := int(portBytes[0])<<8 | int(portBytes[1])
		destAddr = net.JoinHostPort(net.IP(ip).String(), strconv.Itoa(port))
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(c, lenBuf); err != nil {
			return
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(c, domain); err != nil {
			return
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(c, portBytes); err != nil {
			return
		}
		port := int(portBytes[0])<<8 | int(portBytes[1])
		destAddr = net.JoinHostPort(string(domain), strconv.Itoa(port))
	default:
		return
	}

	targetConn, err := net.DialTimeout("tcp", destAddr, 2*time.Second)
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer targetConn.Close()

	// 回复成功: [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// 双向转发
	errCh := make(chan error, 2)
	go func() {
		_, errCopy := io.Copy(targetConn, c)
		errCh <- errCopy
	}()
	go func() {
		_, errCopy := io.Copy(c, targetConn)
		errCh <- errCopy
	}()
	<-errCh
}

// TestZeroDowntimeUpstreamSwitch 验证旧连接在线路热切时不中断，新连接走新线路
func TestZeroDowntimeUpstreamSwitch(t *testing.T) {
	echoLn := startMockEchoServer(t)
	defer echoLn.Close()
	echoAddr := echoLn.Addr().String()

	lnA, countA := startMockSOCKS5Server(t, "A")
	defer lnA.Close()
	addrA := lnA.Addr().String()

	lnB, countB := startMockSOCKS5Server(t, "B")
	defer lnB.Close()
	addrB := lnB.Addr().String()

	// 1. 初始化 UpstreamDialer 指向 SOCKS5 代理 A
	u := NewUpstreamDialer("socks5", addrA, "", "")

	// 2. 通过 UpstreamDialer 建立长连接 Connection 1 到目标回显服务器
	conn1, err := u.Dial("tcp", echoAddr)
	if err != nil {
		t.Fatalf("u.Dial via A failed: %v", err)
	}
	defer conn1.Close()

	// 验证 Connection 1 确实经过代理 A
	if atomic.LoadInt32(countA) != 1 {
		t.Fatalf("expected 1 connection on A, got %d", atomic.LoadInt32(countA))
	}

	// 验证 Connection 1 双向收发正常
	if _, err := conn1.Write([]byte("ping1")); err != nil {
		t.Fatalf("conn1 write failed: %v", err)
	}
	buf := make([]byte, 64)
	n, err := conn1.Read(buf)
	if err != nil || string(buf[:n]) != "[Echo]ping1" {
		t.Fatalf("conn1 expected [Echo]ping1, got %s (err: %v)", string(buf[:n]), err)
	}

	// 3. 执行热切换：UpstreamDialer 热更新为 SOCKS5 代理 B
	u.Update("socks5", addrB, "", "")
	_, currAddr := u.Current()
	if currAddr != addrB {
		t.Fatalf("expected current upstream %s, got %s", addrB, currAddr)
	}

	// 4. 【核心断言 1】：旧连接 Connection 1 必须完好无损，继续保持并能双向传输！
	if _, err := conn1.Write([]byte("ping_after_update")); err != nil {
		t.Fatalf("old connection 1 must not be interrupted by Update(): %v", err)
	}
	n, err = conn1.Read(buf)
	if err != nil || string(buf[:n]) != "[Echo]ping_after_update" {
		t.Fatalf("old connection 1 read error: got %s (err: %v)", string(buf[:n]), err)
	}
	// 确认代理 A 仍保持该连接，代理 B 尚未收到新连接
	if atomic.LoadInt32(countB) != 0 {
		t.Fatalf("proxy B should not have connections yet, got %d", atomic.LoadInt32(countB))
	}

	// 5. 【核心断言 2】：新建连接 Connection 2 必须无缝接入新上游代理 B
	conn2, err := u.Dial("tcp", echoAddr)
	if err != nil {
		t.Fatalf("u.Dial via B failed: %v", err)
	}
	defer conn2.Close()

	if atomic.LoadInt32(countB) != 1 {
		t.Fatalf("expected 1 connection on B, got %d", atomic.LoadInt32(countB))
	}

	if _, err := conn2.Write([]byte("ping2")); err != nil {
		t.Fatalf("conn2 write failed: %v", err)
	}
	n, err = conn2.Read(buf)
	if err != nil || string(buf[:n]) != "[Echo]ping2" {
		t.Fatalf("conn2 expected [Echo]ping2, got %s (err: %v)", string(buf[:n]), err)
	}

	// 6. 再次验证旧连接 Connection 1 依然持续工作正常 (多次持续传输)
	if _, err := conn1.Write([]byte("ping_third")); err != nil {
		t.Fatalf("old connection 1 continuous write failed: %v", err)
	}
	n, err = conn1.Read(buf)
	if err != nil || string(buf[:n]) != "[Echo]ping_third" {
		t.Fatalf("old connection 1 continuous read failed: got %s (err: %v)", string(buf[:n]), err)
	}
}

// socks5AuthResult 记录一次 SOCKS5 认证协商的结果。
type socks5AuthResult struct {
	offered bool   // 客户端是否提供了 0x02（用户名密码）方法
	user    string // 客户端实际发送的用户名
	pass    string // 客户端实际发送的密码
	ok      bool   // 凭据与预期一致且服务器已放行
}

// startMockSOCKS5AuthServer 启动一个强制要求用户名密码认证的 SOCKS5 服务。
// 关键在于必须回 0x02 而不是 0x00：x/net/proxy 在配了凭据时会同时提供
// 0x00 和 0x02 两种方法，若服务器回 0x00，客户端压根不会发送凭据，
// 认证路径就永远走不到，测试也就验不到东西。
func startMockSOCKS5AuthServer(t *testing.T, wantUser, wantPass string) (net.Listener, <-chan socks5AuthResult) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan socks5AuthResult, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleMockSOCKS5Auth(c, wantUser, wantPass, results)
		}
	}()
	return ln, results
}

func handleMockSOCKS5Auth(c net.Conn, wantUser, wantPass string, results chan<- socks5AuthResult) {
	defer c.Close()
	res := socks5AuthResult{}
	fail := func() { results <- res }

	// 1. 协商方法
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil || head[0] != 0x05 {
		fail()
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		fail()
		return
	}
	for _, m := range methods {
		if m == 0x02 {
			res.offered = true
		}
	}
	if !res.offered {
		// 客户端没带凭据 → 回 0xFF 拒绝，用来证明凭据确实是发出去的。
		_, _ = c.Write([]byte{0x05, 0xff})
		fail()
		return
	}
	if _, err := c.Write([]byte{0x05, 0x02}); err != nil {
		fail()
		return
	}

	// 2. RFC 1929 用户名密码子协商
	authHead := make([]byte, 2)
	if _, err := io.ReadFull(c, authHead); err != nil || authHead[0] != 0x01 {
		fail()
		return
	}
	ul := make([]byte, authHead[1])
	if _, err := io.ReadFull(c, ul); err != nil {
		fail()
		return
	}
	pl := make([]byte, 1)
	if _, err := io.ReadFull(c, pl); err != nil {
		fail()
		return
	}
	password := make([]byte, pl[0])
	if _, err := io.ReadFull(c, password); err != nil {
		fail()
		return
	}
	res.user, res.pass = string(ul), string(password)
	if res.user != wantUser || res.pass != wantPass {
		_, _ = c.Write([]byte{0x01, 0x01})
		fail()
		return
	}
	if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
		fail()
		return
	}
	res.ok = true
	fail()

	// 3. CONNECT：本测试只关心认证，回成功即可，不需要真的转发到目标。
	reqHead := make([]byte, 4)
	if _, err := io.ReadFull(c, reqHead); err != nil {
		return
	}
	var addrLen int
	switch reqHead[3] {
	case 0x01:
		addrLen = 4
	case 0x04:
		addrLen = 16
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(c, lb); err != nil {
			return
		}
		if _, err := io.ReadFull(c, make([]byte, lb[0])); err != nil {
			return
		}
	default:
		return
	}
	if _, err := io.ReadFull(c, make([]byte, addrLen)); err != nil {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	// 连接保持到对端关闭，避免客户端在收到回应前读到 EOF。
	buf := make([]byte, 1024)
	for {
		if _, err := c.Read(buf); err != nil {
			return
		}
	}
}

// TestUpstreamCacheKeyIncludesCredentials 保证凭据参与 dialer 缓存键。
// 否则改密码后仍复用旧 dialer，新凭据永远不生效——表现就是"配了认证却没用"。
func TestUpstreamCacheKeyIncludesCredentials(t *testing.T) {
	base := upstreamCacheKey("socks5", "127.0.0.1:1080", "alice", "pw1")
	cases := []struct {
		name string
		key  string
	}{
		{"密码变化", upstreamCacheKey("socks5", "127.0.0.1:1080", "alice", "pw2")},
		{"用户名变化", upstreamCacheKey("socks5", "127.0.0.1:1080", "bob", "pw1")},
		{"类型变化", upstreamCacheKey("http", "127.0.0.1:1080", "alice", "pw1")},
		{"地址变化", upstreamCacheKey("socks5", "127.0.0.1:1081", "alice", "pw1")},
		{"地址与凭据不串位", upstreamCacheKey("socks5", "h:1u", "", "pw1")},
	}
	for _, c := range cases {
		if base == c.key {
			t.Errorf("%s：缓存键没有变化，会复用旧 dialer", c.name)
		}
	}
}

// TestUpstreamDialerCacheInvalidatedByPasswordChange 验证改凭据后确实重建 dialer。
func TestUpstreamDialerCacheInvalidatedByPasswordChange(t *testing.T) {
	u := NewUpstreamDialer("socks5", "127.0.0.1:1080", "alice", "pw1")
	d1, err := u.Dialer()
	if err != nil {
		t.Fatalf("Dialer(): %v", err)
	}
	d2, err := u.Dialer()
	if err != nil {
		t.Fatalf("Dialer() 再次调用: %v", err)
	}
	if d1 != d2 {
		t.Fatal("相同配置应复用缓存 dialer")
	}

	u.Update("socks5", "127.0.0.1:1080", "alice", "pw2")
	if u.username != "alice" || u.password != "pw2" {
		t.Fatalf("Update 没有保存凭据: user=%q pass=%q", u.username, u.password)
	}
	d3, err := u.Dialer()
	if err != nil {
		t.Fatalf("Dialer() 改密码后: %v", err)
	}
	if d3 == d1 {
		t.Fatal("改密码后仍复用旧 dialer，新凭据不会生效")
	}
	// 直接钉住缓存键：Update() 会无条件清空缓存，所以仅凭 d3!=d1
	// 不足以说明键里带了凭据。用 Contains 而不是拿 upstreamCacheKey
	// 拼期望值——否则该函数本身被改坏时，两边会一起错、断言永远为真。
	if !strings.Contains(u.cachedKey, "pw2") {
		t.Fatalf("缓存键未包含新密码: %q", u.cachedKey)
	}
}

// TestUpstreamSendsConfiguredCredentials 证明配置里的上游账号密码真的被发出去了。
// 修复前 upstream.go 硬编码 ""/nil，这里配了凭据也会被忽略。
func TestUpstreamSendsConfiguredCredentials(t *testing.T) {
	ln, results := startMockSOCKS5AuthServer(t, "alice", "s3cret")
	defer ln.Close()

	u := NewUpstreamDialer("socks5", ln.Addr().String(), "alice", "s3cret")
	conn, err := u.Dial("tcp", "127.0.0.1:1")
	if err != nil {
		t.Fatalf("带凭据的拨号失败: %v", err)
	}
	conn.Close()

	select {
	case res := <-results:
		if !res.offered {
			t.Fatal("客户端没有提供 0x02 认证方法")
		}
		if !res.ok {
			t.Fatalf("服务器拒绝了凭据: user=%q pass=%q", res.user, res.pass)
		}
		if res.user != "alice" || res.pass != "s3cret" {
			t.Fatalf("凭据不符: user=%q pass=%q", res.user, res.pass)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("超时未收到认证结果")
	}
}

// TestUpstreamWithoutCredentialsFailsAgainstAuthRequiredServer 是反向对照：
// 不配凭据时，强制认证的服务器必须拨号失败。这说明上一个测试的成功
// 确实来自发出的凭据，而不是服务器无条件放行。
func TestUpstreamWithoutCredentialsFailsAgainstAuthRequiredServer(t *testing.T) {
	ln, results := startMockSOCKS5AuthServer(t, "alice", "s3cret")
	defer ln.Close()

	u := NewUpstreamDialer("socks5", ln.Addr().String(), "", "")
	conn, err := u.Dial("tcp", "127.0.0.1:1")
	if err == nil {
		conn.Close()
		t.Fatal("未配凭据却拨通了强制认证的服务器")
	}

	select {
	case res := <-results:
		if res.offered {
			t.Fatal("未配凭据时客户端不应提供 0x02")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("超时未收到认证结果")
	}
}

// startMockHTTPProxyAuth 起一个要求 Proxy-Authorization 的 HTTP 代理：
// 用裸 TCP + http.ReadRequest 读一条 CONNECT，凭据不符回 407。
// 返回通道里是客户端实际发出的 Proxy-Authorization 头。
func startMockHTTPProxyAuth(t *testing.T, wantAuth string) (net.Listener, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					got <- ""
					return
				}
				auth := req.Header.Get("Proxy-Authorization")
				got <- auth
				if auth != wantAuth {
					_, _ = c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n"))
					return
				}
				if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n")); err != nil {
					return
				}
				buf := make([]byte, 256)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln, got
}

// TestUpstreamHTTPProxySendsProxyAuthorization 覆盖 HTTP 上游这条路径：
// 修复前调用方硬编码 NewHTTPProxy(pAddr,"","")，配了认证也发不出去，
// 上游回 407 就直接断网且没有任何提示。
func TestUpstreamHTTPProxySendsProxyAuthorization(t *testing.T) {
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
	ln, got := startMockHTTPProxyAuth(t, want)
	defer ln.Close()

	u := NewUpstreamDialer("http", ln.Addr().String(), "alice", "s3cret")
	conn, err := u.Dial("tcp", "127.0.0.1:1")
	if err != nil {
		t.Fatalf("HTTP 上游带凭据拨号失败: %v", err)
	}
	conn.Close()

	select {
	case auth := <-got:
		if auth != want {
			t.Fatalf("Proxy-Authorization 不符: got %q, want %q", auth, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("超时未收到代理请求")
	}
}

// TestUpstreamHTTPProxyWithoutCredentialsRejected 是反向对照：
// 不配凭据时上游回 407，拨号必须失败——说明上一个测试的成功
// 确实来自发出的 Authorization，而不是代理无条件放行。
func TestUpstreamHTTPProxyWithoutCredentialsRejected(t *testing.T) {
	ln, got := startMockHTTPProxyAuth(t, "Basic YWxpY2U6czNjcmV0")
	defer ln.Close()

	u := NewUpstreamDialer("http", ln.Addr().String(), "", "")
	conn, err := u.Dial("tcp", "127.0.0.1:1")
	if err == nil {
		conn.Close()
		t.Fatal("未配凭据却拨通了要求认证的 HTTP 代理")
	}

	select {
	case auth := <-got:
		if auth != "" {
			t.Fatalf("未配凭据时不应发送 Proxy-Authorization, got %q", auth)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("超时未收到代理请求")
	}
}
