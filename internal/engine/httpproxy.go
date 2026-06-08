package engine

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/proxy"
)

// HTTPProxyDialer 实现了 proxy.Dialer 接口，通过 HTTP CONNECT 方法连接上游
type HTTPProxyDialer struct {
	proxyAddr string
	username  string
	password  string
	forward   proxy.Dialer
}

// NewHTTPProxy 创建一个新的 HTTP CONNECT Dialer
func NewHTTPProxy(addr, username, password string, forward proxy.Dialer) (proxy.Dialer, error) {
	if forward == nil {
		forward = proxy.Direct
	}
	// 确保地址包含端口
	if !strings.Contains(addr, ":") {
		addr += ":80"
	}
	return &HTTPProxyDialer{
		proxyAddr: addr,
		username:  username,
		password:  password,
		forward:   forward,
	}, nil
}

// Dial 建立 HTTP 隧道连接
func (d *HTTPProxyDialer) Dial(network, addr string) (c net.Conn, err error) {
	// 1. 连接到 HTTP 代理服务器
	c, err = d.forward.Dial("tcp", d.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("无法连接到 HTTP 代理 %s: %w", d.proxyAddr, err)
	}

	// 2. 发送 CONNECT 请求
	reqURL, err := url.Parse("http://" + addr)
	if err != nil {
		c.Close()
		return nil, err
	}
	reqURL.Scheme = ""

	req, err := http.NewRequest("CONNECT", reqURL.String(), nil)
	if err != nil {
		c.Close()
		return nil, err
	}
	req.Close = false

	// Basic Auth
	if d.username != "" {
		auth := d.username + ":" + d.password
		basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
		req.Header.Set("Proxy-Authorization", basicAuth)
	}
	req.Header.Set("User-Agent", "GoPass/1.4.5")

	err = req.Write(c)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("发送 CONNECT 请求失败: %w", err)
	}

	// 3. 读取响应
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("读取代理响应失败: %w", err)
	}
	if resp.StatusCode != 200 {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		c.Close()
		return nil, fmt.Errorf("代理服务器拒绝连接: %s", resp.Status)
	}

	// 注意：这里由于使用了 bufio.Reader 可能会多读数据，
	// 但 CONNECT 握手通常是以 \r\n\r\n 结尾，紧跟着的通常就是真实数据了。
	// 对于 TLS SNI 解析等场景，我们需要把缓冲里多读的数据交还出去。
	// 为了简单和兼容 Go 的 net.Conn，我们在外面直接用这个 net.Conn 读写，
	// bufio.Reader 里如果有多余数据，我们需要封装一个带 Buffer 的 Conn。

	if br.Buffered() > 0 {
		// 如果代理服务器在发送 200 OK 之后，立刻发送了对端的数据（极其罕见，通常是客户端先发 TLS ClientHello）
		// 我们必须保留这些数据
		return &BufferedConn{Conn: c, br: br}, nil
	}

	return c, nil
}

// BufferedConn 包装了 net.Conn，优先从 bufio.Reader 中读取数据
type BufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *BufferedConn) Read(b []byte) (int, error) {
	return c.br.Read(b) // br 内部优先读取 Buffer，然后调底层 Conn
}
