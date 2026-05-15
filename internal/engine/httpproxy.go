package engine

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"

	"golang.org/x/net/proxy"
)

// HTTPProxyDialer 实现了 proxy.Dialer 接口，通过 HTTP CONNECT 方法连接上游
type HTTPProxyDialer struct {
	proxyAddr string
	auth      string // pre-encoded "Basic ..." header value
	forward   proxy.Dialer
}

// NewHTTPProxy 创建一个新的 HTTP CONNECT Dialer
func NewHTTPProxy(addr, username, password string, forward proxy.Dialer) (proxy.Dialer, error) {
	if forward == nil {
		forward = proxy.Direct
	}
	if !strings.Contains(addr, ":") {
		addr += ":80"
	}

	var auth string
	if username != "" {
		auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	}

	return &HTTPProxyDialer{
		proxyAddr: addr,
		auth:      auth,
		forward:   forward,
	}, nil
}

// Dial 建立 HTTP 隧道连接
func (d *HTTPProxyDialer) Dial(network, addr string) (c net.Conn, err error) {
	c, err = d.forward.Dial("tcp", d.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("无法连接到 HTTP 代理 %s: %w", d.proxyAddr, err)
	}

	// 手动构建 CONNECT 请求，避免 url.Parse + http.NewRequest 分配
	req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\nUser-Agent: GoPass/1.2.8\r\n"
	if d.auth != "" {
		req += "Proxy-Authorization: " + d.auth + "\r\n"
	}
	req += "\r\n"

	_, err = c.Write([]byte(req))
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("发送 CONNECT 请求失败: %w", err)
	}

	br := bufio.NewReader(c)
	resp, err := httpReadResponse(br)
	if err != nil {
		c.Close()
		return nil, err
	}
	if resp.statusCode != 200 {
		io.Copy(io.Discard, resp.body)
		c.Close()
		return nil, fmt.Errorf("代理服务器拒绝连接: %s", resp.status)
	}

	if br.Buffered() > 0 {
		return &BufferedConn{Conn: c, br: br}, nil
	}

	return c, nil
}

// minimalResponse 避免 http.ReadResponse 的完整解析开销
type minimalResponse struct {
	statusCode int
	status     string
	body       io.Reader
}

func httpReadResponse(br *bufio.Reader) (*minimalResponse, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, fmt.Errorf("空响应")
	}

	// Parse "HTTP/1.1 200 Connection established"
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("无效响应行: %s", line)
	}

	var code int
	fmt.Sscanf(parts[1], "%d", &code)

	status := line
	if len(parts) > 2 {
		status = parts[1] + " " + parts[2]
	}

	// 跳过剩余 headers
	for {
		hdr, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("读取 headers 失败: %w", err)
		}
		if strings.TrimSpace(hdr) == "" {
			break
		}
	}

	return &minimalResponse{
		statusCode: code,
		status:     status,
		body:       br,
	}, nil
}

// BufferedConn 包装了 net.Conn，优先从 bufio.Reader 中读取数据
type BufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *BufferedConn) Read(b []byte) (int, error) {
	return c.br.Read(b)
}
