package controller

import (
	"fmt"
	"io"
	"net"
	"time"
)

// ProbeResult 探测结果
type ProbeResult struct {
	RouteID   string
	Success   bool
	RTT       float64 // ms
	Err       error
	Timestamp time.Time
}

// Prober 轻量级低开销探测器
type Prober struct {
	timeout time.Duration
	sem     chan struct{} // 并发限制信号量
}

// NewProber 创建轻量健康探测器
func NewProber(timeout time.Duration, maxConcurrency int) *Prober {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if maxConcurrency <= 0 {
		maxConcurrency = 4
	}
	return &Prober{
		timeout: timeout,
		sem:     make(chan struct{}, maxConcurrency),
	}
}

// ProbeRoute 执行一次轻量级就绪与握手探测（极低 CPU / 网络开销）
func (p *Prober) ProbeRoute(r *Route) ProbeResult {
	p.sem <- struct{}{}
	defer func() { <-p.sem }()

	now := time.Now()
	res := ProbeResult{
		RouteID:   r.ID,
		Timestamp: now,
	}

	addr := fmt.Sprintf("%s:%d", r.Address, r.Port)
	start := time.Now()

	d := net.Dialer{Timeout: p.timeout}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		res.Success = false
		res.Err = err
		res.RTT = float64(p.timeout.Milliseconds())
		return res
	}
	defer conn.Close()

	// 协议轻量握手验证
	_ = conn.SetDeadline(time.Now().Add(p.timeout))

	if r.Protocol == "socks5" {
		// SOCKS5 握手认证协商 (0x05, 0x01, 0x00) -> 3 bytes
		req := []byte{0x05, 0x01, 0x00}
		if _, err := conn.Write(req); err != nil {
			res.Success = false
			res.Err = err
			return res
		}
		resp := make([]byte, 2)
		if _, err := io.ReadFull(conn, resp); err != nil || resp[0] != 0x05 || resp[1] != 0x00 {
			res.Success = false
			res.Err = fmt.Errorf("SOCKS5 握手失败: %v, resp: %v", err, resp)
			return res
		}
	} else if r.Protocol == "http" {
		// HTTP 代理简单嗅探
		req := []byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
		if _, err := conn.Write(req); err != nil {
			res.Success = false
			res.Err = err
			return res
		}
		resp := make([]byte, 12)
		if _, err := io.ReadAtLeast(conn, resp, 4); err != nil {
			res.Success = false
			res.Err = err
			return res
		}
	}

	rtt := float64(time.Since(start).Microseconds()) / 1000.0 // 毫秒浮点数
	res.Success = true
	res.RTT = rtt
	return res
}
