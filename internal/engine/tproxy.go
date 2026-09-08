package engine

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CFM503/goPass/internal/config"
)

// bufferPool holds 1MB buffers; handleConn slices them to the configured size.
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 1024*1024) // 1MB max
	},
}

// readTLSClientHello reads and extracts the SNI from a TLS ClientHello.
// CRITICAL FIX: Returns ALL bytes read from conn (readBuf) regardless of whether SNI extraction
// succeeded or failed. This guarantees ZERO DATA LOSS so the TLS handshake is never corrupted.
func readTLSClientHello(conn net.Conn) (readBuf []byte, sni string, err error) {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	var buf bytes.Buffer

	// Step 1: Read TLS Record header (5 bytes)
	header := make([]byte, 5)
	n, errRead := io.ReadFull(conn, header)
	if n > 0 {
		buf.Write(header[:n])
	}
	if errRead != nil || n < 5 {
		return buf.Bytes(), "", fmt.Errorf("read header error: %w", errRead)
	}

	if header[0] != 22 {
		return buf.Bytes(), "", fmt.Errorf("not TLS handshake: type=%d", header[0])
	}

	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen <= 0 || recordLen > 16384 {
		return buf.Bytes(), "", fmt.Errorf("invalid TLS record length: %d", recordLen)
	}

	// Step 2: Read full record body (dynamic alloc for Kyber large records)
	body := make([]byte, recordLen)
	nBody, errBody := io.ReadFull(conn, body)
	if nBody > 0 {
		buf.Write(body[:nBody])
	}
	if errBody != nil {
		return buf.Bytes(), "", fmt.Errorf("read record body error: %w", errBody)
	}

	allData := buf.Bytes()
	foundSNI, sniErr := ExtractSNI(allData)
	return allData, foundSNI, sniErr
}

// TProxy 是本地透明代理 TCP 监听器
// 它监听 127.0.0.1:7893，接收 WinDivert 劫持过来的连接
// 然后查出原始目标，通过 SOCKS5/HTTP 代理转发
type TProxy struct {
	listener net.Listener
	tracker  *ConnTracker

	// 上游代理拨号器（热切换）
	upstream *UpstreamDialer

	// 分流路由器（绝对分流）；为 nil 时保持原有「全部走代理」行为
	router *Router

	// [v1.2.1] Hot-reloadable performance settings
	bufferSize      int
	tcpNoDelay      bool
	tcpSocketBuffer int
	bidirectWait    bool
	tcpKeepAlive    bool
	keepAlivePeriod int
	tcpLinger       int
	perfMu          sync.RWMutex

	stats *Stats
}

// NewTProxy 创建本地代理监听器
func NewTProxy(tracker *ConnTracker, proxyType, proxyAddr string, stats *Stats, perf config.PerformanceConfig, tproxyPort int, router *Router) (*TProxy, error) {
	// [v1.2.6 Config] 移除魔数 7893，使用系统配置的 TProxyPort
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", tproxyPort))
	if err != nil {
		return nil, fmt.Errorf("TProxy listen failed: %w", err)
	}
	log.Printf("[TProxy] 本地透明代理监听: 0.0.0.0:%d", tproxyPort)
	return &TProxy{
		listener:        ln,
		tracker:         tracker,
		upstream:        NewUpstreamDialer(proxyType, proxyAddr),
		router:          router,
		bufferSize:      perf.BufferSize,
		tcpNoDelay:      perf.TCPNoDelay,
		tcpSocketBuffer: perf.TCPSocketBuffer,
		bidirectWait:    perf.BidirectWait,
		tcpKeepAlive:    perf.TCPKeepAlive,
		keepAlivePeriod: perf.KeepAlivePeriod,
		tcpLinger:       perf.TCPLinger,
		stats:           stats,
	}, nil
}

// UpdatePerformance 热更新性能参数（无需重启，立即对新连接生效）
func (tp *TProxy) UpdatePerformance(perf config.PerformanceConfig) {
	tp.perfMu.Lock()
	defer tp.perfMu.Unlock()
	tp.bufferSize = perf.BufferSize
	tp.tcpNoDelay = perf.TCPNoDelay
	tp.tcpSocketBuffer = perf.TCPSocketBuffer
	tp.bidirectWait = perf.BidirectWait
	tp.tcpKeepAlive = perf.TCPKeepAlive
	tp.keepAlivePeriod = perf.KeepAlivePeriod
	tp.tcpLinger = perf.TCPLinger
	log.Printf("[TProxy] 🚀 性能参数热更新: Buffer=%dB, NoDelay=%v, SocketBuf=%dB, BidirectWait=%v, KeepAlive=%v/%ds, Linger=%d",
		perf.BufferSize, perf.TCPNoDelay, perf.TCPSocketBuffer, perf.BidirectWait, perf.TCPKeepAlive, perf.KeepAlivePeriod, perf.TCPLinger)
}

// UpdateUpstream 热更上游代理配置
func (tp *TProxy) UpdateUpstream(pType, pAddr string) {
	tp.upstream.Update(pType, pAddr)
	log.Printf("[TProxy] 上游代理已热切换为: %s -> %s", pType, pAddr)
}

// Accept 开始接受连接（阻塞）
func (tp *TProxy) Accept() {
	var tempDelay time.Duration
	for {
		conn, err := tp.listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				log.Printf("[TProxy] Accept 临时错误: %v, 重试等待 %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			log.Printf("[TProxy] 致命 Accept 错误，退出监听: %v", err)
			return
		}
		tempDelay = 0
		go tp.handleConn(conn)
	}
}

func (tp *TProxy) handleConn(conn net.Conn) {
	defer conn.Close()

	// [v1.2.1] Snapshot current performance settings (hot-reloadable)
	tp.perfMu.RLock()
	bufSize := tp.bufferSize
	noDelay := tp.tcpNoDelay
	sockBuf := tp.tcpSocketBuffer
	biWait := tp.bidirectWait
	keepAlive := tp.tcpKeepAlive
	keepAlivePeriod := tp.keepAlivePeriod
	tcpLinger := tp.tcpLinger
	tp.perfMu.RUnlock()

	// Clamp buffer size to [4096, 1MB]
	if bufSize < 4096 {
		bufSize = 4096
	}
	if bufSize > 1024*1024 {
		bufSize = 1024 * 1024
	}

	tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}

	srcIP := tcpAddr.IP.String()
	srcPort := uint16(tcpAddr.Port)

	target, found := tp.tracker.Get(srcIP, srcPort)
	if !found {
		return
	}
	defer tp.tracker.Delete(srcIP, srcPort)

	targetAddr := fmt.Sprintf("%s:%d", target.OrigDstIP.String(), target.OrigDstPort)

	// SNI Sniffing (Zero-Data-Loss)
	var peekBuf []byte
	isHTTPS := target.OrigDstPort == 443
	domain := ""

	if isHTTPS {
		var sni string
		var err error
		peekBuf, sni, err = readTLSClientHello(conn)
		if err == nil && sni != "" {
			domain = sni
			targetAddr = fmt.Sprintf("%s:%d", sni, target.OrigDstPort)
		}
	}

	// =========================================================================
	// 绝对分流：在 SNI 嗅探之后、真正转发之前做出 直连/代理 决策
	// =========================================================================
	policy := "PROXY"
	reason := "whitelist"
	var remote net.Conn
	var err error

	if tp.router != nil && tp.router.SplitEnabled() {
		res := tp.router.Decide(domain, target.OrigDstIP, target.ProcessName)
		reason = res.Reason
		if res.Decision == DecisionDirect {
			// 直连：直接拨原始目标 IP（不做本地 DNS 解析，避免任何 DNS 泄漏）
			directAddr := net.JoinHostPort(target.OrigDstIP.String(), strconv.Itoa(int(target.OrigDstPort)))
			remote, err = net.DialTimeout("tcp", directAddr, 10*time.Second)
			policy = "DIRECT"
			targetAddr = directAddr
		} else {
			// 代理：SNI 域名交给上游代理做远端 DNS 解析（零本地 DNS 泄漏）
			if domain != "" {
				targetAddr = fmt.Sprintf("%s:%d", domain, target.OrigDstPort)
			} else {
				targetAddr = fmt.Sprintf("%s:%d", target.OrigDstIP.String(), target.OrigDstPort)
			}
			remote, err = tp.upstream.Dial("tcp", targetAddr)
		}
	} else {
		// 原有逻辑：一律走上游代理
		dialer, errDialer := tp.upstream.Dialer()
		if errDialer != nil {
			log.Printf("[TProxy] 代理 Dialer 创建失败: %v", errDialer)
			return
		}
		remote, err = dialer.Dial("tcp", targetAddr)
	}

	// 关键：任何失败都直接关闭连接，绝不回退直连（零中国痕迹的核心保障）
	if err != nil {
		log.Printf("[TProxy] 连接失败 %s (policy=%s reason=%s): %v", targetAddr, policy, reason, err)
		return
	}
	defer remote.Close()

	// Dynamic TCP tuning
	tuneConn := func(c net.Conn) {
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetNoDelay(noDelay)
			tc.SetKeepAlive(keepAlive)
			if keepAlivePeriod > 0 {
				tc.SetKeepAlivePeriod(time.Duration(keepAlivePeriod) * time.Second)
			}
			if tcpLinger >= 0 {
				tc.SetLinger(tcpLinger)
			}
			// Only override socket buffer if > 0. If <= 0, retain Windows OS Auto-Tuning!
			if sockBuf > 0 {
				tc.SetReadBuffer(sockBuf)
				tc.SetWriteBuffer(sockBuf)
			}
		}
	}
	tuneConn(conn)
	tuneConn(remote)

	// Write buffered ClientHello bytes to remote
	if len(peekBuf) > 0 {
		_, err := remote.Write(peekBuf)
		if err != nil {
			log.Printf("[TProxy] 发送缓存包失败: %v", err)
			return
		}
	}

	if tp.stats != nil {
		connInfo := map[string]interface{}{
			"id":      fmt.Sprintf("%s:%d", srcIP, srcPort),
			"process": target.ProcessName,
			"target":  targetAddr,
			"host":    target.OrigDstIP.String(),
			"policy":  policy,
			"reason":  reason,
		}
		tp.stats.AddActiveConn(connInfo)
	}

	defer func() {
		if tp.stats != nil {
			tp.stats.RemoveActiveConn(fmt.Sprintf("%s:%d", srcIP, srcPort))
		}
	}()

	done := make(chan struct{}, 2)

	go func() {
		buf := bufferPool.Get().([]byte)
		defer bufferPool.Put(buf)
		if cap(buf) < bufSize {
			buf = make([]byte, bufSize)
		}
		copyBuf := buf[:bufSize]
		for {
			n, err := remote.Read(copyBuf)
			if n > 0 {
				if tp.stats != nil {
					atomic.AddInt64(&tp.stats.RxBytes, int64(n))
				}
				if _, errWrite := conn.Write(copyBuf[:n]); errWrite != nil {
					if tc, ok := conn.(*net.TCPConn); ok {
						tc.CloseWrite()
					}
					break
				}
			}
			if err != nil {
				if tc, ok := conn.(*net.TCPConn); ok {
					tc.CloseWrite()
				}
				break
			}
		}
		done <- struct{}{}
	}()

	go func() {
		buf := bufferPool.Get().([]byte)
		defer bufferPool.Put(buf)
		if cap(buf) < bufSize {
			buf = make([]byte, bufSize)
		}
		copyBuf := buf[:bufSize]
		for {
			n, err := conn.Read(copyBuf)
			if n > 0 {
				if tp.stats != nil {
					atomic.AddInt64(&tp.stats.TxBytes, int64(n))
				}
				if _, errWrite := remote.Write(copyBuf[:n]); errWrite != nil {
					if tc, ok := remote.(*net.TCPConn); ok {
						tc.CloseWrite()
					}
					break
				}
			}
			if err != nil {
				if tc, ok := remote.(*net.TCPConn); ok {
					tc.CloseWrite()
				}
				break
			}
		}
		done <- struct{}{}
	}()

	<-done
	if biWait {
		<-done
	}
}

// Close 关闭监听器
func (tp *TProxy) Close() error {
	return tp.listener.Close()
}
