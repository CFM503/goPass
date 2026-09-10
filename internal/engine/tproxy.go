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

// bufferPool holds 2MB buffers; handleConn slices them to the configured size.
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 2*1024*1024) // 2MB max
	},
}

const (
	TargetTypeOriginalIP     = "original_ip"
	TargetTypeFakeIPResolved = "fake_ip_resolved_ip"
	TargetTypeSNIFallback    = "sni_fallback"
)

// ResolveProxyTargetResult 包含代理目标解析结果
type ResolveProxyTargetResult struct {
	Target     string // 目标地址 (host:port)
	TargetType string // original_ip | fake_ip_resolved_ip | sni_fallback
	Reason     string // 仅在 fallback 或异常时说明原因
}

// isFakeIP 判断是否属于 Fake-IP / Benchmark 保留地址段 (198.18.0.0/15)
func isFakeIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return v4[0] == 198 && (v4[1] == 18 || v4[1] == 19)
}

// isValidRealIP 判断是否为有效的非 Fake 真实目标 IP
func isValidRealIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() {
		return false
	}
	if isFakeIP(ip) {
		return false
	}
	return true
}

// ResolveProxyTarget 统一解析代理上游 TCP 连接目标：
// 解耦 TCP 连接目标 IP 与 TLS SNI，确保优先连接真实 OrigDstIP。
func ResolveProxyTarget(origDstIP net.IP, origDstPort uint16, sni string, isHTTPS bool, domain string, fakeResolver func(net.IP) (net.IP, bool)) ResolveProxyTargetResult {
	portStr := strconv.Itoa(int(origDstPort))
	effectiveDomain := sni
	if effectiveDomain == "" {
		effectiveDomain = domain
	}

	var res ResolveProxyTargetResult

	if isValidRealIP(origDstIP) {
		res = ResolveProxyTargetResult{
			Target:     net.JoinHostPort(origDstIP.String(), portStr),
			TargetType: TargetTypeOriginalIP,
		}
	} else if isFakeIP(origDstIP) {
		if fakeResolver != nil {
			if realIP, ok := fakeResolver(origDstIP); ok && isValidRealIP(realIP) {
				res = ResolveProxyTargetResult{
					Target:     net.JoinHostPort(realIP.String(), portStr),
					TargetType: TargetTypeFakeIPResolved,
				}
			}
		}

		if res.Target == "" {
			if effectiveDomain != "" {
				res = ResolveProxyTargetResult{
					Target:     net.JoinHostPort(effectiveDomain, portStr),
					TargetType: TargetTypeSNIFallback,
					Reason:     "fake_ip_mapping_unavailable",
				}
			} else {
				res = ResolveProxyTargetResult{
					Target:     net.JoinHostPort(origDstIP.String(), portStr),
					TargetType: TargetTypeFakeIPResolved,
					Reason:     "fake_ip_no_domain_available",
				}
			}
		}
	} else {
		if effectiveDomain != "" {
			res = ResolveProxyTargetResult{
				Target:     net.JoinHostPort(effectiveDomain, portStr),
				TargetType: TargetTypeSNIFallback,
				Reason:     "unspecified_ip",
			}
		} else {
			ipStr := "0.0.0.0"
			if origDstIP != nil {
				ipStr = origDstIP.String()
			}
			res = ResolveProxyTargetResult{
				Target:     net.JoinHostPort(ipStr, portStr),
				TargetType: TargetTypeOriginalIP,
			}
		}
	}

	logProxyTarget(origDstIP, origDstPort, effectiveDomain, res)
	return res
}

func logProxyTarget(origDstIP net.IP, origDstPort uint16, sni string, res ResolveProxyTargetResult) {
	origDst := "nil"
	if origDstIP != nil {
		origDst = net.JoinHostPort(origDstIP.String(), strconv.Itoa(int(origDstPort)))
	}
	sniStr := sni
	if sniStr == "" {
		sniStr = "<none>"
	}
	if res.Reason != "" {
		log.Printf("[PROXY TARGET] orig_dst=%s sni=%s target=%s type=%s reason=%s", origDst, sniStr, res.Target, res.TargetType, res.Reason)
	} else {
		log.Printf("[PROXY TARGET] orig_dst=%s sni=%s target=%s type=%s", origDst, sniStr, res.Target, res.TargetType)
	}
}

func readTLSClientHello(conn net.Conn) (readBuf []byte, sni string, err error) {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	var buf bytes.Buffer
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

type TProxy struct {
	listener net.Listener
	tracker  *ConnTracker
	upstream *UpstreamDialer
	router   *Router
	fakeIPResolver func(net.IP) (net.IP, bool)
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

func NewTProxy(tracker *ConnTracker, proxyType, proxyAddr string, stats *Stats, perf config.PerformanceConfig, tproxyPort int, router *Router) (*TProxy, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", tproxyPort))
	if err != nil {
		return nil, fmt.Errorf("TProxy listen failed: %w", err)
	}
	log.Printf("[TProxy] 本地透明代理监听: 0.0.0.0:%d", tproxyPort)
	return &TProxy{
		listener: ln,
		tracker: tracker,
		upstream: NewUpstreamDialer(proxyType, proxyAddr),
		router: router,
		bufferSize: perf.BufferSize,
		tcpNoDelay: perf.TCPNoDelay,
		tcpSocketBuffer: perf.TCPSocketBuffer,
		bidirectWait: perf.BidirectWait,
		tcpKeepAlive: perf.TCPKeepAlive,
		keepAlivePeriod: perf.KeepAlivePeriod,
		tcpLinger: perf.TCPLinger,
		stats: stats,
	}, nil
}

func (tp *TProxy) UpdatePerformance(perf config.PerformanceConfig) {
	tp.perfMu.Lock()
	defer tp.perfMu.Unlock()
	tp.bufferSize = config.ClampBufferSize(perf.BufferSize)
	tp.tcpNoDelay = perf.TCPNoDelay
	tp.tcpSocketBuffer = 0
	tp.bidirectWait = perf.BidirectWait
	tp.tcpKeepAlive = perf.TCPKeepAlive
	tp.keepAlivePeriod = perf.KeepAlivePeriod
	tp.tcpLinger = perf.TCPLinger
	log.Printf("[TProxy] 🚀 性能参数热更新: Buffer=%dB, NoDelay=%v, SocketBuf=0B, BidirectWait=%v, KeepAlive=%v/%ds, Linger=%d",
		tp.bufferSize, tp.tcpNoDelay, tp.bidirectWait, tp.tcpKeepAlive, tp.keepAlivePeriod, tp.tcpLinger)
}

func (tp *TProxy) UpdateUpstream(pType, pAddr string) {
	tp.upstream.Update(pType, pAddr)
	log.Printf("[TProxy] 上游代理已热切换为: %s -> %s", pType, pAddr)
}

func (tp *TProxy) SetFakeIPResolver(fn func(net.IP) (net.IP, bool)) {
	tp.fakeIPResolver = fn
}

func (tp *TProxy) resolveProxyTarget(origDstIP net.IP, origDstPort uint16, sni string, isHTTPS bool, domain string) ResolveProxyTargetResult {
	return ResolveProxyTarget(origDstIP, origDstPort, sni, isHTTPS, domain, tp.fakeIPResolver)
}

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

	tp.perfMu.RLock()
	bufSize := tp.bufferSize
	noDelay := tp.tcpNoDelay
	sockBuf := 0 // v1.6.6: always use Windows TCP Auto-Tuning
	biWait := tp.bidirectWait
	keepAlive := tp.tcpKeepAlive
	keepAlivePeriod := tp.keepAlivePeriod
	tcpLinger := tp.tcpLinger
	tp.perfMu.RUnlock()

	bufSize = config.ClampBufferSize(bufSize)

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

	origDstAddr := net.JoinHostPort(target.OrigDstIP.String(), strconv.Itoa(int(target.OrigDstPort)))

	var peekBuf []byte
	isHTTPS := target.OrigDstPort == 443
	domain := ""
	var sni string

	if isHTTPS {
		var err error
		peekBuf, sni, err = readTLSClientHello(conn)
		if err == nil && sni != "" {
			domain = sni
		}
	}

	policy := "PROXY"
	reason := "whitelist"
	var remote net.Conn
	var err error
	var targetAddr string

	if tp.router != nil && tp.router.SplitEnabled() {
		res := tp.router.Decide(domain, target.OrigDstIP, target.ProcessName)
		reason = res.Reason
		if res.Decision == DecisionDirect {
			targetAddr = origDstAddr
			remote, err = net.DialTimeout("tcp", targetAddr, 10*time.Second)
			policy = "DIRECT"
		} else {
			resolved := tp.resolveProxyTarget(target.OrigDstIP, target.OrigDstPort, sni, isHTTPS, domain)
			targetAddr = resolved.Target
			remote, err = tp.upstream.Dial("tcp", targetAddr)
		}
	} else {
		resolved := tp.resolveProxyTarget(target.OrigDstIP, target.OrigDstPort, sni, isHTTPS, domain)
		targetAddr = resolved.Target
		remote, err = tp.upstream.Dial("tcp", targetAddr)
	}

	if err != nil {
		log.Printf("[TProxy] 连接失败 %s (policy=%s reason=%s): %v", targetAddr, policy, reason, err)
		return
	}
	defer remote.Close()

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
			if sockBuf > 0 {
				tc.SetReadBuffer(sockBuf)
				tc.SetWriteBuffer(sockBuf)
			}
		}
	}
	tuneConn(conn)
	tuneConn(remote)

	if len(peekBuf) > 0 {
		_, err := remote.Write(peekBuf)
		if err != nil {
			log.Printf("[TProxy] 发送缓存包失败: %v", err)
			return
		}
	}

	if tp.stats != nil {
		connInfo := map[string]interface{}{
			"id": fmt.Sprintf("%s:%d", srcIP, srcPort),
			"process": target.ProcessName,
			"target": targetAddr,
			"host": target.OrigDstIP.String(),
			"domain": domain,
			"policy": policy,
			"reason": reason,
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

func (tp *TProxy) Close() error {
	return tp.listener.Close()
}
