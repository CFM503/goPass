package engine

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CFM503/goPass/internal/config"
	"golang.org/x/net/proxy"
)

// bufferPool holds 1MB buffers; handleConn slices them to the configured size.
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 1024*1024) // 1MB max
	},
}

// readTLSClientHello reads a complete TLS ClientHello record.
//
// [v1.1.7 FIX] Chrome Kyber post-quantum makes ClientHello > MTU, causing TCP fragmentation.
//
//	Old single conn.Read() only got fragment 1, SNI extraction failed, YouTube showed error.
//
// [v1.1.9 FIX] Dynamic buffer alloc for records > 4096 bytes (old pool buffer silently dropped them).
func readTLSClientHello(conn net.Conn) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Step 1: TLS Record header (5 bytes)
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != 22 {
		return nil, fmt.Errorf("not TLS handshake: type=%d", header[0])
	}

	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen <= 0 || recordLen > 16384 {
		return nil, fmt.Errorf("invalid TLS record length: %d", recordLen)
	}

	// Step 2: Read full record body (dynamic alloc for Kyber large records)
	data := make([]byte, 5+recordLen)
	copy(data, header)
	if _, err := io.ReadFull(conn, data[5:]); err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Time{})
	return data, nil
}

// TProxy 是本地透明代理 TCP 监听器
// 它监听 127.0.0.1:7893，接收 WinDivert 劫持过来的连接
// 然后查出原始目标，通过 SOCKS5/HTTP 代理转发
type TProxy struct {
	listener net.Listener
	tracker  *ConnTracker

	proxyType string
	proxyAddr string
	proxyMu   sync.RWMutex

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
func NewTProxy(tracker *ConnTracker, proxyType, proxyAddr string, stats *Stats, perf config.PerformanceConfig, tproxyPort int) (*TProxy, error) {
	// [v1.2.6 Config] 移除魔数 7893，使用系统配置的 TProxyPort
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", tproxyPort))
	if err != nil {
		return nil, fmt.Errorf("TProxy listen failed: %w", err)
	}
	log.Printf("[TProxy] 本地透明代理监听: 0.0.0.0:%d", tproxyPort)
	return &TProxy{
		listener:        ln,
		tracker:         tracker,
		proxyType:       proxyType,
		proxyAddr:       proxyAddr,
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
	tp.proxyMu.Lock()
	defer tp.proxyMu.Unlock()
	tp.proxyType = pType
	tp.proxyAddr = pAddr
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
	if bufSize <= 0 {
		bufSize = 32768
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

	// SNI Sniffing
	var peekBuf []byte
	isHTTPS := target.OrigDstPort == 443

	if isHTTPS {
		var err error
		peekBuf, err = readTLSClientHello(conn)
		if err != nil {
			_ = err
		}
		if len(peekBuf) > 0 {
			if sni, errSNI := ExtractSNI(peekBuf); errSNI == nil && sni != "" {
				targetAddr = fmt.Sprintf("%s:%d", sni, target.OrigDstPort)
			}
		}
	}

	tp.proxyMu.RLock()
	pType := tp.proxyType
	pAddr := tp.proxyAddr
	tp.proxyMu.RUnlock()

	var dialer proxy.Dialer
	var errDialer error

	if pType == "http" {
		dialer, errDialer = NewHTTPProxy(pAddr, "", "", proxy.Direct)
	} else {
		dialer, errDialer = proxy.SOCKS5("tcp", pAddr, nil, proxy.Direct)
	}

	if errDialer != nil {
		log.Printf("[TProxy] 代理 Dialer 创建失败: %v", errDialer)
		return
	}

	remote, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("[TProxy] 上游连接失败 %s: %v", targetAddr, err)
		return
	}
	defer remote.Close()

	// [v1.2.1] Apply dynamic TCP tuning using live performance settings
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
			"id":      fmt.Sprintf("%s:%d", srcIP, srcPort),
			"process": target.ProcessName,
			"target":  targetAddr,
			"host":    target.OrigDstIP.String(),
			"policy":  "PROXY",
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
		copyBuf := buf[:bufSize]
		for {
			n, err := remote.Read(copyBuf)
			if n > 0 {
				if tp.stats != nil {
					atomic.AddInt64(&tp.stats.RxBytes, int64(n))
				}
				if _, errWrite := conn.Write(copyBuf[:n]); errWrite != nil {
					// [FIX 2] Data Blackhole: if we can't write to local anymore, break and half-close
					if tc, ok := conn.(*net.TCPConn); ok {
						tc.CloseWrite()
					}
					break
				}
			}
			if err != nil {
				// [FIX 1] TCP Half-Close: when remote finishes sending, close local's receiving end
				// This prevents local from hanging on Read() forever.
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
		copyBuf := buf[:bufSize]
		for {
			n, err := conn.Read(copyBuf)
			if n > 0 {
				if tp.stats != nil {
					atomic.AddInt64(&tp.stats.TxBytes, int64(n))
				}
				if _, errWrite := remote.Write(copyBuf[:n]); errWrite != nil {
					// [FIX 2] Data Blackhole: if we can't write to remote anymore, break and half-close
					if tc, ok := remote.(*net.TCPConn); ok {
						tc.CloseWrite()
					}
					break
				}
			}
			if err != nil {
				// [FIX 1] TCP Half-Close: when local finishes sending, close remote's receiving end
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
