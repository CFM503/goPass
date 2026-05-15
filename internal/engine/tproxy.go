package engine

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yourusername/gopass/internal/config"
	"golang.org/x/net/proxy"
)

// ip4String converts [4]byte to dotted decimal string, zero allocation via small buffer
func ip4String(b [4]byte) string {
	return strconv.Itoa(int(b[0])) + "." + strconv.Itoa(int(b[1])) + "." + strconv.Itoa(int(b[2])) + "." + strconv.Itoa(int(b[3]))
}

// bufferPool 32KB buffers; 99% of TLS ClientHellos are <4KB.
// Large records handled by dynamic alloc in readTLSClientHello.
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32768)
	},
}

// readTLSClientHello reads a complete TLS ClientHello record.
//
// [v1.1.7 FIX] Chrome Kyber post-quantum makes ClientHello > MTU, causing TCP fragmentation.
//
//	Old single conn.Read() only got fragment 1, SNI extraction failed, YouTube showed error.
//
// [v1.1.9 FIX] Dynamic buffer alloc for records > 4096 bytes.
func readTLSClientHello(conn net.Conn) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

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

	data := make([]byte, 5+recordLen)
	copy(data, header)
	if _, err := io.ReadFull(conn, data[5:]); err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Time{})
	return data, nil
}

// TProxy 是本地透明代理 TCP 监听器
type TProxy struct {
	listener net.Listener
	tracker  *ConnTracker

	proxyType string
	proxyAddr string
	proxyMu   sync.RWMutex

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

// UpdatePerformance 热更新性能参数
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

	tp.perfMu.RLock()
	bufSize := tp.bufferSize
	noDelay := tp.tcpNoDelay
	sockBuf := tp.tcpSocketBuffer
	biWait := tp.bidirectWait
	keepAlive := tp.tcpKeepAlive
	keepAlivePeriod := tp.keepAlivePeriod
	tcpLinger := tp.tcpLinger
	tp.perfMu.RUnlock()

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

	targetAddr := ip4String(target.OrigDstIP) + ":" + strconv.Itoa(int(target.OrigDstPort))

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
				targetAddr = sni + ":" + strconv.Itoa(int(target.OrigDstPort))
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

	tp.tuneConn(conn, noDelay, keepAlive, keepAlivePeriod, tcpLinger, sockBuf)
	tp.tuneConn(remote, noDelay, keepAlive, keepAlivePeriod, tcpLinger, sockBuf)

	if len(peekBuf) > 0 {
		_, err := remote.Write(peekBuf)
		if err != nil {
			log.Printf("[TProxy] 发送缓存包失败: %v", err)
			return
		}
	}

	connID := srcIP + ":" + strconv.Itoa(int(srcPort))
	if tp.stats != nil {
		tp.stats.AddActiveConn(ConnInfo{
			ID:      connID,
			Process: target.ProcessName,
			Target:  targetAddr,
			Host:    ip4String(target.OrigDstIP),
			Policy:  "PROXY",
		})
	}

	defer func() {
		if tp.stats != nil {
			tp.stats.RemoveActiveConn(connID)
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

func (tp *TProxy) tuneConn(c net.Conn, noDelay, keepAlive bool, keepAlivePeriod, tcpLinger, sockBuf int) {
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

// Close 关闭监听器
func (tp *TProxy) Close() error {
	return tp.listener.Close()
}
