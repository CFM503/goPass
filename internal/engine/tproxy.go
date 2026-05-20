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

// ip4String converts [4]byte to dotted decimal string using a single buffer
func ip4String(b [4]byte) string {
	var buf [15]byte
	n := 0
	for i := 0; i < 4; i++ {
		v := int(b[i])
		if v >= 100 {
			buf[n] = byte('0' + v/100)
			buf[n+1] = byte('0' + (v/10)%10)
			buf[n+2] = byte('0' + v%10)
			n += 3
		} else if v >= 10 {
			buf[n] = byte('0' + v/10)
			buf[n+1] = byte('0' + v%10)
			n += 2
		} else {
			buf[n] = byte('0' + v)
			n++
		}
		if i < 3 {
			buf[n] = '.'
			n++
		}
	}
	return string(buf[:n])
}

// bufferPool 32KB buffers; 99% of TLS ClientHellos are <4KB.
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

	bufferSize      atomic.Int64
	tcpNoDelay      atomic.Bool
	tcpSocketBuffer atomic.Int64
	bidirectWait    atomic.Bool
	tcpKeepAlive    atomic.Bool
	keepAlivePeriod atomic.Int64
	tcpLinger       atomic.Int64

	stats *Stats
}

// NewTProxy 创建本地代理监听器
func NewTProxy(tracker *ConnTracker, proxyType, proxyAddr string, stats *Stats, perf config.PerformanceConfig, tproxyPort int) (*TProxy, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", tproxyPort))
	if err != nil {
		return nil, fmt.Errorf("TProxy listen failed: %w", err)
	}
	log.Printf("[TProxy] 本地透明代理监听: 0.0.0.0:%d", tproxyPort)

	tp := &TProxy{
		listener:   ln,
		tracker:    tracker,
		proxyType:  proxyType,
		proxyAddr:  proxyAddr,
		stats:      stats,
	}
	tp.bufferSize.Store(int64(perf.BufferSize))
	tp.tcpNoDelay.Store(perf.TCPNoDelay)
	tp.tcpSocketBuffer.Store(int64(perf.TCPSocketBuffer))
	tp.bidirectWait.Store(perf.BidirectWait)
	tp.tcpKeepAlive.Store(perf.TCPKeepAlive)
	tp.keepAlivePeriod.Store(int64(perf.KeepAlivePeriod))
	tp.tcpLinger.Store(int64(perf.TCPLinger))
	return tp, nil
}

// UpdatePerformance 热更新性能参数
func (tp *TProxy) UpdatePerformance(perf config.PerformanceConfig) {
	tp.bufferSize.Store(int64(perf.BufferSize))
	tp.tcpNoDelay.Store(perf.TCPNoDelay)
	tp.tcpSocketBuffer.Store(int64(perf.TCPSocketBuffer))
	tp.bidirectWait.Store(perf.BidirectWait)
	tp.tcpKeepAlive.Store(perf.TCPKeepAlive)
	tp.keepAlivePeriod.Store(int64(perf.KeepAlivePeriod))
	tp.tcpLinger.Store(int64(perf.TCPLinger))
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

	bufSize := int(tp.bufferSize.Load())
	noDelay := tp.tcpNoDelay.Load()
	sockBuf := int(tp.tcpSocketBuffer.Load())
	biWait := tp.bidirectWait.Load()
	keepAlive := tp.tcpKeepAlive.Load()
	keepAlivePeriod := int(tp.keepAlivePeriod.Load())
	tcpLinger := int(tp.tcpLinger.Load())

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

	srcIP := ip4ToBytes(tcpAddr.IP)
	srcPort := uint16(tcpAddr.Port)

	target, found := tp.tracker.Get(srcIP, srcPort)
	if !found {
		return
	}
	defer tp.tracker.Delete(srcIP, srcPort)

	dstIPStr := ip4String(target.OrigDstIP)
	targetAddr := dstIPStr + ":" + strconv.Itoa(int(target.OrigDstPort))

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
	if pType == "http" {
		dialer, _ = NewHTTPProxy(pAddr, "", "", proxy.Direct)
	} else {
		dialer, _ = proxy.SOCKS5("tcp", pAddr, nil, proxy.Direct)
	}
	if dialer == nil {
		log.Printf("[TProxy] 代理 Dialer 创建失败 (type=%s, addr=%s)", pType, pAddr)
		return
	}

	remote, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("[TProxy] 上游连接失败 %s via %s %s: %v", targetAddr, pType, pAddr, err)
		return
	}
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

	connID := ip4String(srcIP) + ":" + strconv.Itoa(int(srcPort))
	if tp.stats != nil {
		tp.stats.AddActiveConn(ConnInfo{
			ID:      connID,
			Process: target.ProcessName,
			Target:  targetAddr,
			Host:    dstIPStr,
			Policy:  "PROXY",
		})
	}

	defer func() {
		if tp.stats != nil {
			tp.stats.RemoveActiveConn(connID)
		}
	}()

	stats := tp.stats

	done := make(chan struct{}, 2)

	go func() {
		buf := bufferPool.Get().([]byte)
		if cap(buf) < bufSize {
			buf = make([]byte, bufSize)
		} else {
			buf = buf[:bufSize]
		}
		defer func() {
			if cap(buf) <= 32768 {
				bufferPool.Put(buf[:cap(buf)])
			}
		}()
		for {
			n, err := remote.Read(buf)
			if n > 0 {
				if stats != nil {
					atomic.AddInt64(&stats.RxBytes, int64(n))
				}
				if _, errWrite := conn.Write(buf[:n]); errWrite != nil {
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
		if cap(buf) < bufSize {
			buf = make([]byte, bufSize)
		} else {
			buf = buf[:bufSize]
		}
		defer func() {
			if cap(buf) <= 32768 {
				bufferPool.Put(buf[:cap(buf)])
			}
		}()
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if stats != nil {
					atomic.AddInt64(&stats.TxBytes, int64(n))
				}
				if _, errWrite := remote.Write(buf[:n]); errWrite != nil {
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
