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

	"github.com/CFM503/goPass/internal/config"
)

const defaultRelayBufferSize = 64 * 1024

var relayBufferPool = sync.Pool{New: func() any { return make([]byte, defaultRelayBufferSize) }}

func getRelayBuffer(size int) []byte {
	size = config.ClampBufferSize(size)
	if size <= defaultRelayBufferSize {
		return relayBufferPool.Get().([]byte)[:size]
	}
	return make([]byte, size)
}

func putRelayBuffer(buf []byte) {
	if cap(buf) == defaultRelayBufferSize {
		relayBufferPool.Put(buf[:defaultRelayBufferSize])
	}
}

func originalTarget(ip net.IP, port uint16) (string, error) {
	if ip == nil || ip.IsUnspecified() { return "", fmt.Errorf("invalid original destination IP") }
	if port == 0 { return "", fmt.Errorf("invalid original destination port") }
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), nil
}

// readTLSClientHello reads exactly the first TLS record and extracts SNI.
// This is the important historical YouTube compatibility behavior: the
// upstream proxy must receive the hostname, not only the intercepted IP.
// All bytes read are returned so the ClientHello is never lost.
func readTLSClientHello(conn net.Conn) (readBuf []byte, sni string, err error) {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	// 头部读进栈上数组：只有确认是合法 TLS ClientHello 后才分配返回缓冲。
	var hdr [5]byte
	n, errRead := io.ReadFull(conn, hdr[:])
	if n < 5 {
		return hdr[:n], "", fmt.Errorf("read TLS header: %w", errRead)
	}
	if hdr[0] != 22 {
		return hdr[:], "", fmt.Errorf("not TLS handshake: type=%d", hdr[0])
	}
	recordLen := int(hdr[3])<<8 | int(hdr[4])
	if recordLen <= 0 || recordLen > 16384 {
		return hdr[:], "", fmt.Errorf("invalid TLS record length: %d", recordLen)
	}
	// 精确一次分配（5 + recordLen），替代 bytes.Buffer 的多次扩容+拷贝。
	all := make([]byte, 5+recordLen)
	copy(all, hdr[:])
	nBody, errBody := io.ReadFull(conn, all[5:])
	if errBody != nil {
		return all[:5+nBody], "", fmt.Errorf("read TLS record: %w", errBody)
	}
	foundSNI, sniErr := ExtractSNI(all)
	return all, foundSNI, sniErr
}

type TProxy struct {
	listener   net.Listener
	tracker    *ConnTracker
	upstream   *UpstreamDialer
	bufferSize int
	perfMu     sync.RWMutex
	stats      *Stats
}

func NewTProxy(tracker *ConnTracker, proxyType, proxyAddr, proxyUser, proxyPass string, stats *Stats, perf config.PerformanceConfig, tproxyPort int) (*TProxy, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", tproxyPort))
	if err != nil { return nil, fmt.Errorf("TProxy listen failed: %w", err) }
	return &TProxy{
		listener: ln,
		tracker: tracker,
		upstream: NewUpstreamDialer(proxyType, proxyAddr, proxyUser, proxyPass),
		bufferSize: config.ClampBufferSize(perf.BufferSize),
		stats: stats,
	}, nil
}

func (tp *TProxy) UpdatePerformance(perf config.PerformanceConfig) {
	tp.perfMu.Lock()
	tp.bufferSize = config.ClampBufferSize(perf.BufferSize)
	tp.perfMu.Unlock()
}

func (tp *TProxy) UpdateUpstream(proxyType, proxyAddr, proxyUser, proxyPass string) {
	tp.upstream.Update(proxyType, proxyAddr, proxyUser, proxyPass)
	// 只打印类型与地址：凭据不能进日志。
	log.Printf("[TProxy] upstream proxy switched to %s -> %s", proxyType, proxyAddr)
}

func (tp *TProxy) Accept() {
	var tempDelay time.Duration
	for {
		conn, err := tp.listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 { tempDelay = 5 * time.Millisecond } else { tempDelay *= 2 }
				if tempDelay > time.Second { tempDelay = time.Second }
				time.Sleep(tempDelay)
				continue
			}
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
	tp.perfMu.RUnlock()

	tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok { return }
	srcIP, srcPort := tcpAddr.IP.String(), uint16(tcpAddr.Port)
	target, found := tp.tracker.Get(srcIP, srcPort)
	if !found { return }
	tp.tracker.Activate(srcIP, srcPort)
	defer tp.tracker.Delete(srcIP, srcPort)

	targetAddr, err := originalTarget(target.OrigDstIP, target.OrigDstPort)
	if err != nil { return }

	// Historical YouTube fix: for HTTPS, sniff SNI before opening the
	// upstream connection. Google/YouTube CDNs can require the hostname for
	// correct routing; dialing the intercepted IP alone is not equivalent.
	var peekBuf []byte
	if target.OrigDstPort == 443 {
		if data, sni, sniffErr := readTLSClientHello(conn); len(data) > 0 {
			peekBuf = data
			if sniffErr == nil && sni != "" {
				targetAddr = net.JoinHostPort(sni, strconv.Itoa(int(target.OrigDstPort)))
				log.Printf("[TProxy] HTTPS SNI=%s target=%s", sni, targetAddr)
			}
		}
	}

	remote, err := tp.upstream.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("[TProxy] upstream connect failed target=%s: %v", targetAddr, err)
		return
	}
	defer remote.Close()

	tune := func(c net.Conn) {
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(15 * time.Second)
		}
	}
	tune(conn)
	tune(remote)

	// Replay the complete ClientHello that was consumed by SNI sniffing.
	if len(peekBuf) > 0 {
		if _, err := remote.Write(peekBuf); err != nil {
			log.Printf("[TProxy] write buffered TLS ClientHello failed: %v", err)
			return
		}
	}

	if tp.stats != nil {
		id := fmt.Sprintf("%s:%d", srcIP, srcPort)
		tp.stats.AddActiveConn(map[string]interface{}{"id": id, "target": targetAddr})
		defer tp.stats.RemoveActiveConn(id)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	result := make(chan relayResult, 2)
	go func() { defer wg.Done(); result <- tp.relay(remote, conn, false, bufSize) }()
	go func() { defer wg.Done(); result <- tp.relay(conn, remote, true, bufSize) }()

	first := <-result
	if first.err != nil { _ = conn.Close(); _ = remote.Close() }
	second := <-result
	if first.err == nil && second.err != nil { _ = conn.Close(); _ = remote.Close() }
	wg.Wait()
}

type relayResult struct { n int64; err error }

func (tp *TProxy) relay(src, dst net.Conn, tx bool, size int) relayResult {
	buf := getRelayBuffer(size)
	defer putRelayBuffer(buf)
	n, err := io.CopyBuffer(writerConn{Conn: dst, stats: tp.stats, tx: tx}, src, buf)
	if err == nil || err == io.EOF {
		if tc, ok := dst.(*net.TCPConn); ok { _ = tc.CloseWrite() }
	}
	return relayResult{n: n, err: err}
}

type writerConn struct { net.Conn; stats *Stats; tx bool }

func (w writerConn) Write(p []byte) (int, error) {
	n, err := w.Conn.Write(p)
	if n > 0 && w.stats != nil {
		if w.tx { atomic.AddInt64(&w.stats.TxBytes, int64(n)) } else { atomic.AddInt64(&w.stats.RxBytes, int64(n)) }
	}
	return n, err
}

func (tp *TProxy) Close() error { return tp.listener.Close() }
