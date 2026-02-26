package engine

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"golang.org/x/net/proxy"
)

// TProxy 是本地透明代理 TCP 监听器
// 它监听 127.0.0.1:7893，接收 WinDivert 劫持过来的连接
// 然后查出原始目标，通过 SOCKS5 代理转发
type TProxy struct {
	listener   net.Listener
	tracker    *ConnTracker
	socks5Addr string // e.g. "127.0.0.1:9192"
	stats      *Stats
	mu         sync.Mutex
}

// NewTProxy 创建本地代理监听器
func NewTProxy(tracker *ConnTracker, socks5Addr string, stats *Stats) (*TProxy, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", TProxyPort))
	if err != nil {
		return nil, fmt.Errorf("TProxy listen failed: %w", err)
	}
	log.Printf("[TProxy] 本地透明代理监听: 0.0.0.0:%d", TProxyPort)
	return &TProxy{
		listener:   ln,
		tracker:    tracker,
		socks5Addr: socks5Addr,
		stats:      stats,
	}, nil
}

// Accept 开始接受连接（阻塞）
func (tp *TProxy) Accept() {
	for {
		conn, err := tp.listener.Accept()
		if err != nil {
			log.Printf("[TProxy] Accept error: %v", err)
			return
		}
		log.Printf("[TProxy] 收到连接: %s", conn.RemoteAddr())
		go tp.handleConn(conn)
	}
}

func (tp *TProxy) handleConn(conn net.Conn) {
	defer conn.Close()

	// 获取连接的来源 IP 和端口
	tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}

	srcIP := tcpAddr.IP.String()
	srcPort := uint16(tcpAddr.Port)

	// 在连接跟踪表中查找原始目标
	target, found := tp.tracker.Get(srcIP, srcPort)
	if !found {
		log.Printf("[TProxy] 找不到连接跟踪: %s:%d", srcIP, srcPort)
		return
	}
	defer tp.tracker.Delete(srcIP, srcPort)

	targetAddr := fmt.Sprintf("%s:%d", target.OrigDstIP.String(), target.OrigDstPort)
	log.Printf("[TProxy] %s:%d -> 原始目标 %s -> 经 SOCKS5 转发", srcIP, srcPort, targetAddr)

	// 通过 SOCKS5 连接原始目标
	dialer, err := proxy.SOCKS5("tcp", tp.socks5Addr, nil, proxy.Direct)
	if err != nil {
		log.Printf("[TProxy] SOCKS5 dialer 创建失败: %v", err)
		return
	}

	remote, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("[TProxy] SOCKS5 连接失败 %s: %v", targetAddr, err)
		return
	}
	defer remote.Close()

	// 记录活动连接
	tp.mu.Lock()
	if tp.stats != nil {
		tp.stats.Connections++
		connInfo := map[string]interface{}{
			"id":      fmt.Sprintf("%s:%d", srcIP, srcPort),
			"process": target.ProcessName,
			"target":  targetAddr,
			"host":    target.OrigDstIP.String(),
			"policy":  "PROXY",
		}
		tp.stats.Active = append(tp.stats.Active, connInfo)
	}
	tp.mu.Unlock()

	defer func() {
		tp.mu.Lock()
		if tp.stats != nil {
			tp.stats.Connections--
			// Remove from Active list
			for i, v := range tp.stats.Active {
				if v["id"] == fmt.Sprintf("%s:%d", srcIP, srcPort) {
					tp.stats.Active = append(tp.stats.Active[:i], tp.stats.Active[i+1:]...)
					break
				}
			}
		}
		tp.mu.Unlock()
	}()

	// 双向数据中继并统计流量
	done := make(chan struct{}, 2)
	relay := func(dst, src net.Conn, isRx bool) {
		written, _ := io.Copy(dst, src)
		// Update byte counters
		tp.mu.Lock()
		if tp.stats != nil {
			if isRx {
				tp.stats.RxBytes += written
			} else {
				tp.stats.TxBytes += written
			}
		}
		tp.mu.Unlock()
		done <- struct{}{}
	}
	go relay(remote, conn, false) // 发送 (Tx)
	go relay(conn, remote, true)  // 接收 (Rx)
	<-done
}

// Close 关闭监听器
func (tp *TProxy) Close() error {
	return tp.listener.Close()
}
