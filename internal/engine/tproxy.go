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
			// 解决 Active 切片缩减引发的底层指针垃圾回收泄漏 (Pointer Leak Trap)
			activeLen := len(tp.stats.Active)
			for i := 0; i < activeLen; i++ {
				if tp.stats.Active[i]["id"] == fmt.Sprintf("%s:%d", srcIP, srcPort) {
					// 将最后一个元素移到当前位置（不关心顺序）并置空最后一个元素
					tp.stats.Active[i] = tp.stats.Active[activeLen-1]
					tp.stats.Active[activeLen-1] = nil // 显式置空，帮助 GC
					tp.stats.Active = tp.stats.Active[:activeLen-1]
					break
				}
			}
		}
		tp.mu.Unlock()
	}()

	// 为 io.Copy 包裹一层统计跟踪器，解决大文件下载统计卡死的问题 (Real-time stat fix)
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(remote, &statTracker{Reader: conn, tp: tp, isRx: false})
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, &statTracker{Reader: remote, tp: tp, isRx: true})
		done <- struct{}{}
	}()
	<-done
}

// statTracker 包装 io.Reader 实现一边传输一边实时增加统计字节数
type statTracker struct {
	io.Reader
	tp   *TProxy
	isRx bool
}

func (st *statTracker) Read(p []byte) (n int, err error) {
	n, err = st.Reader.Read(p)
	if n > 0 && st.tp.stats != nil {
		st.tp.mu.Lock()
		if st.isRx {
			st.tp.stats.RxBytes += int64(n)
		} else {
			st.tp.stats.TxBytes += int64(n)
		}
		st.tp.mu.Unlock()
	}
	return n, err
}

// Close 关闭监听器
func (tp *TProxy) Close() error {
	return tp.listener.Close()
}
