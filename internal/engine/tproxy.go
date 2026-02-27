package engine

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// TProxy 是本地透明代理 TCP 监听器
// 它监听 127.0.0.1:7893，接收 WinDivert 劫持过来的连接
// 然后查出原始目标，通过 SOCKS5/HTTP 代理转发
type TProxy struct {
	listener net.Listener
	tracker  *ConnTracker

	// 上游代理配置（支持热身修改）
	proxyType string // "socks5" or "http"
	proxyAddr string // e.g. "127.0.0.1:9192"
	proxyMu   sync.RWMutex

	stats *Stats
	mu    sync.Mutex
}

// NewTProxy 创建本地代理监听器
func NewTProxy(tracker *ConnTracker, proxyType, proxyAddr string, stats *Stats) (*TProxy, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", TProxyPort))
	if err != nil {
		return nil, fmt.Errorf("TProxy listen failed: %w", err)
	}
	log.Printf("[TProxy] 本地透明代理监听: 0.0.0.0:%d", TProxyPort)
	return &TProxy{
		listener:  ln,
		tracker:   tracker,
		proxyType: proxyType,
		proxyAddr: proxyAddr,
		stats:     stats,
	}, nil
}

// UpdateUpstream 热更上游代理配置
func (tp *TProxy) UpdateUpstream(pType, pAddr string) {
	tp.proxyMu.Lock()
	defer tp.proxyMu.Unlock()
	tp.proxyType = pType
	tp.proxyAddr = pAddr
	log.Printf("[TProxy] 🔄 上游代理已热切换为: %s -> %s", pType, pAddr)
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

	// ==========================================================
	// 核心魔法：SNI 嗅探防污染 (SNI Sniffing)
	// ==========================================================
	var peekBuf []byte
	isHTTPS := target.OrigDstPort == 443

	if isHTTPS {
		// 尝试读取客户端发来的第一段数据 (通常是 TLS ClientHello)
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		conn.SetReadDeadline(time.Time{}) // 恢复阻止模式

		if err == nil && n > 0 {
			peekBuf = buf[:n]
			sni, errSNI := ExtractSNI(peekBuf)
			if errSNI == nil && sni != "" {
				log.Printf("[TProxy] 🎯 成功嗅探到 SNI 域名: %s (原目标 IP: %s)", sni, target.OrigDstIP.String())
				// 替换 targetAddr，让 SOCKS5 代理使用纯净的域名去解析
				targetAddr = fmt.Sprintf("%s:%d", sni, target.OrigDstPort)
			} else {
				log.Printf("[TProxy] 未提取到 SNI: %v", errSNI)
			}
		}
	}

	// 获取当前最新上游配置
	tp.proxyMu.RLock()
	pType := tp.proxyType
	pAddr := tp.proxyAddr
	tp.proxyMu.RUnlock()

	log.Printf("[TProxy] %s:%d -> 经 %s 转发至 -> %s", srcIP, srcPort, strings.ToUpper(pType), targetAddr)

	var dialer proxy.Dialer
	var errDialer error

	if pType == "http" {
		dialer, errDialer = NewHTTPProxy(pAddr, "", "", proxy.Direct)
	} else {
		// 默认 socks5
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

	// 如果我们上面读取 (Peek) 了数据，需要先把它发送给远端，不能丢包
	if len(peekBuf) > 0 {
		_, err := remote.Write(peekBuf)
		if err != nil {
			log.Printf("[TProxy] 发送缓存包失败: %v", err)
			return
		}
	}

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
