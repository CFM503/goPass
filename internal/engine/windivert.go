package engine

// WinDivert 纯 Go 实现 - 通过 Windows syscall 动态加载 WinDivert.dll
// 无需 CGo、无需头文件、无需 .lib 文件
// 参考文档：https://reqrypt.org/windivert-doc.html

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/CFM503/goPass/internal/process"
	"golang.org/x/sys/windows"
)

const (
	// WinDivert Layer
	layerNetwork = 0

	// WinDivert Priority
	priorityDefault = 0

	// WinDivert Flags
	flagSniff = 1
)

// WINDIVERT_ADDRESS 对应 C 结构体 WINDIVERT_ADDRESS
// 完整 64 字节联合体，保证与驱动二进制兼容
type winDivertAddress struct {
	Timestamp int64    // 0-7
	Bits      uint32   // 8-11: Layer(8), Event(8), Sniffed(1), Outbound(1), Loopback(1)...
	Reserved2 uint32   // 12-15
	IfIdx     uint32   // 16-19 (Union starts here)
	SubIfIdx  uint32   // 20-23
	Data      [60]byte // Remaining Union space
}

const (
	// Bits 中的标志偏移 (基于 2.2 官方定义)
	flagOutbound = 1 << 17
	flagLoopback = 1 << 18
)

// WinDivert DLL 动态加载封装
type winDivertDLL struct {
	dll            *windows.DLL
	procOpen       *windows.Proc
	procRecv       *windows.Proc
	procSend       *windows.Proc
	procClose      *windows.Proc
	procCalcChecks *windows.Proc
}

var (
	wdOnce sync.Once
	wdDLL  *winDivertDLL
	wdErr  error
)

// stopAndRemoveWinDivertDriver 停止并删除 WinDivert 内核驱动服务，释放 SYS 文件锁
// 关键：必须删除旧服务，否则 WinDivert DLL 会复用旧的 BINARY_PATH_NAME（指向已不存在的路径）
func stopAndRemoveWinDivertDriver() {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_CREATE_SERVICE)
	if err != nil {
		return
	}
	defer windows.CloseServiceHandle(scm)
	svc, err := windows.OpenService(scm, syscall.StringToUTF16Ptr("WinDivert"), windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS|windows.DELETE)
	if err != nil {
		return
	}
	defer windows.CloseServiceHandle(svc)
	var status windows.SERVICE_STATUS
	windows.ControlService(svc, windows.SERVICE_CONTROL_STOP, &status)
	// 等待驱动停止，最多 2 秒
	for i := 0; i < 20; i++ {
		time.Sleep(100 * time.Millisecond)
		windows.QueryServiceStatus(svc, &status)
		if status.CurrentState == windows.SERVICE_STOPPED {
			break
		}
	}
	// 删除旧服务，确保下次 WinDivertOpen 会用新路径重新注册
	windows.DeleteService(svc)
	log.Println("[WinDivert] 已清理旧的驱动服务注册")
}

// mustStatSize 获取文件大小，失败返回 -1
func mustStatSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return info.Size()
}

// getExeDir 获取可执行文件所在目录（便携版场景，文件释放到 exe 同目录）
func getExeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return os.TempDir()
	}
	return filepath.Dir(exe)
}

// loadWinDivert 加载 WinDivert.dll（仅加载一次）
// DLL 和 SYS 驱动已嵌入二进制，启动时释放到 exe 所在目录
func loadWinDivert() (*winDivertDLL, error) {
	wdOnce.Do(func() {
		// 先停止已运行的 WinDivert 驱动，释放 SYS 文件锁
		stopAndRemoveWinDivertDriver()

		// 释放嵌入的 WinDivert 文件到 exe 所在目录（便携版友好）
		wdDir := filepath.Join(getExeDir(), "gopass_wd")
		if err := os.MkdirAll(wdDir, 0755); err != nil {
			wdErr = fmt.Errorf("无法创建驱动目录 %s: %w", wdDir, err)
			return
		}
		dllPath := filepath.Join(wdDir, "WinDivert.dll")
		sysPath := filepath.Join(wdDir, "WinDivert64.sys")

		log.Printf("[WinDivert] 释放驱动到: %s", wdDir)

		// 尝试删除旧文件（可能被上一次运行的内核驱动锁定）
		for i := 0; i < 10; i++ {
			os.Remove(dllPath)
			os.Remove(sysPath)
			// 检查文件是否已释放
			if _, err := os.Stat(sysPath); os.IsNotExist(err) {
				break
			}
			log.Printf("[WinDivert] 等待旧驱动文件释放... (%d/10)", i+1)
			time.Sleep(500 * time.Millisecond)
		}

		if err := os.WriteFile(dllPath, windivertDLL, 0755); err != nil {
			wdErr = fmt.Errorf("无法释放 WinDivert.dll: %w", err)
			return
		}
		if err := os.WriteFile(sysPath, windivertSYS, 0755); err != nil {
			wdErr = fmt.Errorf("无法释放 WinDivert64.sys: %w", err)
			return
		}

		// 写入后立即验证文件存在（防 Windows Defender 拦截）
		if info, err := os.Stat(dllPath); err != nil || info.Size() == 0 {
			wdErr = fmt.Errorf("WinDivert.dll 写入后丢失（可能被杀毒软件拦截）: %v", err)
			return
		}
		if info, err := os.Stat(sysPath); err != nil || info.Size() == 0 {
			wdErr = fmt.Errorf("WinDivert64.sys 写入后丢失（可能被杀毒软件拦截）: %v", err)
			return
		}
		log.Printf("[WinDivert] 驱动文件就绪: DLL=%d bytes, SYS=%d bytes",
			mustStatSize(dllPath), mustStatSize(sysPath))

		dll, err := windows.LoadDLL(dllPath)
		if err != nil {
			wdErr = fmt.Errorf("无法加载 WinDivert.dll: %w\n请确认以管理员权限运行", err)
			return
		}
		findProc := func(name string) *windows.Proc {
			p, e := dll.FindProc(name)
			if e != nil {
				wdErr = fmt.Errorf("找不到函数 %s: %w", name, e)
				return nil
			}
			return p
		}
		wdDLL = &winDivertDLL{
			dll:            dll,
			procOpen:       findProc("WinDivertOpen"),
			procRecv:       findProc("WinDivertRecv"),
			procSend:       findProc("WinDivertSend"),
			procClose:      findProc("WinDivertClose"),
			procCalcChecks: findProc("WinDivertHelperCalcChecksums"),
		}
	})
	return wdDLL, wdErr
}

// winDivertHandle 封装一个 HANDLE
type winDivertHandle struct {
	handle windows.Handle
	dll    *winDivertDLL
}

// wdOpen 打开 WinDivert 句柄（调用 WinDivertOpen）
func wdOpen(filter string, layer, priority int, flags uint64) (*winDivertHandle, error) {
	dll, err := loadWinDivert()
	if err != nil {
		return nil, err
	}

	wdDir := filepath.Join(getExeDir(), "gopass_wd")
	log.Printf("[WinDivert] Open: filter=%q, DLL/SYS dir=%s, CWD=%s", filter, wdDir, func() string {
		d, _ := os.Getwd()
		return d
	}())

	filterPtr, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}

	ret, _, eno := dll.procOpen.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
	)

	if ret == uintptr(windows.InvalidHandle) {
		return nil, fmt.Errorf("WinDivertOpen 失败: %w", eno)
	}

	return &winDivertHandle{handle: windows.Handle(ret), dll: dll}, nil
}

// Recv 读取一个拦截的数据包
func (h *winDivertHandle) Recv(buf []byte) (int, *winDivertAddress, error) {
	var addr winDivertAddress
	var recvLen uint32

	ret, _, eno := h.dll.procRecv.Call(
		uintptr(h.handle),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&recvLen)), // WinDivert 2.x: pRecvLen 是第 4 个参数
		uintptr(unsafe.Pointer(&addr)),    // WinDivert 2.x: pAddr 是第 5 个参数
	)
	if ret == 0 {
		return 0, nil, fmt.Errorf("WinDivertRecv: %w", eno)
	}
	return int(recvLen), &addr, nil
}

// Send 重新注入数据包
func (h *winDivertHandle) Send(pkt []byte, addr *winDivertAddress) error {
	var sentLen uint32
	ret, _, eno := h.dll.procSend.Call(
		uintptr(h.handle),
		uintptr(unsafe.Pointer(&pkt[0])),
		uintptr(len(pkt)),
		uintptr(unsafe.Pointer(&sentLen)), // WinDivert 2.x: pSentLen 是第 4 个参数
		uintptr(unsafe.Pointer(addr)),     // WinDivert 2.x: pAddr 是第 5 个参数
	)
	if ret == 0 {
		return fmt.Errorf("WinDivertSend: %w", eno)
	}
	return nil
}

// CalcChecksums 重新计算 IP/TCP/UDP 校验和
func (h *winDivertHandle) CalcChecksums(pkt []byte, addr *winDivertAddress) error {
	ret, _, eno := h.dll.procCalcChecks.Call(
		uintptr(unsafe.Pointer(&pkt[0])),
		uintptr(len(pkt)),
		uintptr(unsafe.Pointer(addr)),
		0,
	)
	if ret == 0 {
		return fmt.Errorf("WinDivertHelperCalcChecksums: %w", eno)
	}
	return nil
}

// Close 关闭句柄
func (h *winDivertHandle) Close() {
	if h.handle != windows.InvalidHandle {
		h.dll.procClose.Call(uintptr(h.handle))
		h.handle = windows.InvalidHandle
	}
}

// =============================================================================
// Interceptor：白名单拦截主逻辑
// =============================================================================

// Interceptor 拦截指定进程的流量，并重定向到本地 TProxy 端口
type Interceptor struct {
	handle      *winDivertHandle
	mu          sync.Mutex
	mode        string
	myPid       uint32
	upstreamPid uint32
	whitelist   []string
	tracker     *ConnTracker
	proxyIP     string
	proxyPort   uint16
	tproxyPort  uint16
	stopCh      chan struct{}
	stats       *Stats
}

// NewInterceptor 创建拦截器
func NewInterceptor(mode string, whitelist []string, tracker *ConnTracker, proxyIP string, proxyPort uint16, tproxyPort uint16, stats *Stats) *Interceptor {
	return &Interceptor{
		mode:       mode,
		myPid:      uint32(os.Getpid()),
		whitelist:  whitelist,
		tracker:    tracker,
		proxyIP:    proxyIP,
		proxyPort:  proxyPort,
		tproxyPort: tproxyPort,
		stopCh:     make(chan struct{}),
		stats:      stats,
	}
}

// buildFilter 动态构建 WinDivert 过滤字符串
// 仅拦截出站 TCP，排除 127.0.0.1 (具体进程在 handlePacket 中根据 PID 过滤)
func (i *Interceptor) buildFilter() string {
	// 拦截：
	// 1. 出站 TCP (准备劫持)
	// 2. 出站 IPv6 (防泄露，由于目前上游大多不走 v6，防止双栈解析回退直连)
	// 3. TProxy 返回的 TCP 包 (反向 NAT)
	// 注意：彻底删除了针对 UDP(QUIC) 443 的 Drop 规则，将兜底报 RST/ICMP 控制权还给操作系统，防止假死！
	filter := fmt.Sprintf("(outbound and ip and tcp and ip.DstAddr != 127.0.0.1) or "+
		"(outbound and ipv6) or "+
		"(outbound and ip and tcp and tcp.SrcPort == %d)", i.tproxyPort)

	if i.proxyIP != "" && i.proxyIP != "127.0.0.1" {
		filter += fmt.Sprintf(" and ip.DstAddr != %s", i.proxyIP)
	}

	return filter
}

// Start 启动拦截循环（阻塞）
func (i *Interceptor) Start() {
	log.Printf("[WinDivert] 正在启动... PID=%d（已排除自身，防止回环）", i.myPid)

	handle, err := wdOpen("false", layerNetwork, priorityDefault, 0)
	if err != nil {
		log.Printf("[WinDivert] ❌ 启动失败: %v", err)
		return
	}
	i.mu.Lock()
	i.handle = handle
	i.mu.Unlock()
	log.Println("[WinDivert] ✅ 驱动就绪，开始扫描白名单进程...")

	go i.filterUpdater()

	buf := make([]byte, 65535)
	for {
		select {
		case <-i.stopCh:
			return
		default:
		}

		i.mu.Lock()
		h := i.handle
		i.mu.Unlock()
		if h == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		n, addr, err := h.Recv(buf)
		if err != nil {
			select {
			case <-i.stopCh:
				return
			default:
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}

		if n <= 0 || n > len(buf) {
			continue
		}

		// [v1.1.9 CPU FIX #2] Removed `go i.handlePacket(...)`.
		// NEW: Synchronous call. handlePacket only does cached PID lookup + packet rewrite + Send.
		// [FIX 3] Zero-Alloc Optimization: since it's synchronous, we don't need to copy `buf`!
		i.handlePacket(buf[:n], addr)
	}
}

// filterUpdater - refreshes WinDivert filter every 5 seconds.
//
// [v1.1.8 CPU FIX] Atomic handle swap to prevent nil-gap spin.
// OLD: Close old handle first, then open new one. During the gap, i.handle == nil,
//
//	causing the main recv loop to spin at 100% CPU in the `continue` branch.
//
// NEW: Open new handle first, swap atomically, then close old handle. No nil gap ever.
func (i *Interceptor) filterUpdater() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	last := ""
	lastUpstreamPid := uint32(0)

	for {
		select {
		case <-i.stopCh:
			return
		case <-ticker.C:
			// 定期通过监听端口获取上游代理进程的 PID
			if pid, err := process.GetPidByPort(i.proxyPort); err == nil && pid != 0 {
				i.mu.Lock()
				if i.upstreamPid != pid {
					i.upstreamPid = pid
				}
				i.mu.Unlock()
				if pid != lastUpstreamPid {
					log.Printf("[WinDivert] 发现上游代理进程 PID: %d (端口 %d)", pid, i.proxyPort)
					lastUpstreamPid = pid
				}
			}

			f := i.buildFilter()
			if f == last {
				continue
			}
			log.Printf("[WinDivert] 更新过滤规则: %s", f)

			// 化震核心：先开新句柄 → 再关旧句柄
			// 这样主循环的 i.handle 永远不为 nil，彻底不存在空转窗口
			newH, err := wdOpen(f, layerNetwork, priorityDefault, 0)
			if err != nil {
				log.Printf("[WinDivert] 重新打开失败: %v", err)
				continue // 暖居，旧句柄不动
			}

			i.mu.Lock()
			oldH := i.handle
			i.handle = newH // 原子换手，主循环下一次 Recv 就会拿到新句柄
			i.mu.Unlock()

			// 关掉旧句柄（在换手之后，旧句柄上的 Recv 会因 Handle 已关闭而退出错误锯，不影响主循环）
			if oldH != nil {
				oldH.Close()
			}
			last = f
		}
	}
}

// handlePacket 修改包头目标地址 → 本地 TProxy，记录原始目标，重新注入
func (i *Interceptor) handlePacket(pkt []byte, addr *winDivertAddress) {
	if len(pkt) < 20 {
		return
	}
	ipHeaderLen := int(pkt[0]&0x0F) * 4
	if len(pkt) < ipHeaderLen+4 {
		return
	}

	origDstIP := make(net.IP, 4)
	copy(origDstIP, pkt[16:20])
	origSrcIP := make(net.IP, 4)
	copy(origSrcIP, pkt[12:16])
	tcpOffset := ipHeaderLen
	srcPort := binary.BigEndian.Uint16(pkt[tcpOffset : tcpOffset+2])
	origDstPort := binary.BigEndian.Uint16(pkt[tcpOffset+2 : tcpOffset+4])
	origDstIPStr := origDstIP.String()
	srcIP := net.IP(pkt[12:16]).String()

	// 拦截到 IPv6 包（因为 filter 加了 outbound and ipv6）
	// 直接静默丢弃不发回，暴力阻止本地环境泄露双栈请求
	isIPv6 := (pkt[0] >> 4) == 6
	if isIPv6 {
		return
	}

	// 先判断是否为 TProxy 发回的数据包（反向 NAT）
	if srcPort == i.tproxyPort {
		target, found := i.tracker.Get(origDstIP.String(), origDstPort)
		if !found {
			// 如果没找到跟踪记录，原样发回
			i.mu.Lock()
			h := i.handle
			i.mu.Unlock()
			if h != nil {
				h.Send(pkt, addr)
			}
			return
		}

		// 反向 NAT：TProxy (127.0.0.1:7893) -> App (127.0.0.1:AppPort)
		// 修改为：OrigDst (真实外网) -> OrigSrc (App内网IP:AppPort)
		copy(pkt[12:16], target.OrigDstIP.To4())
		binary.BigEndian.PutUint16(pkt[tcpOffset:tcpOffset+2], target.OrigDstPort)
		copy(pkt[16:20], target.OrigSrcIP.To4())

		if target.OrigSrcIP.IsLoopback() {
			addr.Bits |= uint32(flagOutbound) // Loopback packets are always outbound
			addr.Bits |= uint32(flagLoopback)
		} else {
			addr.Bits &= ^uint32(flagOutbound) // 改为入站接收 (Inbound)
			addr.Bits &= ^uint32(flagLoopback)
		}
		addr.IfIdx = target.OrigIfIdx
		addr.SubIfIdx = target.OrigSubIfIdx

		i.mu.Lock()
		h := i.handle
		i.mu.Unlock()
		if h == nil {
			return
		}

		if err := h.CalcChecksums(pkt, addr); err != nil {
			log.Printf("[WinDivert] 反向 NAT 计算校验和失败: %v", err)
			return
		}
		if err := h.Send(pkt, addr); err != nil {
			log.Printf("[WinDivert] 反向 NAT Send 失败: %v", err)
		}
		return
	}

	// 1. 获取该端口所属 PID
	pid, _ := process.GetPidByPort(srcPort)

	if pid == 0 || pid == i.myPid {
		// 无法识别或自身流量，直接发回（不修改）
		i.mu.Lock()
		h := i.handle
		i.mu.Unlock()
		if h != nil {
			h.Send(pkt, addr)
		}
		return
	}

	// 2. 检查策略
	isAllowed := false
	matchedName := ""

	i.mu.Lock()
	mode := i.mode
	whitelist := make([]string, len(i.whitelist))
	copy(whitelist, i.whitelist)
	upstreamPid := i.upstreamPid
	i.mu.Unlock()

	if mode == "global" {
		// 全局模式下，如果抓到的包是上游代理自己发出的，直接放行，避免死循环
		if upstreamPid != 0 && pid == upstreamPid {
			isAllowed = false
		} else {
			isAllowed = true
			matchedName = process.GetNameByPID(pid)
		}
	} else {
		// 性能优化核心点：先获取包所属的进程名（已完全缓存）
		pName := process.GetNameByPID(pid)
		pNameLower := strings.ToLower(pName)

		// 然后对比白名单，大幅减少循环和重复的系统快照调用
		for _, name := range whitelist {
			if strings.ToLower(name) == pNameLower {
				isAllowed = true
				matchedName = name
				break
			}
		}
	}

	if !isAllowed {
		// 未在白名单，或者被旁路，上报直连统计
		if i.stats != nil {
			targetAddr := fmt.Sprintf("%s:%d", origDstIPStr, origDstPort)
			id := fmt.Sprintf("%s:%d", srcIP, srcPort)
			// 如果没有名字，获取一下
			if matchedName == "" {
				matchedName = process.GetNameByPID(pid)
			}
			i.stats.ReportDirect(id, matchedName, targetAddr, origDstIPStr)
		}

		// 直接原样发回
		i.mu.Lock()
		h := i.handle
		i.mu.Unlock()
		if h != nil {
			h.Send(pkt, addr)
		}
		return
	}

	log.Printf("[WinDivert] 劫持进程 %s (PID %d): %s:%d -> %s:%d", matchedName, pid, srcIP, srcPort, origDstIPStr, origDstPort)

	// 记录原始目标（连接跟踪）
	// 注意：我们将包的源 IP 也改为 127.0.0.1 以确保本地监听器能正确接收，
	// 并在 tracker 中完整记录真实的 OrigSrcIP 和 OrigDstIP
	origIfIdx := addr.IfIdx
	origSubIfIdx := addr.SubIfIdx
	i.tracker.Set("127.0.0.1", srcPort, origSrcIP, srcPort, origDstIP, origDstPort, origIfIdx, origSubIfIdx, matchedName)

	// 修改源 IP 为 127.0.0.1 (重要：为了让本地 Socket 接受，建议源和目的一致)
	copy(pkt[12:16], net.IPv4(127, 0, 0, 1).To4())
	// 修改目标 IP 为 127.0.0.1
	copy(pkt[16:20], net.IPv4(127, 0, 0, 1).To4())
	// 修改目标端口为本地 TProxy
	binary.BigEndian.PutUint16(pkt[tcpOffset+2:tcpOffset+4], i.tproxyPort)

	// 修正标志位 (WinDivert 2.x 位域操作)
	// 如果是注入到本地 127.0.0.1，必须设置 Outbound 和 Loopback
	addr.Bits |= uint32(flagOutbound) // 必须是 Outbound
	addr.Bits |= uint32(flagLoopback) // 必须是 Loopback

	i.mu.Lock()
	h := i.handle
	i.mu.Unlock()
	if h == nil {
		return
	}

	// 重新计算校验和
	if err := h.CalcChecksums(pkt, addr); err != nil {
		log.Printf("[WinDivert] CalcChecksums 失败: %v", err)
		return
	}
	// 重新注入
	if err := h.Send(pkt, addr); err != nil {
		log.Printf("[WinDivert] Send 失败: %v", err)
	}
}

// SetMode 动态更新代理模式
func (i *Interceptor) SetMode(mode string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.mode = mode
	log.Printf("[WinDivert] 工作模式已切换为: %s", mode)
}

// SetWhitelist 动态更新白名单
func (i *Interceptor) SetWhitelist(whitelist []string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.whitelist = whitelist
	log.Printf("[WinDivert] 白名单规则已更新: %v", whitelist)
}

// Close 停止拦截
func (i *Interceptor) Close() {
	close(i.stopCh)
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.handle != nil {
		i.handle.Close()
		i.handle = nil
	}
}
