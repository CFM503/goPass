package engine

// WinDivert 纯 Go 实现 - 通过 Windows syscall 动态加载 WinDivert.dll
// 无需 CGo、无需头文件、无需 .lib 文件
// 参考文档：https://reqrypt.org/windivert-doc.html

import (
	"bytes"
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

// stopAndRemoveService 停止并删除指定的内核驱动服务
// 关键修复：正确处理 "marked for deletion" 状态，确保关闭所有句柄后等待 SCM 真正移除服务
func stopAndRemoveService(name string) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_CREATE_SERVICE)
	if err != nil {
		log.Printf("[WinDivert] 打开服务管理器失败: %v（需要管理员权限）", err)
		return
	}
	defer windows.CloseServiceHandle(scm)
	svc, err := windows.OpenService(scm, syscall.StringToUTF16Ptr(name), windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS|windows.DELETE)
	if err != nil {
		// 服务不存在是正常的
		return
	}
	// 注意：不使用 defer，而是在需要时手动关闭，以便 SCM 能完成延迟删除
	var status windows.SERVICE_STATUS
	if err := windows.ControlService(svc, windows.SERVICE_CONTROL_STOP, &status); err != nil {
		// 如果服务本就已经停止，ControlService 会报错，在此忽略即可
	}
	// 等待驱动停止，最多 5 秒（内核驱动释放文件需要时间）
	stopped := false
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		if err := windows.QueryServiceStatus(svc, &status); err != nil {
			stopped = true
			break
		}
		if status.CurrentState == windows.SERVICE_STOPPED {
			stopped = true
			break
		}
	}
	if !stopped {
		log.Printf("[WinDivert] 驱动服务 %s 未能在 5 秒内停止（当前状态: %d）", name, status.CurrentState)
	}
	// 删除旧服务，确保下次 WinDivertOpen 会用新路径重新注册
	deleteErr := windows.DeleteService(svc)
	if deleteErr != nil {
		log.Printf("[WinDivert] 删除服务 %s 注册失败: %v", name, deleteErr)
	} else {
		log.Printf("[WinDivert] 已清理旧的驱动服务注册: %s", name)
	}

	// 关键修复：立即关闭服务句柄，让 SCM 能完成延迟删除
	// Windows SCM 只有在所有打开该服务的句柄都关闭后，才会真正删除 "marked for deletion" 的服务
	windows.CloseServiceHandle(svc)

	// 等待服务真正从 SCM 中消失（最多 15 秒）
	// 只有服务完全消失，内核才会释放对 .sys 文件的锁定
	for i := 0; i < 30; i++ {
		checkSvc, checkErr := windows.OpenService(scm, syscall.StringToUTF16Ptr(name), windows.SERVICE_QUERY_STATUS)
		if checkErr != nil {
			// 服务已不存在 → 删除完成
			if i > 0 {
				log.Printf("[WinDivert] 服务 %s 已从 SCM 中完全移除", name)
			}
			break
		}
		windows.CloseServiceHandle(checkSvc)
		if i == 0 {
			log.Printf("[WinDivert] 等待服务 %s 从 SCM 中完全移除...", name)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// 服务停止后，内核可能需要额外时间释放文件句柄
	if stopped {
		time.Sleep(500 * time.Millisecond)
	}
}

// stopAndRemoveWinDivertDriver 停止并删除 WinDivert 和 WinDivert14 内核驱动服务，释放 SYS 文件锁
// 关键：必须删除旧服务，否则 WinDivert DLL 会复用旧的 BINARY_PATH_NAME（指向已不存在的路径）
func stopAndRemoveWinDivertDriver() {
	stopAndRemoveService("WinDivert")
	stopAndRemoveService("WinDivert14")
}

// CleanUpDependencies 停止并删除 WinDivert 驱动服务，并清理当前目录下的依赖文件
func CleanUpDependencies() {
	log.Println("[WinDivert] 正在执行运行前依赖项清理...")
	stopAndRemoveWinDivertDriver()

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	dllPath := filepath.Join(cwd, "WinDivert.dll")
	sysPath := filepath.Join(cwd, "WinDivert64.sys")
	tmpPath := filepath.Join(cwd, "WinDivert64.sys.tmp")

	// 尝试清理 DLL 和 SYS 文件
	if err := os.Remove(dllPath); err == nil {
		log.Println("[WinDivert] 已清理旧的 WinDivert.dll")
	}
	if err := os.Remove(sysPath); err == nil {
		log.Println("[WinDivert] 已清理旧的 WinDivert64.sys")
	}
	if err := os.Remove(tmpPath); err == nil {
		log.Println("[WinDivert] 已清理旧的 WinDivert64.sys.tmp")
	}
}

// fileContentMatch 检查文件内容是否与给定数据完全一致
func fileContentMatch(path string, data []byte) bool {
	existing, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return bytes.Equal(existing, data)
}

// CleanUpOnShutdown 在程序退出时彻底清理 WinDivert 驱动和文件
// 确保下次启动不会遇到残留的驱动锁定
func CleanUpOnShutdown() {
	log.Println("[WinDivert] 正在执行关闭清理...")
	// 释放 DLL（如果已加载），以解除对 DLL 文件的锁定
	if wdDLL != nil && wdDLL.dll != nil {
		wdDLL.dll.Release()
		wdDLL = nil
	}
	// 停止并删除内核驱动服务
	stopAndRemoveWinDivertDriver()
	// 清理释放的文件
	cwd, err := os.Getwd()
	if err != nil {
		return
	}
	os.Remove(filepath.Join(cwd, "WinDivert.dll"))
	os.Remove(filepath.Join(cwd, "WinDivert64.sys"))
	os.Remove(filepath.Join(cwd, "WinDivert64.sys.tmp"))
	log.Println("[WinDivert] 关闭清理完成")
}

// extractSysFile 释放 WinDivert64.sys，使用多种策略处理文件锁定
// 策略 1: 直接 os.WriteFile（覆盖写入）
// 策略 2: os.OpenFile O_WRONLY|O_TRUNC（仅截断，不删除）
// 策略 3: 写入临时文件 + MoveFileEx 原子替换
func extractSysFile(targetPath string, data []byte) error {
	// 策略 1: 直接写入（如果文件不存在或未被锁定，这会成功）
	if err := os.WriteFile(targetPath, data, 0755); err == nil {
		log.Printf("[WinDivert] SYS 文件直接写入成功")
		return nil
	} else {
		log.Printf("[WinDivert] 直接写入失败: %v", err)
	}

	// 策略 2: 尝试以写入+截断模式打开（不删除文件，仅覆盖内容）
	if f, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_TRUNC, 0755); err == nil {
		if _, err := f.Write(data); err == nil {
			f.Close()
			log.Printf("[WinDivert] SYS 文件截断写入成功")
			return nil
		}
		f.Close()
		log.Printf("[WinDivert] 截断写入失败: %v", err)
	} else {
		log.Printf("[WinDivert] 以写入模式打开失败: %v", err)
	}

	// 策略 3: 写入临时文件 + MoveFileEx 原子替换
	// Windows 上 MoveFileEx 可以替换被其他进程以 FILE_SHARE_READ 打开的文件
	tmpPath := targetPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0755); err != nil {
		return fmt.Errorf("写入临时文件失败: %w", err)
	}

	// MOVEFILE_REPLACE_EXISTING = 1, MOVEFILE_COPY_ALLOWED = 2
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	moveFileEx := kernel32.NewProc("MoveFileExW")
	srcPtr, _ := syscall.UTF16PtrFromString(tmpPath)
	dstPtr, _ := syscall.UTF16PtrFromString(targetPath)
	ret, _, err := moveFileEx.Call(
		uintptr(unsafe.Pointer(srcPtr)),
		uintptr(unsafe.Pointer(dstPtr)),
		uintptr(1|2), // MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED
	)
	if ret != 0 {
		log.Printf("[WinDivert] SYS 文件原子替换成功")
		return nil
	}

	// 清理临时文件
	os.Remove(tmpPath)
	return fmt.Errorf("所有策略均失败（直接写入、截断写入、原子替换），最后错误: %w\n"+
		"文件可能被杀毒软件独占锁定，请将 %s 目录加入白名单", err, filepath.Dir(targetPath))
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

		// 释放嵌入的 WinDivert 文件到运行的当前目录
		wdDir, err := os.Getwd()
		if err != nil {
			wdDir = "."
		}
		dllPath := filepath.Join(wdDir, "WinDivert.dll")
		sysPath := filepath.Join(wdDir, "WinDivert64.sys")

		log.Printf("[WinDivert] 释放驱动到: %s", wdDir)

		// 关键优化：先检查现有文件内容是否与嵌入内容一致
		// 如果内容相同，完全跳过写入操作，从根本上避免文件锁冲突
		dllMatch := fileContentMatch(dllPath, windivertDLL)
		sysMatch := fileContentMatch(sysPath, windivertSYS)

		if dllMatch && sysMatch {
			log.Printf("[WinDivert] 驱动文件内容一致，跳过重新释放")
		} else {
			// 需要更新文件，先尝试清理旧的 SYS 文件
			if !sysMatch {
				for i := 0; i < 15; i++ {
					os.Remove(sysPath)
					if _, err := os.Stat(sysPath); os.IsNotExist(err) {
						log.Printf("[WinDivert] 旧驱动文件已释放")
						break
					}
					if i > 0 && i%3 == 0 {
						log.Printf("[WinDivert] 文件仍被锁定，重试停止驱动服务...")
						stopAndRemoveWinDivertDriver()
					}
					log.Printf("[WinDivert] 等待旧驱动文件释放... (%d/15)", i+1)
					time.Sleep(1 * time.Second)
				}
			}

			// DLL 文件写入
			if !dllMatch {
				os.Remove(dllPath)
				if err := os.WriteFile(dllPath, windivertDLL, 0755); err != nil {
					wdErr = fmt.Errorf("无法释放 WinDivert.dll: %w", err)
					return
				}
			}

			// SYS 文件写入（可能被内核锁定，尝试多种策略）
			if !sysMatch {
				if err := extractSysFile(sysPath, windivertSYS); err != nil {
					// 最后防线：写入失败但文件已存在且内容匹配（可能其他实例已写入），也算成功
					if fileContentMatch(sysPath, windivertSYS) {
						log.Printf("[WinDivert] SYS 文件写入失败但内容已匹配，继续加载")
					} else {
						wdErr = fmt.Errorf("无法释放 WinDivert64.sys: %w\n"+
							"可能原因：杀毒软件正在扫描，或内核驱动未完全释放\n"+
							"请将当前目录加入杀毒软件白名单后重试，或重启系统", err)
						return
					}
				}
			}
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

	wdDir, err := os.Getwd()
	if err != nil {
		wdDir = "."
	}
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

// Interceptor 拦截受控进程/分流范围内的流量，并重定向到本地 TProxy / DNS 中继
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
	dnsRelayPort uint16
	router       *Router
	stopCh       chan struct{}
	stats        *Stats
	lastLog      time.Time // 日志限流
}

// NewInterceptor 创建拦截器
func NewInterceptor(mode string, whitelist []string, tracker *ConnTracker, proxyIP string, proxyPort uint16, tproxyPort uint16, stats *Stats, router *Router) *Interceptor {
	var dnsPort uint16
	if router != nil && router.SplitEnabled() && router.DNSRelayPort() > 0 {
		dnsPort = uint16(router.DNSRelayPort())
	}
	return &Interceptor{
		mode:         mode,
		myPid:        uint32(os.Getpid()),
		whitelist:    whitelist,
		tracker:      tracker,
		proxyIP:      proxyIP,
		proxyPort:    proxyPort,
		tproxyPort:   tproxyPort,
		dnsRelayPort: dnsPort,
		router:       router,
		stopCh:       make(chan struct{}),
		stats:        stats,
	}
}

// SetDNSRelayPort 热更新 DNS 中继端口（0=关闭 DNS 劫持）。
func (i *Interceptor) SetDNSRelayPort(port uint16) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.dnsRelayPort != port {
		i.dnsRelayPort = port
		log.Printf("[WinDivert] DNS 中继端口已更新: %d", port)
	}
}

// buildFilter 动态构建 WinDivert 过滤字符串
// 拦截：
//  1. 出站 TCP (准备劫持)
//  2. 出站 UDP 443 (QUIC 拦截，防双栈泄漏)
//  3. 出站 UDP 53 (DNS 劫持，防 DNS 泄漏) —— 分流开启且 DNS 中继启用时
//  4. DNS 中继回包 (反向 NAT)
//  5. 出站 IPv6 (防 IPv6 泄漏，可配置)
//  6. TProxy 返回的 TCP 包 (反向 NAT)
func (i *Interceptor) buildFilter() string {
	blockIPv6 := true
	dnsPort := uint16(0)
	if i.router != nil {
		blockIPv6 = i.router.BlockIPv6()
		if i.router.SplitEnabled() && i.router.DNSRelayPort() > 0 {
			dnsPort = uint16(i.router.DNSRelayPort())
		}
	}

	parts := []string{
		"(outbound and ip and tcp and ip.DstAddr != 127.0.0.1)",
		fmt.Sprintf("(outbound and ip and tcp and tcp.SrcPort == %d)", i.tproxyPort),
		"(outbound and ip and udp and udp.DstPort == 443)",
	}
	if blockIPv6 {
		parts = append(parts, "(outbound and ipv6)")
	}
	if dnsPort != 0 {
		parts = append(parts, "(outbound and ip and udp and udp.DstPort == 53)")
		parts = append(parts, fmt.Sprintf("(outbound and ip and udp and udp.SrcPort == %d)", dnsPort))
	}
	filter := strings.Join(parts, " or ")

	if i.proxyIP != "" && i.proxyIP != "127.0.0.1" {
		filter += fmt.Sprintf(" and ip.DstAddr != %s", i.proxyIP)
	}

	return filter
}

// Start 启动拦截循环（阻塞）
func (i *Interceptor) Start() {
	log.Printf("[WinDivert] 正在启动... PID=%d（已排除自身，防止回环）", i.myPid)

	// 直接以真实过滤规则打开，避免启动窗口期（filter 为 false）流量裸奔泄漏
	handle, err := wdOpen(i.buildFilter(), layerNetwork, priorityDefault, 0)
	if err != nil {
		log.Printf("[WinDivert] ❌ 启动失败: %v", err)
		return
	}
	i.mu.Lock()
	i.handle = handle
	i.mu.Unlock()
	log.Println("[WinDivert] ✅ 驱动就绪，开始扫描拦截...")

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

// handlePacket 修改包头目标地址 → 本地 TProxy / DNS 中继，记录原始目标，重新注入
func (i *Interceptor) handlePacket(pkt []byte, addr *winDivertAddress) {
	if len(pkt) < 20 {
		return
	}
	ipHeaderLen := int(pkt[0]&0x0F) * 4
	if len(pkt) < ipHeaderLen+4 {
		return
	}

	// IPv6：按 block_ipv6 配置屏蔽（零 IPv6 泄漏）或放行
	if (pkt[0] >> 4) == 6 {
		if i.shouldBlockIPv6() {
			return // 静默丢弃，暴力阻止本地环境泄露双栈请求
		}
		i.sendPass(pkt, addr)
		return
	}

	origDstIP := make(net.IP, 4)
	copy(origDstIP, pkt[16:20])
	origSrcIP := make(net.IP, 4)
	copy(origSrcIP, pkt[12:16])
	srcPort := binary.BigEndian.Uint16(pkt[ipHeaderLen : ipHeaderLen+2])
	origDstPort := binary.BigEndian.Uint16(pkt[ipHeaderLen+2 : ipHeaderLen+4])
	origDstIPStr := origDstIP.String()
	srcIP := net.IP(pkt[12:16]).String()
	isUDP := pkt[9] == 17

	// 反向 NAT：TProxy / DNS 中继 发回应用的数据包
	if srcPort == i.tproxyPort || (isUDP && i.dnsRelayPort != 0 && srcPort == i.dnsRelayPort) {
		i.reverseNAT(pkt, addr, ipHeaderLen)
		return
	}

	// 自身流量直接放行
	pid, _ := process.GetPidByPort(srcPort)
	if pid == 0 || pid == i.myPid {
		i.sendPass(pkt, addr)
		return
	}

	i.mu.Lock()
	mode := i.mode
	upstreamPid := i.upstreamPid
	proxyIP := i.proxyIP
	i.mu.Unlock()

	// 上游代理自身流量放行（防回环）
	if upstreamPid != 0 && pid == upstreamPid {
		i.sendPass(pkt, addr)
		return
	}
	if proxyIP != "" && origDstIPStr == proxyIP {
		i.sendPass(pkt, addr)
		return
	}

	// 私有/本地目标一律不劫持（LAN 流量直连，绝不上代理）
	if isPrivateOrLocal(origDstIP) {
		i.sendPass(pkt, addr)
		return
	}

	pName := process.GetNameByPID(pid)
	router := i.router
	splitOn := router != nil && router.SplitEnabled()

	if isUDP {
		i.handleUDP(pkt, addr, pid, pName, origSrcIP, origDstIP, origDstPort, srcPort, ipHeaderLen, splitOn, router)
		return
	}

	// ---- TCP：决定是否劫持到 TProxy ----
	hijack := false
	matchedName := ""
	if splitOn {
		if router.InterceptScope(pName) {
			hijack = true
			matchedName = pName
		}
	} else {
		// 原有进程白名单逻辑
		if mode == "global" {
			hijack = true
			matchedName = pName
		} else {
			i.mu.Lock()
			whitelist := make([]string, len(i.whitelist))
			copy(whitelist, i.whitelist)
			i.mu.Unlock()
			for _, name := range whitelist {
				if strings.EqualFold(name, pName) {
					hijack = true
					matchedName = name
					break
				}
			}
		}
	}

	if !hijack {
		// 未纳入分流管控，上报直连统计并原样放行
		if i.stats != nil {
			targetAddr := fmt.Sprintf("%s:%d", origDstIPStr, origDstPort)
			id := fmt.Sprintf("%s:%d", srcIP, srcPort)
			if matchedName == "" {
				matchedName = pName
			}
			i.stats.ReportDirect(id, matchedName, targetAddr, origDstIPStr)
		}
		i.sendPass(pkt, addr)
		return
	}

	// 分流开启时劫持量很大，限流记录；原有白名单模式保持每次劫持都记录
	if splitOn {
		i.logLimited("[WinDivert] 劫持 %s (PID %d): %s:%d -> %s:%d", pName, pid, srcIP, srcPort, origDstIPStr, origDstPort)
	} else {
		log.Printf("[WinDivert] 劫持进程 %s (PID %d): %s:%d -> %s:%d", matchedName, pid, srcIP, srcPort, origDstIPStr, origDstPort)
	}
	i.hijackTCP(pkt, addr, origSrcIP, origDstIP, origDstPort, srcPort, ipHeaderLen, matchedName)
}

// handleUDP 处理出站 UDP：
//   - 分流开启：DNS(53) 劫持到中继；国外 UDP 一律丢弃（QUIC/STUN/TURN 零泄漏）；中国 UDP 放行
//   - 原有逻辑：白名单进程的 UDP 443 (QUIC) 丢弃，强制回退 TCP
func (i *Interceptor) handleUDP(pkt []byte, addr *winDivertAddress, pid uint32, pName string, origSrcIP, origDstIP net.IP, origDstPort, srcPort uint16, ipHeaderLen int, splitOn bool, router *Router) {
	if splitOn {
		inScope := router.InterceptScope(pName)

		// DNS 劫持到本地中继（零系统 DNS 泄漏）
		if inScope && origDstPort == 53 && router.DNSRelayPort() > 0 {
			i.hijackToDNSRelay(pkt, addr, origSrcIP, origDstIP, origDstPort, srcPort, ipHeaderLen, pName)
			return
		}
		if !inScope {
			i.sendPass(pkt, addr)
			return
		}
		// 国外 UDP（QUIC/HTTP3、STUN/TURN、游戏等）一律丢弃 —— 零中国痕迹
		if router.BlockForeignUDP() && router.IsForeignIP(origDstIP) {
			i.logLimited("[WinDivert] 丢弃国外 UDP (%s pid=%d) -> %s:%d", pName, pid, origDstIP.String(), origDstPort)
			return
		}
		i.sendPass(pkt, addr)
		return
	}

	// 原有逻辑：白名单/全局进程的 UDP 443 (QUIC) 丢弃，强制浏览器回退 TCP HTTP/2
	i.mu.Lock()
	mode := i.mode
	whitelist := make([]string, len(i.whitelist))
	copy(whitelist, i.whitelist)
	i.mu.Unlock()

	allowed := false
	if mode == "global" {
		allowed = true
	} else {
		for _, name := range whitelist {
			if strings.EqualFold(name, pName) {
				allowed = true
				break
			}
		}
	}
	if allowed && origDstPort == 443 {
		i.logLimited("[WinDivert] 丢弃受控进程 QUIC UDP (%s pid=%d) -> %s:%d", pName, pid, origDstIP.String(), origDstPort)
		return
	}
	i.sendPass(pkt, addr)
}

// hijackTCP 记录连接跟踪并改写 TCP 报文 → 本地 TProxy
func (i *Interceptor) hijackTCP(pkt []byte, addr *winDivertAddress, origSrcIP, origDstIP net.IP, origDstPort, srcPort uint16, ipHeaderLen int, processName string) {
	origIfIdx := addr.IfIdx
	origSubIfIdx := addr.SubIfIdx
	i.tracker.Set("127.0.0.1", srcPort, origSrcIP, srcPort, origDstIP, origDstPort, origIfIdx, origSubIfIdx, processName)

	// 修改源 IP 为 127.0.0.1（本地 Socket 才能接收）
	copy(pkt[12:16], net.IPv4(127, 0, 0, 1).To4())
	// 修改目标 IP 为 127.0.0.1
	copy(pkt[16:20], net.IPv4(127, 0, 0, 1).To4())
	// 修改目标端口为本地 TProxy
	binary.BigEndian.PutUint16(pkt[ipHeaderLen+2:ipHeaderLen+4], i.tproxyPort)

	// 注入到本地 127.0.0.1，必须设置 Outbound 和 Loopback
	addr.Bits |= uint32(flagOutbound)
	addr.Bits |= uint32(flagLoopback)

	if err := i.calcAndSend(pkt, addr); err != nil {
		log.Printf("[WinDivert] 劫持 TCP 注入失败: %v", err)
	}
}

// hijackToDNSRelay 记录连接跟踪并改写 UDP 53 报文 → 本地 DNS 中继
func (i *Interceptor) hijackToDNSRelay(pkt []byte, addr *winDivertAddress, origSrcIP, origDstIP net.IP, origDstPort, srcPort uint16, ipHeaderLen int, processName string) {
	origIfIdx := addr.IfIdx
	origSubIfIdx := addr.SubIfIdx
	i.tracker.Set("127.0.0.1", srcPort, origSrcIP, srcPort, origDstIP, origDstPort, origIfIdx, origSubIfIdx, processName)

	copy(pkt[12:16], net.IPv4(127, 0, 0, 1).To4())
	copy(pkt[16:20], net.IPv4(127, 0, 0, 1).To4())
	binary.BigEndian.PutUint16(pkt[ipHeaderLen+2:ipHeaderLen+4], i.dnsRelayPort)

	addr.Bits |= uint32(flagOutbound)
	addr.Bits |= uint32(flagLoopback)

	if err := i.calcAndSend(pkt, addr); err != nil {
		log.Printf("[WinDivert] DNS 劫持注入失败: %v", err)
	}
}

// reverseNAT 反向 NAT：TProxy/DNS中继 (127.0.0.1:port) -> App (127.0.0.1:AppPort)
// 改写为：OrigDst (真实外网/DNS) -> OrigSrc (App 真实 IP:AppPort)
func (i *Interceptor) reverseNAT(pkt []byte, addr *winDivertAddress, ipHeaderLen int) {
	dstIP := net.IP(pkt[16:20])
	dstPort := binary.BigEndian.Uint16(pkt[ipHeaderLen+2 : ipHeaderLen+4])
	target, found := i.tracker.Get(dstIP.String(), dstPort)
	if !found {
		// 没有跟踪记录，原样发回
		i.sendPass(pkt, addr)
		return
	}

	copy(pkt[12:16], target.OrigDstIP.To4())
	binary.BigEndian.PutUint16(pkt[ipHeaderLen:ipHeaderLen+2], target.OrigDstPort)
	copy(pkt[16:20], target.OrigSrcIP.To4())
	binary.BigEndian.PutUint16(pkt[ipHeaderLen+2:ipHeaderLen+4], target.OrigSrcPort)

	if target.OrigSrcIP.IsLoopback() {
		addr.Bits |= uint32(flagOutbound)
		addr.Bits |= uint32(flagLoopback)
	} else {
		addr.Bits &= ^uint32(flagOutbound) // 改为入站接收 (Inbound)
		addr.Bits &= ^uint32(flagLoopback)
	}
	addr.IfIdx = target.OrigIfIdx
	addr.SubIfIdx = target.OrigSubIfIdx

	if err := i.calcAndSend(pkt, addr); err != nil {
		log.Printf("[WinDivert] 反向 NAT 注入失败: %v", err)
	}
}

// calcAndSend 重新计算校验和并注入数据包。
func (i *Interceptor) calcAndSend(pkt []byte, addr *winDivertAddress) error {
	i.mu.Lock()
	h := i.handle
	i.mu.Unlock()
	if h == nil {
		return fmt.Errorf("WinDivert 句柄未就绪")
	}
	if err := h.CalcChecksums(pkt, addr); err != nil {
		return fmt.Errorf("CalcChecksums 失败: %w", err)
	}
	if err := h.Send(pkt, addr); err != nil {
		return fmt.Errorf("Send 失败: %w", err)
	}
	return nil
}

// sendPass 原样放行数据包。
func (i *Interceptor) sendPass(pkt []byte, addr *winDivertAddress) {
	i.mu.Lock()
	h := i.handle
	i.mu.Unlock()
	if h != nil {
		h.Send(pkt, addr)
	}
}

// shouldBlockIPv6 是否屏蔽全部出站 IPv6。
func (i *Interceptor) shouldBlockIPv6() bool {
	if i.router != nil && i.router.SplitEnabled() {
		return i.router.BlockIPv6()
	}
	// 未开启分流时保持原有行为：一律丢弃 IPv6
	return true
}

// logLimited 日志限流（最多每 10 秒一条），避免刷屏。
func (i *Interceptor) logLimited(format string, args ...interface{}) {
	i.mu.Lock()
	defer i.mu.Unlock()
	now := time.Now()
	if now.Sub(i.lastLog) < 10*time.Second {
		return
	}
	i.lastLog = now
	log.Printf(format, args...)
}

// isPrivateOrLocal 判断目标 IP 是否为私网/本地/组播地址（这类流量绝不上代理）。
func isPrivateOrLocal(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return true
	}
	b := v4
	switch {
	case b[0] == 0: // 0.0.0.0/8
		return true
	case b[0] == 10: // 10/8
		return true
	case b[0] == 127: // 回环
		return true
	case b[0] == 169 && b[1] == 254: // 链路本地 169.254/16
		return true
	case b[0] == 172 && b[1] >= 16 && b[1] <= 31: // 172.16/12
		return true
	case b[0] == 192 && b[1] == 168: // 192.168/16
		return true
	case b[0] == 100 && b[1] >= 64 && b[1] <= 127: // CGNAT 100.64/10
		return true
	case b[0] == 198 && b[1] == 18: // 198.18/15 (fake-IP / benchmark)
		return true
	case b[0] == 192 && b[1] == 0 && b[2] == 0: // 192.0.0/24
		return true
	case b[0] >= 224: // 组播 + 保留
		return true
	}
	return false
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
