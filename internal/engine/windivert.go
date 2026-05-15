package engine

// WinDivert 纯 Go 实现 - 通过 Windows syscall 动态加载 WinDivert.dll
// 无需 CGo、无需头文件、无需 .lib 文件
// 参考文档：https://reqrypt.org/windivert-doc.html

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/yourusername/gopass/internal/process"
	"golang.org/x/sys/windows"
)

const (
	layerNetwork    = 0
	priorityDefault = 0
	flagSniff       = 1
)

type winDivertAddress struct {
	Timestamp int64
	Bits      uint32
	Reserved2 uint32
	IfIdx     uint32
	SubIfIdx  uint32
	Data      [60]byte
}

const (
	flagOutbound = 1 << 17
	flagLoopback = 1 << 18
)

// loopbackIP 预分配的 127.0.0.1，避免 net.IPv4().To4() 每次分配
var loopbackIP = [4]byte{127, 0, 0, 1}

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

func loadWinDivert() (*winDivertDLL, error) {
	wdOnce.Do(func() {
		dll, err := windows.LoadDLL("WinDivert.dll")
		if err != nil {
			wdErr = fmt.Errorf("无法加载 WinDivert.dll: %w\n请确认 WinDivert.dll 与 gopass.exe 在同一目录，且以管理员权限运行", err)
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

type winDivertHandle struct {
	handle windows.Handle
	dll    *winDivertDLL
}

func wdOpen(filter string, layer, priority int, flags uint64) (*winDivertHandle, error) {
	dll, err := loadWinDivert()
	if err != nil {
		return nil, err
	}

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

func (h *winDivertHandle) Recv(buf []byte) (int, *winDivertAddress, error) {
	var addr winDivertAddress
	var recvLen uint32

	ret, _, eno := h.dll.procRecv.Call(
		uintptr(h.handle),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&recvLen)),
		uintptr(unsafe.Pointer(&addr)),
	)
	if ret == 0 {
		return 0, nil, fmt.Errorf("WinDivertRecv: %w", eno)
	}
	return int(recvLen), &addr, nil
}

func (h *winDivertHandle) Send(pkt []byte, addr *winDivertAddress) error {
	var sentLen uint32
	ret, _, eno := h.dll.procSend.Call(
		uintptr(h.handle),
		uintptr(unsafe.Pointer(&pkt[0])),
		uintptr(len(pkt)),
		uintptr(unsafe.Pointer(&sentLen)),
		uintptr(unsafe.Pointer(addr)),
	)
	if ret == 0 {
		return fmt.Errorf("WinDivertSend: %w", eno)
	}
	return nil
}

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

func (h *winDivertHandle) Close() {
	if h.handle != windows.InvalidHandle {
		h.dll.procClose.Call(uintptr(h.handle))
		h.handle = windows.InvalidHandle
	}
}

// =============================================================================
// Interceptor：白名单拦截主逻辑（性能优化版）
// =============================================================================

type modeConfig struct {
	mode      string
	whitelist map[string]struct{}
}

type Interceptor struct {
	handle atomic.Pointer[winDivertHandle]

	modeCfg atomic.Pointer[modeConfig]

	myPid       uint32
	upstreamPid atomic.Uint32
	tracker     *ConnTracker
	proxyIP     string
	proxyPort   uint16
	tproxyPort  uint16
	stopCh      chan struct{}
	stats       *Stats

	hijackLogMu sync.Mutex
	hijackLog   map[string]time.Time
}

func NewInterceptor(mode string, whitelist []string, tracker *ConnTracker, proxyIP string, proxyPort uint16, tproxyPort uint16, stats *Stats) *Interceptor {
	m := make(map[string]struct{}, len(whitelist))
	for _, name := range whitelist {
		m[name] = struct{}{}
	}
	i := &Interceptor{
		myPid:      uint32(os.Getpid()),
		tracker:    tracker,
		proxyIP:    proxyIP,
		proxyPort:  proxyPort,
		tproxyPort: tproxyPort,
		stopCh:     make(chan struct{}),
		stats:      stats,
		hijackLog:  make(map[string]time.Time),
	}
	cfg := &modeConfig{mode: mode, whitelist: m}
	i.modeCfg.Store(cfg)
	return i
}

func (i *Interceptor) setWhitelist(whitelist []string) map[string]struct{} {
	m := make(map[string]struct{}, len(whitelist))
	for _, name := range whitelist {
		m[name] = struct{}{}
	}
	return m
}

func (i *Interceptor) buildFilter() string {
	filter := "(outbound and ip and tcp and ip.DstAddr != 127.0.0.1) or " +
		"(outbound and ipv6) or " +
		"(outbound and ip and tcp and tcp.SrcPort == " + strconv.Itoa(int(i.tproxyPort)) + ")"

	if i.proxyIP != "" && i.proxyIP != "127.0.0.1" {
		filter += " and ip.DstAddr != " + i.proxyIP
	}

	return filter
}

func (i *Interceptor) Start() {
	log.Printf("[WinDivert] 正在启动... PID=%d（已排除自身，防止回环）", i.myPid)

	handle, err := wdOpen("false", layerNetwork, priorityDefault, 0)
	if err != nil {
		log.Printf("[WinDivert] ❌ 启动失败: %v", err)
		return
	}
	i.handle.Store(handle)
	log.Println("[WinDivert] ✅ 驱动就绪，开始扫描白名单进程...")

	go i.filterUpdater()

	buf := make([]byte, 65535)
	for {
		select {
		case <-i.stopCh:
			return
		default:
		}

		h := i.handle.Load()
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

		i.handlePacket(buf[:n], addr)
	}
}

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
			if pid, err := process.GetPidByPort(i.proxyPort); err == nil && pid != 0 {
				if i.upstreamPid.Load() != pid {
					i.upstreamPid.Store(pid)
				}
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

			newH, err := wdOpen(f, layerNetwork, priorityDefault, 0)
			if err != nil {
				log.Printf("[WinDivert] 重新打开失败: %v", err)
				continue
			}

			oldH := i.handle.Swap(newH)
			if oldH != nil {
				oldH.Close()
			}
			last = f
		}
	}
}

func (i *Interceptor) handlePacket(pkt []byte, addr *winDivertAddress) {
	if len(pkt) < 20 {
		return
	}
	ipHeaderLen := int(pkt[0]&0x0F) * 4
	if len(pkt) < ipHeaderLen+4 {
		return
	}

	tcpOffset := ipHeaderLen
	srcPort := binary.BigEndian.Uint16(pkt[tcpOffset : tcpOffset+2])
	origDstPort := binary.BigEndian.Uint16(pkt[tcpOffset+2 : tcpOffset+4])

	if (pkt[0] >> 4) == 6 {
		return
	}

	h := i.handle.Load()
	if h == nil {
		return
	}

	if srcPort == i.tproxyPort {
		origDstIP := ip4ToBytes(pkt[16:20])
		target, found := i.tracker.Get(origDstIP, origDstPort)
		if !found {
			h.Send(pkt, addr)
			return
		}

		copy(pkt[12:16], target.OrigDstIP[:])
		binary.BigEndian.PutUint16(pkt[tcpOffset:tcpOffset+2], target.OrigDstPort)
		copy(pkt[16:20], target.OrigSrcIP[:])

		if target.OrigSrcIP[0] == 127 {
			addr.Bits |= uint32(flagOutbound) | uint32(flagLoopback)
		} else {
			addr.Bits &= ^uint32(flagOutbound | flagLoopback)
		}
		addr.IfIdx = target.OrigIfIdx
		addr.SubIfIdx = target.OrigSubIfIdx

		if err := h.CalcChecksums(pkt, addr); err != nil {
			log.Printf("[WinDivert] 反向 NAT 计算校验和失败: %v", err)
			return
		}
		if err := h.Send(pkt, addr); err != nil {
			log.Printf("[WinDivert] 反向 NAT Send 失败: %v", err)
		}
		return
	}

	pid, _ := process.GetPidByPort(srcPort)

	if pid == 0 || pid == i.myPid {
		h.Send(pkt, addr)
		return
	}

	cfg := i.modeCfg.Load()
	mode := cfg.mode
	whitelist := cfg.whitelist

	isAllowed := false
	matchedName := ""

	if mode == "global" {
		upstreamPid := i.upstreamPid.Load()
		if upstreamPid == 0 || pid != upstreamPid {
			isAllowed = true
		}
	} else {
		pName := process.GetNameByPID(pid)
		if _, ok := whitelist[pName]; ok {
			isAllowed = true
			matchedName = pName
		}
	}

	if !isAllowed {
		if i.stats != nil {
			origDstIP := pkt[16:20]
			srcIP := pkt[12:16]
			if matchedName == "" {
				matchedName = process.GetNameByPID(pid)
			}
			i.stats.ReportDirect(ip4ToBytes(srcIP), srcPort, matchedName, ip4ToBytes(origDstIP), origDstPort)
		}

		h.Send(pkt, addr)
		return
	}

	if matchedName == "" {
		matchedName = process.GetNameByPID(pid)
	}

	i.maybeLogHijack(matchedName, pid, pkt, origDstPort)

	origDstIP := ip4ToBytes(pkt[16:20])
	origSrcIP := ip4ToBytes(pkt[12:16])
	origIfIdx := addr.IfIdx
	origSubIfIdx := addr.SubIfIdx
	i.tracker.Set(loopbackIP, srcPort, origSrcIP, srcPort, origDstIP, origDstPort, origIfIdx, origSubIfIdx, matchedName)

	copy(pkt[12:16], loopbackIP[:])
	copy(pkt[16:20], loopbackIP[:])
	binary.BigEndian.PutUint16(pkt[tcpOffset+2:tcpOffset+4], i.tproxyPort)

	addr.Bits |= uint32(flagOutbound) | uint32(flagLoopback)

	if err := h.CalcChecksums(pkt, addr); err != nil {
		log.Printf("[WinDivert] CalcChecksums 失败: %v", err)
		return
	}
	if err := h.Send(pkt, addr); err != nil {
		log.Printf("[WinDivert] Send 失败: %v", err)
	}
}

func (i *Interceptor) maybeLogHijack(name string, pid uint32, pkt []byte, origDstPort uint16) {
	var buf [64]byte
	n := copy(buf[:], name)
	buf[n] = ':'
	n++
	// Inline itoa for pid to avoid strconv.Itoa alloc
	pidStr := buf[n:]
	pidVal := pid
	if pidVal == 0 {
		pidStr[0] = '0'
		n++
	} else {
		start := len(pidStr)
		for pidVal > 0 {
			start--
			pidStr[start] = byte('0' + pidVal%10)
			pidVal /= 10
		}
		n += len(pidStr) - start
	}
	key := string(buf[:n])

	i.hijackLogMu.Lock()
	defer i.hijackLogMu.Unlock()

	last, ok := i.hijackLog[key]
	if ok && time.Since(last) <= 10*time.Second {
		return
	}

	srcIP := ip4String(ip4ToBytes(pkt[12:16]))
	origDstIP := ip4String(ip4ToBytes(pkt[16:20]))
	log.Printf("[WinDivert] 劫持进程 %s (PID %d): %s -> %s:%d", name, pid, srcIP, origDstIP, origDstPort)
	i.hijackLog[key] = time.Now()

	if len(i.hijackLog) > 100 {
		for k := range i.hijackLog {
			delete(i.hijackLog, k)
			break
		}
	}
}

func (i *Interceptor) SetMode(mode string) {
	old := i.modeCfg.Load()
	cfg := &modeConfig{mode: mode, whitelist: old.whitelist}
	i.modeCfg.Store(cfg)
	log.Printf("[WinDivert] 工作模式已切换为: %s", mode)
}

func (i *Interceptor) SetWhitelist(whitelist []string) {
	old := i.modeCfg.Load()
	wl := i.setWhitelist(whitelist)
	cfg := &modeConfig{mode: old.mode, whitelist: wl}
	i.modeCfg.Store(cfg)
	log.Printf("[WinDivert] 白名单规则已更新: %v", whitelist)
}

func (i *Interceptor) Close() {
	close(i.stopCh)
	if old := i.handle.Swap(nil); old != nil {
		old.Close()
	}
}
