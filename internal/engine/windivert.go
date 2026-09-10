package engine

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

	"golang.org/x/sys/windows"
)

const (
	layerNetwork    = 0
	priorityDefault = 0
	flagOutbound    = 1 << 17
	flagLoopback    = 1 << 18
)

type winDivertAddress struct {
	Timestamp int64
	Bits      uint32
	Reserved2 uint32
	IfIdx     uint32
	SubIfIdx  uint32
	Data      [60]byte
}

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

func stopAndRemoveService(name string) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_CREATE_SERVICE)
	if err != nil { return }
	defer windows.CloseServiceHandle(scm)
	svc, err := windows.OpenService(scm, syscall.StringToUTF16Ptr(name), windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS|windows.DELETE)
	if err != nil { return }
	var status windows.SERVICE_STATUS
	_ = windows.ControlService(svc, windows.SERVICE_CONTROL_STOP, &status)
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		if err := windows.QueryServiceStatus(svc, &status); err != nil || status.CurrentState == windows.SERVICE_STOPPED { break }
	}
	_ = windows.DeleteService(svc)
	windows.CloseServiceHandle(svc)
	for i := 0; i < 30; i++ {
		checkSvc, checkErr := windows.OpenService(scm, syscall.StringToUTF16Ptr(name), windows.SERVICE_QUERY_STATUS)
		if checkErr != nil { break }
		windows.CloseServiceHandle(checkSvc)
		time.Sleep(500 * time.Millisecond)
	}
}

func stopAndRemoveWinDivertDriver() {
	stopAndRemoveService("WinDivert")
	stopAndRemoveService("WinDivert14")
}

func CleanUpDependencies() {
	stopAndRemoveWinDivertDriver()
	cwd, err := os.Getwd()
	if err != nil { cwd = "." }
	for _, name := range []string{"WinDivert.dll", "WinDivert64.sys", "WinDivert64.sys.tmp"} {
		_ = os.Remove(filepath.Join(cwd, name))
	}
}

func fileContentMatch(path string, data []byte) bool {
	existing, err := os.ReadFile(path)
	return err == nil && bytes.Equal(existing, data)
}

func CleanUpOnShutdown() {
	if wdDLL != nil && wdDLL.dll != nil {
		_ = wdDLL.dll.Release()
		wdDLL = nil
	}
	stopAndRemoveWinDivertDriver()
	if cwd, err := os.Getwd(); err == nil {
		for _, name := range []string{"WinDivert.dll", "WinDivert64.sys", "WinDivert64.sys.tmp"} {
			_ = os.Remove(filepath.Join(cwd, name))
		}
	}
}

func extractSysFile(targetPath string, data []byte) error {
	if err := os.WriteFile(targetPath, data, 0755); err == nil { return nil }
	if f, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_TRUNC, 0755); err == nil {
		if _, err = f.Write(data); err == nil { _ = f.Close(); return nil }
		_ = f.Close()
	}
	tmpPath := targetPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0755); err != nil { return fmt.Errorf("write temp SYS failed: %w", err) }
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	moveFileEx := kernel32.NewProc("MoveFileExW")
	srcPtr, _ := syscall.UTF16PtrFromString(tmpPath)
	dstPtr, _ := syscall.UTF16PtrFromString(targetPath)
	ret, _, err := moveFileEx.Call(uintptr(unsafe.Pointer(srcPtr)), uintptr(unsafe.Pointer(dstPtr)), uintptr(1|2))
	if ret != 0 { return nil }
	_ = os.Remove(tmpPath)
	return fmt.Errorf("replace SYS failed: %w", err)
}

func mustStatSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil { return -1 }
	return info.Size()
}

func getExeDir() string {
	exe, err := os.Executable()
	if err != nil { return os.TempDir() }
	return filepath.Dir(exe)
}

func loadWinDivert() (*winDivertDLL, error) {
	wdOnce.Do(func() {
		stopAndRemoveWinDivertDriver()
		wdDir, err := os.Getwd()
		if err != nil { wdDir = "." }
		dllPath := filepath.Join(wdDir, "WinDivert.dll")
		sysPath := filepath.Join(wdDir, "WinDivert64.sys")
		if !fileContentMatch(dllPath, windivertDLL) {
			if err := os.WriteFile(dllPath, windivertDLL, 0755); err != nil { wdErr = fmt.Errorf("write WinDivert.dll failed: %w", err); return }
		}
		if !fileContentMatch(sysPath, windivertSYS) {
			if err := extractSysFile(sysPath, windivertSYS); err != nil && !fileContentMatch(sysPath, windivertSYS) { wdErr = fmt.Errorf("write WinDivert64.sys failed: %w", err); return }
		}
		if info, err := os.Stat(dllPath); err != nil || info.Size() == 0 { wdErr = fmt.Errorf("WinDivert.dll missing after extraction: %v", err); return }
		if info, err := os.Stat(sysPath); err != nil || info.Size() == 0 { wdErr = fmt.Errorf("WinDivert64.sys missing after extraction: %v", err); return }
		dll, err := windows.LoadDLL(dllPath)
		if err != nil { wdErr = fmt.Errorf("load WinDivert.dll failed: %w", err); return }
		findProc := func(name string) *windows.Proc {
			p, e := dll.FindProc(name)
			if e != nil { wdErr = fmt.Errorf("find %s failed: %w", name, e); return nil }
			return p
		}
		wdDLL = &winDivertDLL{dll: dll, procOpen: findProc("WinDivertOpen"), procRecv: findProc("WinDivertRecv"), procSend: findProc("WinDivertSend"), procClose: findProc("WinDivertClose"), procCalcChecks: findProc("WinDivertHelperCalcChecksums")}
	})
	return wdDLL, wdErr
}

type winDivertHandle struct { handle windows.Handle; dll *winDivertDLL }

func wdOpen(filter string, layer, priority int, flags uint64) (*winDivertHandle, error) {
	dll, err := loadWinDivert()
	if err != nil { return nil, err }
	filterPtr, err := syscall.BytePtrFromString(filter)
	if err != nil { return nil, err }
	ret, _, eno := dll.procOpen.Call(uintptr(unsafe.Pointer(filterPtr)), uintptr(layer), uintptr(priority), uintptr(flags))
	if ret == uintptr(windows.InvalidHandle) { return nil, fmt.Errorf("WinDivertOpen failed: %w", eno) }
	return &winDivertHandle{handle: windows.Handle(ret), dll: dll}, nil
}

func (h *winDivertHandle) Recv(buf []byte) (int, *winDivertAddress, error) {
	if len(buf) == 0 { return 0, nil, fmt.Errorf("empty receive buffer") }
	var addr winDivertAddress
	var recvLen uint32
	ret, _, eno := h.dll.procRecv.Call(uintptr(h.handle), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&recvLen)), uintptr(unsafe.Pointer(&addr)))
	if ret == 0 { return 0, nil, fmt.Errorf("WinDivertRecv: %w", eno) }
	return int(recvLen), &addr, nil
}

func (h *winDivertHandle) Send(pkt []byte, addr *winDivertAddress) error {
	if len(pkt) == 0 { return fmt.Errorf("empty packet") }
	var sentLen uint32
	ret, _, eno := h.dll.procSend.Call(uintptr(h.handle), uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)), uintptr(unsafe.Pointer(&sentLen)), uintptr(unsafe.Pointer(addr)))
	if ret == 0 { return fmt.Errorf("WinDivertSend: %w", eno) }
	return nil
}

func (h *winDivertHandle) CalcChecksums(pkt []byte, addr *winDivertAddress) error {
	if len(pkt) == 0 { return fmt.Errorf("empty packet") }
	ret, _, eno := h.dll.procCalcChecks.Call(uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)), uintptr(unsafe.Pointer(addr)), 0)
	if ret == 0 { return fmt.Errorf("WinDivertHelperCalcChecksums: %w", eno) }
	return nil
}

func (h *winDivertHandle) Close() {
	if h != nil && h.handle != windows.InvalidHandle {
		_, _, _ = h.dll.procClose.Call(uintptr(h.handle))
		h.handle = windows.InvalidHandle
	}
}

type Interceptor struct {
	handle     *winDivertHandle
	mu         sync.Mutex
	tracker    *ConnTracker
	proxyIP    string
	proxyPort  uint16
	tproxyPort uint16
	stopCh     chan struct{}
	closeOnce  sync.Once
}

func NewInterceptor(tracker *ConnTracker, proxyIP string, proxyPort, tproxyPort uint16) *Interceptor {
	return &Interceptor{tracker: tracker, proxyIP: proxyIP, proxyPort: proxyPort, tproxyPort: tproxyPort, stopCh: make(chan struct{})}
}

func (i *Interceptor) SetProxyAddr(ip string, port uint16) {
	i.mu.Lock()
	i.proxyIP, i.proxyPort = ip, port
	i.mu.Unlock()
}

func (i *Interceptor) buildFilter() string {
	i.mu.Lock()
	proxyIP := i.proxyIP
	tproxyPort := i.tproxyPort
	i.mu.Unlock()
	first := "(outbound and ip and tcp and ip.DstAddr != 127.0.0.1"
	if ip := net.ParseIP(proxyIP); ip != nil && ip.To4() != nil && !ip.IsLoopback() { first += fmt.Sprintf(" and ip.DstAddr != %s", ip.To4().String()) }
	first += ")"
	return fmt.Sprintf("%s or (outbound and ip and tcp and tcp.SrcPort == %d)", first, tproxyPort)
}

func (i *Interceptor) Start() {
	h, err := wdOpen(i.buildFilter(), layerNetwork, priorityDefault, 0)
	if err != nil { log.Printf("[WinDivert] start failed: %v", err); return }
	i.mu.Lock(); i.handle = h; i.mu.Unlock()
	log.Println("[WinDivert] TCP interception ready")
	go i.filterUpdater()
	buf := make([]byte, 65535)
	for {
		select { case <-i.stopCh: return; default: }
		i.mu.Lock(); h = i.handle; i.mu.Unlock()
		if h == nil { return }
		n, addr, err := h.Recv(buf)
		if err != nil {
			select { case <-i.stopCh: return; default: time.Sleep(10 * time.Millisecond) }
			continue
		}
		if n > 0 && n <= len(buf) { i.handlePacket(buf[:n], addr) }
	}
}

func (i *Interceptor) filterUpdater() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	last := i.buildFilter()
	for {
		select {
		case <-i.stopCh: return
		case <-ticker.C:
			f := i.buildFilter()
			if f == last { continue }
			newH, err := wdOpen(f, layerNetwork, priorityDefault, 0)
			if err != nil { log.Printf("[WinDivert] filter update failed: %v", err); continue }
			i.mu.Lock(); oldH := i.handle; i.handle = newH; i.mu.Unlock()
			if oldH != nil { oldH.Close() }
			last = f
		}
	}
}

func (i *Interceptor) handlePacket(pkt []byte, addr *winDivertAddress) {
	if len(pkt) < 20 || (pkt[0]>>4) != 4 { return }
	ipHeaderLen := int(pkt[0]&0x0f) * 4
	if ipHeaderLen < 20 || len(pkt) < ipHeaderLen+4 || pkt[9] != 6 { return }

	srcIP := net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15])
	dstIP := net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
	srcPort := binary.BigEndian.Uint16(pkt[ipHeaderLen : ipHeaderLen+2])
	dstPort := binary.BigEndian.Uint16(pkt[ipHeaderLen+2 : ipHeaderLen+4])

	i.mu.Lock()
	proxyIP := i.proxyIP
	tproxyPort := i.tproxyPort
	i.mu.Unlock()

	if srcPort == tproxyPort {
		i.reverseNAT(pkt, addr, ipHeaderLen)
		return
	}
	if proxyIP != "" && net.ParseIP(proxyIP) != nil && net.ParseIP(proxyIP).Equal(dstIP) { i.sendPass(pkt, addr); return }
	if isPrivateOrLocal(dstIP) { i.sendPass(pkt, addr); return }
	i.hijackTCP(pkt, addr, srcIP, dstIP, srcPort, dstPort, ipHeaderLen)
}

func (i *Interceptor) hijackTCP(pkt []byte, addr *winDivertAddress, origSrcIP, origDstIP net.IP, srcPort, dstPort uint16, ipHeaderLen int) {
	i.tracker.Set("127.0.0.1", srcPort, origSrcIP, srcPort, origDstIP, dstPort, addr.IfIdx, addr.SubIfIdx)
	loop := net.IPv4(127, 0, 0, 1).To4()
	copy(pkt[12:16], loop)
	copy(pkt[16:20], loop)
	i.mu.Lock(); tproxyPort := i.tproxyPort; i.mu.Unlock()
	binary.BigEndian.PutUint16(pkt[ipHeaderLen+2:ipHeaderLen+4], tproxyPort)
	addr.Bits |= flagOutbound | flagLoopback
	if err := i.calcAndSend(pkt, addr); err != nil { log.Printf("[WinDivert] hijack send failed: %v", err) }
}

func (i *Interceptor) reverseNAT(pkt []byte, addr *winDivertAddress, ipHeaderLen int) {
	dstIP := net.IP(pkt[16:20])
	dstPort := binary.BigEndian.Uint16(pkt[ipHeaderLen+2 : ipHeaderLen+4])
	target, found := i.tracker.Get(dstIP.String(), dstPort)
	if !found { i.sendPass(pkt, addr); return }
	copy(pkt[12:16], target.OrigDstIP.To4())
	binary.BigEndian.PutUint16(pkt[ipHeaderLen:ipHeaderLen+2], target.OrigDstPort)
	copy(pkt[16:20], target.OrigSrcIP.To4())
	binary.BigEndian.PutUint16(pkt[ipHeaderLen+2:ipHeaderLen+4], target.OrigSrcPort)
	if target.OrigSrcIP.IsLoopback() { addr.Bits |= flagOutbound | flagLoopback } else { addr.Bits &^= flagOutbound | flagLoopback }
	addr.IfIdx, addr.SubIfIdx = target.OrigIfIdx, target.OrigSubIfIdx
	if err := i.calcAndSend(pkt, addr); err != nil { log.Printf("[WinDivert] reverse NAT failed: %v", err) }
}

func (i *Interceptor) calcAndSend(pkt []byte, addr *winDivertAddress) error {
	i.mu.Lock(); h := i.handle; i.mu.Unlock()
	if h == nil { return fmt.Errorf("WinDivert handle not ready") }
	if err := h.CalcChecksums(pkt, addr); err != nil { return err }
	return h.Send(pkt, addr)
}

func (i *Interceptor) sendPass(pkt []byte, addr *winDivertAddress) {
	i.mu.Lock(); h := i.handle; i.mu.Unlock()
	if h != nil { _ = h.Send(pkt, addr) }
}

func isPrivateOrLocal(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil { return true }
	switch {
	case v4[0] == 0, v4[0] == 10, v4[0] == 127:
		return true
	case v4[0] == 169 && v4[1] == 254:
		return true
	case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
		return true
	case v4[0] == 192 && v4[1] == 168:
		return true
	case v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127:
		return true
	case v4[0] == 192 && v4[1] == 0 && v4[2] == 0:
		return true
	case v4[0] >= 224:
		return true
	}
	return false
}

func (i *Interceptor) Close() {
	i.closeOnce.Do(func() {
		close(i.stopCh)
		i.mu.Lock(); h := i.handle; i.handle = nil; i.mu.Unlock()
		if h != nil { h.Close() }
	})
}

var _ = strings.Join
