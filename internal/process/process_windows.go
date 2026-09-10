//go:build windows

package process

import (
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Flow struct {
	LocalIP    uint32
	LocalPort  uint16
	RemoteIP   uint32
	RemotePort uint16
}

type Entry struct {
	Flow Flow
	PID  uint32
	Name string
}

type Resolver struct {
	mu    sync.RWMutex
	flows map[Flow]Entry
}

var (
	iphlpapi           = windows.NewLazySystemDLL("iphlpapi.dll")
	getExtendedTCPTable = iphlpapi.NewProc("GetExtendedTcpTable")
	kernel32            = windows.NewLazySystemDLL("kernel32.dll")
	openProcess         = kernel32.NewProc("OpenProcess")
	closeHandle         = kernel32.NewProc("CloseHandle")
	queryProcessName    = kernel32.NewProc("QueryFullProcessImageNameW")
)

const (
	afInet                  = 2
	tcpTableOwnerPidAll     = 5
	processQueryLimitedInfo  = 0x1000
	processVMRead            = 0x0010
)

func NewResolver() *Resolver { return &Resolver{flows: make(map[Flow]Entry)} }

func (r *Resolver) Refresh() error {
	size := uint32(0)
	ret, _, _ := getExtendedTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwnerPidAll, 0)
	if ret != 0 && size == 0 {
		return fmt.Errorf("GetExtendedTcpTable size failed: %d", ret)
	}
	buf := make([]byte, size)
	ret, _, err := getExtendedTCPTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwnerPidAll, 0)
	if ret != 0 {
		return fmt.Errorf("GetExtendedTcpTable failed: %v", err)
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := uint32(24)
	flows := make(map[Flow]Entry, count)
	for idx := uint32(0); idx < count; idx++ {
		off := 4 + idx*rowSize
		if off+rowSize > uint32(len(buf)) { break }
		row := buf[off : off+rowSize]
		state := *(*uint32)(unsafe.Pointer(&row[0]))
		if state == 1 { // LISTEN: not an outbound flow we need to classify.
			continue
		}
		localIP := *(*uint32)(unsafe.Pointer(&row[4]))
		localPort := ntohs(uint16(*(*uint32)(unsafe.Pointer(&row[8]))))
		remoteIP := *(*uint32)(unsafe.Pointer(&row[12]))
		remotePort := ntohs(uint16(*(*uint32)(unsafe.Pointer(&row[16]))))
		pid := *(*uint32)(unsafe.Pointer(&row[20]))
		name := processName(pid)
		flows[Flow{LocalIP: localIP, LocalPort: localPort, RemoteIP: remoteIP, RemotePort: remotePort}] = Entry{
			Flow: Flow{LocalIP: localIP, LocalPort: localPort, RemoteIP: remoteIP, RemotePort: remotePort},
			PID:  pid,
			Name: name,
		}
	}
	r.mu.Lock()
	r.flows = flows
	r.mu.Unlock()
	return nil
}

func (r *Resolver) Lookup(flow Flow) (Entry, bool) {
	r.mu.RLock()
	e, ok := r.flows[flow]
	r.mu.RUnlock()
	return e, ok
}

func (r *Resolver) Snapshot() []Entry {
	r.mu.RLock()
	out := make([]Entry, 0, len(r.flows))
	for _, e := range r.flows { out = append(out, e) }
	r.mu.RUnlock()
	return out
}

func processName(pid uint32) string {
	if pid == 0 { return "" }
	ret, _, _ := openProcess.Call(processQueryLimitedInfo|processVMRead, 0, uintptr(pid))
	if ret == 0 { return "" }
	h := windows.Handle(ret)
	defer closeHandle.Call(ret)
	buf := make([]uint16, windows.MAX_PATH)
	for {
		n := uint32(len(buf))
		ok, _, _ := queryProcessName.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
		if ok != 0 {
			path := syscall.UTF16ToString(buf[:n])
			if p := strings.LastIndexAny(path, `\\/`); p >= 0 { return path[p+1:] }
			return path
		}
		if len(buf) >= 32768 { return "" }
		buf = make([]uint16, len(buf)*2)
	}
}

func ntohs(v uint16) uint16 { return v<<8 | v>>8 }
