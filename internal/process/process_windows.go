//go:build windows

package process

import (
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
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

type UDPFlow struct {
	LocalIP   uint32
	LocalPort uint16
}

type UDPEntry struct {
	Flow UDPFlow
	PID  uint32
	Name string
}

type pidCacheEntry struct {
	name      string
	checkedAt time.Time
}

type Resolver struct {
	mu        sync.RWMutex
	flows     map[Flow]Entry
	udpFlows  map[UDPFlow]UDPEntry
	pidCache  map[uint32]pidCacheEntry
	fallbackMu sync.Mutex
}

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	getExtendedTCPTable = iphlpapi.NewProc("GetExtendedTcpTable")
	getExtendedUDPTable = iphlpapi.NewProc("GetExtendedUdpTable")
	kernel32            = windows.NewLazySystemDLL("kernel32.dll")
	openProcess         = kernel32.NewProc("OpenProcess")
	closeHandle         = kernel32.NewProc("CloseHandle")
	queryProcessName    = kernel32.NewProc("QueryFullProcessImageNameW")
)

const (
	afInet                  = 2
	tcpTableOwnerPidAll     = 5
	udpTableOwnerPid        = 1
	processQueryLimitedInfo = 0x1000
	pidNameCacheTTL         = 2 * time.Second
)

func NewResolver() *Resolver {
	return &Resolver{
		flows:    make(map[Flow]Entry),
		udpFlows: make(map[UDPFlow]UDPEntry),
		pidCache: make(map[uint32]pidCacheEntry),
	}
}

func (r *Resolver) Refresh() error {
	tcpErr := r.refreshTCP()
	// UDP is intentionally refreshed together with the existing 250ms TCP
	// snapshot. This keeps UDP/443 process lookup O(1) in the packet hot path
	// without adding a second timer or per-packet Windows table syscall.
	_ = r.refreshUDP()
	return tcpErr
}

func (r *Resolver) refreshTCP() error {
	size := uint32(0)
	ret, _, _ := getExtendedTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwnerPidAll, 0)
	if ret != 0 && size == 0 {
		return fmt.Errorf("GetExtendedTcpTable size failed: %d", ret)
	}
	if size == 0 {
		r.mu.Lock()
		r.flows = make(map[Flow]Entry)
		r.mu.Unlock()
		return nil
	}
	buf := make([]byte, size)
	ret, _, err := getExtendedTCPTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwnerPidAll, 0)
	if ret != 0 {
		return fmt.Errorf("GetExtendedTcpTable failed: %v", err)
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := uint32(24)
	now := time.Now()
	flows := make(map[Flow]Entry, count)
	seenPIDs := make(map[uint32]struct{})

	for idx := uint32(0); idx < count; idx++ {
		off := 4 + idx*rowSize
		if off+rowSize > uint32(len(buf)) {
			break
		}
		row := buf[off : off+rowSize]
		state := *(*uint32)(unsafe.Pointer(&row[0]))
		if state == 1 {
			continue
		}
		localIP := *(*uint32)(unsafe.Pointer(&row[4]))
		localPort := ntohs(uint16(*(*uint32)(unsafe.Pointer(&row[8]))))
		remoteIP := *(*uint32)(unsafe.Pointer(&row[12]))
		remotePort := ntohs(uint16(*(*uint32)(unsafe.Pointer(&row[16]))))
		pid := *(*uint32)(unsafe.Pointer(&row[20]))
		seenPIDs[pid] = struct{}{}
		name := r.cachedProcessName(pid, now)
		flow := Flow{LocalIP: localIP, LocalPort: localPort, RemoteIP: remoteIP, RemotePort: remotePort}
		flows[flow] = Entry{Flow: flow, PID: pid, Name: name}
	}

	r.mu.Lock()
	for pid := range r.pidCache {
		if _, ok := seenPIDs[pid]; !ok {
			delete(r.pidCache, pid)
		}
	}
	r.flows = flows
	r.mu.Unlock()
	return nil
}

func (r *Resolver) refreshUDP() error {
	size := uint32(0)
	ret, _, _ := getExtendedUDPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInet, udpTableOwnerPid, 0)
	if ret != 0 && size == 0 {
		return fmt.Errorf("GetExtendedUdpTable size failed: %d", ret)
	}
	if size == 0 {
		r.mu.Lock()
		r.udpFlows = make(map[UDPFlow]UDPEntry)
		r.mu.Unlock()
		return nil
	}
	buf := make([]byte, size)
	ret, _, err := getExtendedUDPTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, afInet, udpTableOwnerPid, 0)
	if ret != 0 {
		return fmt.Errorf("GetExtendedUdpTable failed: %v", err)
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := uint32(12)
	now := time.Now()
	flows := make(map[UDPFlow]UDPEntry, count)
	seenPIDs := make(map[uint32]struct{})

	for idx := uint32(0); idx < count; idx++ {
		off := 4 + idx*rowSize
		if off+rowSize > uint32(len(buf)) {
			break
		}
		row := buf[off : off+rowSize]
		localIP := *(*uint32)(unsafe.Pointer(&row[0]))
		localPort := ntohs(uint16(*(*uint32)(unsafe.Pointer(&row[4]))))
		pid := *(*uint32)(unsafe.Pointer(&row[8]))
		seenPIDs[pid] = struct{}{}
		name := r.cachedProcessName(pid, now)
		flow := UDPFlow{LocalIP: localIP, LocalPort: localPort}
		flows[flow] = UDPEntry{Flow: flow, PID: pid, Name: name}
	}

	r.mu.Lock()
	for pid := range r.pidCache {
		if _, ok := seenPIDs[pid]; !ok {
			// Keep PID entries that are still present in TCP as well. The TCP
			// refresh owns the final cleanup when it sees a PID disappear.
			continue
		}
	}
	r.udpFlows = flows
	r.mu.Unlock()
	return nil
}

func (r *Resolver) cachedProcessName(pid uint32, now time.Time) string {
	if pid == 0 {
		return ""
	}
	r.mu.RLock()
	cached, ok := r.pidCache[pid]
	r.mu.RUnlock()
	if ok && now.Sub(cached.checkedAt) < pidNameCacheTTL {
		return cached.name
	}
	name := processName(pid)
	r.mu.Lock()
	r.pidCache[pid] = pidCacheEntry{name: name, checkedAt: now}
	r.mu.Unlock()
	return name
}

func (r *Resolver) Lookup(flow Flow) (Entry, bool) {
	r.mu.RLock()
	e, ok := r.flows[flow]
	r.mu.RUnlock()
	return e, ok
}

func (r *Resolver) LookupUDP(flow UDPFlow) (UDPEntry, bool) {
	r.mu.RLock()
	e, ok := r.udpFlows[flow]
	if !ok && flow.LocalIP != 0 {
		e, ok = r.udpFlows[UDPFlow{LocalIP: 0, LocalPort: flow.LocalPort}]
	}
	r.mu.RUnlock()
	return e, ok
}

// LookupWithRefresh restores the v1.6.3 startup/new-connection fallback.
// The background refresh normally makes Lookup a cheap O(1) operation, but a
// brand-new TCP connection can arrive at WinDivert before the next TCP-table
// refresh. On a cache miss, perform one serialized live table refresh and retry.
func (r *Resolver) LookupWithRefresh(flow Flow) (Entry, bool) {
	if e, ok := r.Lookup(flow); ok {
		return e, true
	}

	r.fallbackMu.Lock()
	defer r.fallbackMu.Unlock()

	if e, ok := r.Lookup(flow); ok {
		return e, true
	}
	if err := r.Refresh(); err != nil {
		return Entry{}, false
	}
	return r.Lookup(flow)
}

func (r *Resolver) Snapshot() []Entry {
	r.mu.RLock()
	out := make([]Entry, 0, len(r.flows))
	for _, e := range r.flows {
		out = append(out, e)
	}
	r.mu.RUnlock()
	return out
}

func processName(pid uint32) string {
	if pid == 0 {
		return ""
	}
	ret, _, _ := openProcess.Call(processQueryLimitedInfo, 0, uintptr(pid))
	if ret == 0 {
		return ""
	}
	h := windows.Handle(ret)
	defer closeHandle.Call(ret)
	buf := make([]uint16, windows.MAX_PATH)
	for {
		n := uint32(len(buf))
		ok, _, _ := queryProcessName.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
		if ok != 0 {
			path := syscall.UTF16ToString(buf[:n])
			if p := strings.LastIndexAny(path, `\\/`); p >= 0 {
				return path[p+1:]
			}
			return path
		}
		if len(buf) >= 32768 {
			return ""
		}
		buf = make([]uint16, len(buf)*2)
	}
}

func ntohs(v uint16) uint16 { return v<<8 | v>>8 }
