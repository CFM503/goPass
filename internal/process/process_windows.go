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
	buf, err := queryWinTable(getExtendedTCPTable, 0, afInet, tcpTableOwnerPidAll, 0)
	if err != nil {
		return fmt.Errorf("GetExtendedTcpTable: %w", err)
	}
	if len(buf) == 0 {
		r.mu.Lock()
		r.flows = make(map[Flow]Entry)
		r.mu.Unlock()
		return nil
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
	buf, err := queryWinTable(getExtendedUDPTable, 0, afInet, udpTableOwnerPid, 0)
	if err != nil {
		return fmt.Errorf("GetExtendedUdpTable: %w", err)
	}
	if len(buf) == 0 {
		r.mu.Lock()
		r.udpFlows = make(map[UDPFlow]UDPEntry)
		r.mu.Unlock()
		return nil
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := uint32(12)
	now := time.Now()
	flows := make(map[UDPFlow]UDPEntry, count)

	for idx := uint32(0); idx < count; idx++ {
		off := 4 + idx*rowSize
		if off+rowSize > uint32(len(buf)) {
			break
		}
		row := buf[off : off+rowSize]
		localIP := *(*uint32)(unsafe.Pointer(&row[0]))
		localPort := ntohs(uint16(*(*uint32)(unsafe.Pointer(&row[4]))))
		pid := *(*uint32)(unsafe.Pointer(&row[8]))
		name := r.cachedProcessName(pid, now)
		flow := UDPFlow{LocalIP: localIP, LocalPort: localPort}
		flows[flow] = UDPEntry{Flow: flow, PID: pid, Name: name}
	}

	// pidCache 的清理只由 refreshTCP 负责：它按 TCP 表里见过的 PID 删条目。
	// 这里原先也有一个循环，但两个分支都不做事——!ok 分支 continue 到循环末尾，
	// ok 分支压根不进 if——等于把 map 白遍历一遍，连同它的 seenPIDs 一起删掉。
	r.mu.Lock()
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

// maxUTF16Buffer 是给 QueryFullProcessImageNameW 的缓冲上限（UTF-16 字符数）。
// 翻倍到它仍然失败就收手，与改动前的放弃条件一致。
const maxUTF16Buffer = 32768

// queryUTF16WithRetry 在 size 个 UTF-16 字符的缓冲上反复调用 call，返回
// (缓冲区, 写入字符数, 是否成功)。
//
// 只有 ERROR_INSUFFICIENT_BUFFER（122）意味着"缓冲不够，加大再来"——这也是唯一
// 值得重试的失败。其余错误码（访问被拒、参数无效……）加大缓冲毫无意义，立刻返回。
//
// 此前 processName 对任何失败都翻倍重取、从不读错误码：一个被拒绝访问的 PID 要
// 空跑 260→520→…→33280 共 8 轮，每轮一次系统调用加一次分配，最后照样返回 ""。
// 而它挂在进程名缓存未命中的路径上，refreshTCP/refreshUDP 每行 PID 都要过一遍，
// 失败的 PID 还会在 TTL 之后反复重来。
func queryUTF16WithRetry(size int, call func(buf []uint16, need *uint32) (bool, error)) ([]uint16, uint32, bool) {
	for {
		buf := make([]uint16, size)
		need := uint32(size)
		ok, err := call(buf, &need)
		if ok {
			// 成功路径上 *need 是写出的字符数，理论上不会超过缓冲长度；
			// 但这里一旦越界，下面的切片会直接 panic 掉整个代理，所以先夹一下。
			if need > uint32(len(buf)) {
				need = uint32(len(buf))
			}
			return buf, need, true
		}
		if err != syscall.Errno(errorInsufficientBuffer) || size >= maxUTF16Buffer {
			return nil, 0, false
		}
		size *= 2
	}
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
	buf, n, ok := queryUTF16WithRetry(windows.MAX_PATH, func(b []uint16, need *uint32) (bool, error) {
		r, _, err := queryProcessName.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(need)))
		return r != 0, err
	})
	if !ok {
		return ""
	}
	path := syscall.UTF16ToString(buf[:n])
	if p := strings.LastIndexAny(path, `\\/`); p >= 0 {
		return path[p+1:]
	}
	return path
}

func ntohs(v uint16) uint16 { return v<<8 | v>>8 }
