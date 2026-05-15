// netstat.go - TCP port-to-PID lookup
//
// [v1.1.9 CPU FIX] GetPidByPort was the #1 CPU killer.
// OLD: Every intercepted packet called GetExtendedTcpTable (2x syscall + heap alloc + full table scan).
//
//	Windows background TCP traffic (svchost, Defender, Edge) = hundreds of calls/sec = 83% idle CPU.
//
// NEW: Global portCache map refreshed every 2s by background goroutine.
//
//	GetPidByPort is now O(1) map lookup with zero kernel calls on the hot path.
package process

import (
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	iphlpapi                = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	TCP_TABLE_OWNER_PID_ALL = 5
	AF_INET                 = 2
)

type MIB_TCPROW_OWNER_PID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// ========== 全局 TCP 表缓存 ==========
var (
	portCache  map[uint16]uint32
	portCacheMu sync.RWMutex

	// tcpBufPool 复用 TCP 表扫描缓冲区，避免每次 refresh 都分配 100KB+
	tcpBufPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 65536)
			return &b
		},
	}
)

func InitNetstatCache(interval int) {
	portCache = make(map[uint16]uint32)
	refreshPortCache()
	go func() {
		for {
			time.Sleep(time.Duration(interval) * time.Second)
			refreshPortCache()
		}
	}()
}

// refreshPortCache 一次性扫描整张 TCP 表，写入缓存 map
func refreshPortCache() {
	// 第一次调用获取所需大小
	var size uint32
	procGetExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(AF_INET),
		uintptr(TCP_TABLE_OWNER_PID_ALL),
		0,
	)
	if size == 0 {
		return
	}

	// 从 pool 获取缓冲区，不够大则重新分配
	bufPtr := tcpBufPool.Get().(*[]byte)
	buf := *bufPtr
	if uint32(len(buf)) < size {
		buf = make([]byte, size)
		*bufPtr = buf
	}

	ret, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(AF_INET),
		uintptr(TCP_TABLE_OWNER_PID_ALL),
		0,
	)
	if ret != 0 {
		tcpBufPool.Put(bufPtr)
		return
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	entrySize := uint32(unsafe.Sizeof(MIB_TCPROW_OWNER_PID{}))

	newCache := make(map[uint16]uint32, numEntries)
	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + i*entrySize
		entry := (*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&buf[offset]))
		port := uint16(entry.LocalPort>>8) | uint16(entry.LocalPort<<8)
		newCache[port] = entry.OwningPid
	}

	portCacheMu.Lock()
	portCache = newCache
	portCacheMu.Unlock()

	tcpBufPool.Put(bufPtr)
}

// GetPidByPort 从缓存中查找端口对应的 PID，若未命中则异步触发刷新
func GetPidByPort(port uint16) (uint32, error) {
	portCacheMu.RLock()
	pid := portCache[port]
	portCacheMu.RUnlock()

	if pid == 0 {
		// Cache miss: 异步触发刷新，不阻塞热路径
		go refreshPortCache()
	}

	return pid, nil
}
