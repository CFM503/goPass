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
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	TCP_TABLE_OWNER_PID_ALL = 5
	UDP_TABLE_OWNER_PID     = 1
	AF_INET                 = 2
)

// MIB_TCPROW_OWNER_PID 结构体
type MIB_TCPROW_OWNER_PID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// MIB_UDPROW_OWNER_PID 结构体
type MIB_UDPROW_OWNER_PID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

// ========== 全局 TCP/UDP 表缓存 ==========
var (
	portCache   map[uint16]uint32
	portCacheMu sync.RWMutex
	fallbackMu  sync.Mutex
)

// [v1.2.6 Config] 移除硬编码 init，允许从外部传入刷新频率配置
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

// refreshPortCache 一次性扫描整张 TCP/UDP 表，写入缓存 map
func refreshPortCache() {
	newCache := make(map[uint16]uint32)

	// 1. 扫描 TCP 表
	var size uint32
	procGetExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(AF_INET),
		uintptr(TCP_TABLE_OWNER_PID_ALL),
		0,
	)
	if size > 0 {
		buf := make([]byte, size)
		ret, _, _ := procGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
			uintptr(AF_INET),
			uintptr(TCP_TABLE_OWNER_PID_ALL),
			0,
		)
		if ret == 0 {
			numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
			entrySize := uint32(unsafe.Sizeof(MIB_TCPROW_OWNER_PID{}))
			for i := uint32(0); i < numEntries; i++ {
				offset := 4 + i*entrySize
				entry := (*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&buf[offset]))
				port := uint16(entry.LocalPort>>8) | uint16(entry.LocalPort<<8)
				newCache[port] = entry.OwningPid
			}
		}
	}

	// 2. 扫描 UDP 表
	var udpSize uint32
	procGetExtendedUdpTable.Call(
		0,
		uintptr(unsafe.Pointer(&udpSize)),
		0,
		uintptr(AF_INET),
		uintptr(UDP_TABLE_OWNER_PID),
		0,
	)
	if udpSize > 0 {
		buf := make([]byte, udpSize)
		ret, _, _ := procGetExtendedUdpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&udpSize)),
			0,
			uintptr(AF_INET),
			uintptr(UDP_TABLE_OWNER_PID),
			0,
		)
		if ret == 0 {
			numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
			entrySize := uint32(unsafe.Sizeof(MIB_UDPROW_OWNER_PID{}))
			for i := uint32(0); i < numEntries; i++ {
				offset := 4 + i*entrySize
				entry := (*MIB_UDPROW_OWNER_PID)(unsafe.Pointer(&buf[offset]))
				port := uint16(entry.LocalPort>>8) | uint16(entry.LocalPort<<8)
				newCache[port] = entry.OwningPid
			}
		}
	}

	portCacheMu.Lock()
	portCache = newCache
	portCacheMu.Unlock()
}

// GetPidByPort 从缓存中查找端口对应的 PID，若未命中则实时回退更新
func GetPidByPort(port uint16) (uint32, error) {
	portCacheMu.RLock()
	pid := portCache[port]
	portCacheMu.RUnlock()

	if pid == 0 {
		// [FIX 2] Cache Miss Live Fallback: 新连接可能还未进入 2s 缓存。
		// 在这里触发一次实时的表刷新，防止新连接的首个 SYN 被当做未识别直连。
		fallbackMu.Lock()
		// Double-check 机制防止并发刷新风暴
		portCacheMu.RLock()
		pid = portCache[port]
		portCacheMu.RUnlock()
		if pid == 0 {
			refreshPortCache()
			portCacheMu.RLock()
			pid = portCache[port]
			portCacheMu.RUnlock()
		}
		fallbackMu.Unlock()
	}

	return pid, nil
}
