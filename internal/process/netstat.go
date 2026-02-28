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

// MIB_TCPROW_OWNER_PID 结构体
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
	portCache   map[uint16]uint32
	portCacheMu sync.RWMutex
)

func init() {
	portCache = make(map[uint16]uint32)
	refreshPortCache()
	go func() {
		for {
			time.Sleep(2 * time.Second)
			refreshPortCache()
		}
	}()
}

// refreshPortCache 一次性扫描整张 TCP 表，写入缓存 map
func refreshPortCache() {
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

	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(AF_INET),
		uintptr(TCP_TABLE_OWNER_PID_ALL),
		0,
	)
	if ret != 0 {
		return
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	entrySize := uint32(unsafe.Sizeof(MIB_TCPROW_OWNER_PID{}))

	newCache := make(map[uint16]uint32, numEntries)
	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + i*entrySize
		entry := (*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&buf[offset]))
		// 网络字节序端口 → 主机字节序
		port := uint16(entry.LocalPort>>8) | uint16(entry.LocalPort<<8)
		newCache[port] = entry.OwningPid
	}

	portCacheMu.Lock()
	portCache = newCache
	portCacheMu.Unlock()
}

// GetPidByPort 从缓存中 O(1) 查找端口对应的 PID（不再调用内核 API）
func GetPidByPort(port uint16) (uint32, error) {
	portCacheMu.RLock()
	pid := portCache[port]
	portCacheMu.RUnlock()
	return pid, nil
}
