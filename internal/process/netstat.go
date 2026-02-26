package process

import (
	"syscall"
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

// GetPidByPort 根据本地 TCP 端口查找所属 PID
func GetPidByPort(port uint16) (uint32, error) {
	var size uint32
	// 第一次调用获取所需缓存大小
	procGetExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(AF_INET),
		uintptr(TCP_TABLE_OWNER_PID_ALL),
		0,
	)

	if size == 0 {
		return 0, nil
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
		return 0, nil
	}

	// 解析表格
	// 第一个 4 字节是条目数
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	entrySize := uint32(unsafe.Sizeof(MIB_TCPROW_OWNER_PID{}))

	// 网络字节序端口转换 (BigEndian to Host)
	targetPort := uint32(port<<8) | uint32(port>>8)

	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + i*entrySize
		entry := (*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&buf[offset]))

		// 比较本地端口 (entry.LocalPort 是网络字节序)
		if entry.LocalPort == targetPort {
			return entry.OwningPid, nil
		}
	}

	return 0, nil
}
