package process

import (
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = kernel32.NewProc("Process32FirstW")
	procProcess32NextW           = kernel32.NewProc("Process32NextW")

	nameCache = make(map[uint32]string)
	cacheMu   sync.RWMutex
)

// [v1.2.6 Config] 移除硬编码 init，允许从外部传入刷新频率配置
func InitProcessCache(interval int) {
	// 启动后台刷新协程
	go func() {
		for {
			refreshCache()
			time.Sleep(time.Duration(interval) * time.Second)
		}
	}()
}

func refreshCache() {
	snapshot, _, _ := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	handle := windows.Handle(snapshot)
	if handle == windows.InvalidHandle {
		return
	}
	defer windows.CloseHandle(handle)

	var entry PROCESSENTRY32
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, _ := procProcess32FirstW.Call(uintptr(handle), uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return
	}

	newCache := make(map[uint32]string)
	for {
		newCache[entry.Th32ProcessID] = syscall.UTF16ToString(entry.SzExeFile[:])
		ret, _, _ = procProcess32NextW.Call(uintptr(handle), uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	cacheMu.Lock()
	nameCache = newCache
	cacheMu.Unlock()
}

const (
	TH32CS_SNAPPROCESS = 0x00000002
	MAX_PATH           = 260
)

type PROCESSENTRY32 struct {
	Size                uint32
	CntUsage            uint32
	Th32ProcessID       uint32
	Th32DefaultHeapID   uintptr
	Th32ModuleID        uint32
	CntThreads          uint32
	Th32ParentProcessID uint32
	PcPriClassBase      int32
	DwFlags             uint32
	SzExeFile           [MAX_PATH]uint16
}

// GetPIDsByName 返回所有匹配进程名的 PID 列表（从缓存读取，节约 CPU）
func GetPIDsByName(processName string) ([]uint32, error) {
	nameLower := strings.ToLower(processName)
	var pids []uint32

	cacheMu.RLock()
	defer cacheMu.RUnlock()

	for pid, name := range nameCache {
		if strings.ToLower(name) == nameLower {
			pids = append(pids, pid)
		}
	}

	return pids, nil
}

// GetNameByPID 返回给定 PID 的进程名（优先从缓存读取，大幅节约 CPU）
func GetNameByPID(pid uint32) string {
	cacheMu.RLock()
	name, ok := nameCache[pid]
	cacheMu.RUnlock()
	if ok {
		return name
	}
	return "unknown"
}
