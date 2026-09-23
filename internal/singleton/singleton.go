package singleton

import (
	"errors"
	"sync"

	"golang.org/x/sys/windows"
)

// ErrAlreadyRunning 表示本机已经有另一个 GoPass 实例在运行，或者本进程
// 无权访问那把单实例锁。两种情况都必须拒绝启动：无法确认单实例状态时放行的
// 代价，是紧接着的 CleanUpDependencies 会停掉 WinDivert 服务，打断正在代理的
// 连接——那正是这把锁存在的唯一理由。
var ErrAlreadyRunning = errors.New("GoPass 已在运行")

// 全局命名对象：WinDivert 驱动是系统级的，第二个实例启动时会
// stop/delete WinDivert 服务，打断第一个实例正在使用的句柄，
// 导致已建立的 NAT 连接中断。因此必须保证单实例。
const mutexName = "Global\\GoPass_SingleInstance_v1"

var (
	mu     sync.Mutex
	handle windows.Handle
)

// classifyCreateMutexErr 归类 CreateMutex 的失败。
//
// ERROR_ACCESS_DENIED 必须与 ERROR_ALREADY_EXISTS 同等对待，否则单实例锁会
// fail-open：跨完整性级别（普通权限实例去碰管理员创建的 Global\ 对象）以及
// 缺少 SeCreateGlobalPrivilege 都返回它，而它看起来"只是个普通错误"，调用方
// 极易当成可恢复错误继续启动，然后停掉正在用的驱动。
func classifyCreateMutexErr(err error) error {
	if err == nil {
		return nil
	}
	if err == windows.ERROR_ALREADY_EXISTS || err == windows.ERROR_ACCESS_DENIED {
		return ErrAlreadyRunning
	}
	return err
}

// acquire 执行一次 CreateMutexW。判定"已存在"的依据是 ERROR_ALREADY_EXISTS
// （与互斥量所有权无关），因此同进程重复调用也能稳定检测，不依赖线程语义。
// 成功时返回的句柄由调用方持有：只要句柄不关，命名对象就一直存在。
func acquire() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(mutexName)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateMutex(nil, false, name)
	if classified := classifyCreateMutexErr(err); classified != nil {
		if h != 0 {
			_ = windows.CloseHandle(h)
		}
		return 0, classified
	}
	return h, nil
}

// Acquire 占用单实例锁，成功后句柄一直持有到进程退出。可重复调用。
func Acquire() error {
	mu.Lock()
	defer mu.Unlock()
	if handle != 0 {
		return nil
	}
	h, err := acquire()
	if err != nil {
		return err
	}
	handle = h
	return nil
}
