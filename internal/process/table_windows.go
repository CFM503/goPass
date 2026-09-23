//go:build windows

package process

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// errorInsufficientBuffer 是 ERROR_INSUFFICIENT_BUFFER：两段式查询的第二步在表
// 于两次调用之间变长时返回它，并把新的所需尺寸写回传入的 size 指针。
const errorInsufficientBuffer = 122

// maxTableAttempts 限制重取轮数。每一轮都要求所需尺寸严格变大，正常情况一两轮内
// 就结束；上限只是防止表持续增长时无限分配。
const maxTableAttempts = 4

// queryWinTable 执行 GetExtendedTcpTable / GetExtendedUdpTable 的两段式查询。
// 两张表的调用形状完全一致：(pTable, pdwSize, bOrder, ulAf, TableClass, Reserved)，
// 后四个参数由调用方原样透传。
//
// 先用空缓冲区探出所需尺寸，再按该尺寸取数据。返回的缓冲区按探测尺寸完整分配，
// 由调用方按 count 与 len 做行边界检查；长度为 0 表示空表，调用方据此清空映射。
//
// 探测阶段唯一预期的非零返回就是 122（缓冲区太小）；出现别的错误码时 size 没有
// 被写入、不可信，直接失败而不是拿它去分配。
func queryWinTable(proc *windows.LazyProc, bOrder, ulAf, tableClass, reserved uintptr) ([]byte, error) {
	size := uint32(0)
	ret, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&size)), bOrder, ulAf, tableClass, reserved)
	if ret != 0 && (ret != errorInsufficientBuffer || size == 0) {
		return nil, fmt.Errorf("table size query failed: %d", ret)
	}
	if size == 0 {
		return nil, nil
	}
	return fetchWithRetry(size, func(buf []byte, need *uint32) uintptr {
		ret, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(need)), bOrder, ulAf, tableClass, reserved)
		return ret
	})
}

// fetchWithRetry 在 size 字节的缓冲区上取一次数据；表若在探测与取数之间变长
// （返回 errorInsufficientBuffer，且 *need 被更新为新的所需尺寸），就按新尺寸重取。
//
// 这一轮重试省不得：LookupWithRefresh 是数据包路径上的同步兜底，它失败就等于这一
// 条流识别不出来，直接落回 policyUndecided——白名单程序的连接悄悄走直连，而状态页
// 上看不出任何异常。此前四个调用点都是 `if ret != 0 { return err }` 直接放弃本轮，
// 把偶发的表增长变成了偶发的进程识别失败。
//
// 每轮都要求 *need 严格变大才继续，配合 maxTableAttempts，不可能空转或反复分配
// 同样大小的缓冲区。成功时返回完整缓冲区（不按 *need 截断），与旧行为一致。
func fetchWithRetry(size uint32, fetch func(buf []byte, need *uint32) uintptr) ([]byte, error) {
	for attempt := 1; ; attempt++ {
		buf := make([]byte, size)
		need := uint32(len(buf))
		ret := fetch(buf, &need)
		if ret == 0 {
			return buf, nil
		}
		if ret != errorInsufficientBuffer {
			return nil, fmt.Errorf("table fetch failed: %d", ret)
		}
		if attempt >= maxTableAttempts || need <= size {
			return nil, fmt.Errorf("table kept growing during query: needed %d bytes after %d attempt(s)", need, attempt)
		}
		size = need
	}
}
