//go:build windows

package process

import (
	"syscall"
	"testing"
)

// errAccessDenied 是"加大缓冲也没用"的那类失败：ERROR_ACCESS_DENIED。
const errAccessDenied = syscall.Errno(5)

// P3 回归：只有 122（ERROR_INSUFFICIENT_BUFFER）才值得重试。
//
// processName 此前从不读错误码，任何失败都翻倍重取：一个被拒绝访问的 PID 要空跑
// 260→520→…→33280 共 8 轮系统调用加 8 次分配，最后照样返回 ""。它挂在进程名缓存
// 未命中的路径上，refreshTCP/refreshUDP 每行 PID 都要过一遍。
func TestQueryUTF16GivesUpImmediatelyOnNonBufferError(t *testing.T) {
	calls := 0
	got, n, ok := queryUTF16WithRetry(260, func(buf []uint16, need *uint32) (bool, error) {
		calls++
		return false, errAccessDenied
	})
	if ok {
		t.Fatal("an access-denied failure must not be reported as success")
	}
	if calls != 1 {
		t.Fatalf("called %d times, want 1: 非 122 的失败不该被当成缓冲不足重试", calls)
	}
	if got != nil || n != 0 {
		t.Fatalf("failed query returned buf=%v n=%d, want nil/0", got, n)
	}
}

// 失败了却没留下错误码：同样不能当成缓冲不足，否则又会退回无限翻倍。
func TestQueryUTF16TreatsMissingErrnoAsFatal(t *testing.T) {
	calls := 0
	_, _, ok := queryUTF16WithRetry(260, func(buf []uint16, need *uint32) (bool, error) {
		calls++
		return false, nil
	})
	if ok {
		t.Fatal("a failure without an errno must not be reported as success")
	}
	if calls != 1 {
		t.Fatalf("called %d times, want 1: 没有错误码时同样只能调一次", calls)
	}
}

// 122 必须翻倍重取，且下一轮用的是"翻倍后的尺寸"而不是调用方写回的 *need——
// QueryFullProcessImageNameW 不承诺在失败时回填所需长度，照它分配会得到一个
// 随口报的大缓冲。
func TestQueryUTF16GrowsBufferOnInsufficientBuffer(t *testing.T) {
	const start = 260
	calls := 0
	var lens []int

	got, n, ok := queryUTF16WithRetry(start, func(buf []uint16, need *uint32) (bool, error) {
		calls++
		lens = append(lens, len(buf))
		if calls == 1 {
			*need = 1_000_000 // 声称要 100 万字符
			return false, syscall.Errno(errorInsufficientBuffer)
		}
		copy(buf, []uint16{'c', ':', '\\', 'a', '.', 'e', 'x', 'e'})
		*need = 8
		return true, nil
	})
	if !ok {
		t.Fatal("a retry after 122 should have succeeded")
	}
	if calls != 2 {
		t.Fatalf("called %d times, want 2: 必须真的重试一次", calls)
	}
	if len(lens) != 2 || lens[0] != start || lens[1] != start*2 {
		t.Fatalf("buffer lengths %v, want [%d %d]: 没有按翻倍尺寸重取", lens, start, start*2)
	}
	if n != 8 {
		t.Fatalf("wrote %d chars, want 8", n)
	}
	if len(got) < 8 {
		t.Fatalf("returned buffer too short: %d", len(got))
	}
}

// 先 122 后别的错：第二次就必须停手，不能继续翻倍。
func TestQueryUTF16StopsWhenErrorChanges(t *testing.T) {
	calls := 0
	_, _, ok := queryUTF16WithRetry(260, func(buf []uint16, need *uint32) (bool, error) {
		calls++
		if calls == 1 {
			return false, syscall.Errno(errorInsufficientBuffer)
		}
		return false, errAccessDenied
	})
	if ok {
		t.Fatal("the second failure must not be reported as success")
	}
	if calls != 2 {
		t.Fatalf("called %d times, want 2: 换成别的错误码后必须立刻收手", calls)
	}
}

// 持续 122 时靠 maxUTF16Buffer 收口，不能无限翻倍分配。
func TestQueryUTF16StopsAtSizeCap(t *testing.T) {
	calls := 0
	_, _, ok := queryUTF16WithRetry(260, func(buf []uint16, need *uint32) (bool, error) {
		calls++
		*need = uint32(len(buf) * 4) // 每一轮都要求更大
		return false, syscall.Errno(errorInsufficientBuffer)
	})
	if ok {
		t.Fatal("persistent growth must eventually give up")
	}
	// 260→520→1040→2080→4160→8320→16640→33280；第 8 轮时 33280 >= 32768，收手。
	if calls != 8 {
		t.Fatalf("called %d times, want 8: 上限失控（改动前的放弃条件是同一个）", calls)
	}
}

// 正常路径：一次成功就返回。
func TestQueryUTF16SucceedsOnFirstTry(t *testing.T) {
	calls := 0
	got, n, ok := queryUTF16WithRetry(260, func(buf []uint16, need *uint32) (bool, error) {
		calls++
		copy(buf, []uint16{'n', 'o', 't', 'e', '.', 'e', 'x', 'e'})
		*need = 8
		return true, nil
	})
	if !ok {
		t.Fatal(errAccessDenied)
	}
	if calls != 1 {
		t.Fatalf("called %d times, want 1: 成功不该多调", calls)
	}
	if n != 8 {
		t.Fatalf("wrote %d chars, want 8", n)
	}
	if string(utf16ToASCII(got[:n])) != "note.exe" {
		t.Fatalf("got %q, want %q", utf16ToASCII(got[:n]), "note.exe")
	}
}

// 成功却报告了超过缓冲长度的字符数：必须夹住，否则下面的 buf[:n] 会越界 panic。
func TestQueryUTF16ClampsOversizedLength(t *testing.T) {
	got, n, ok := queryUTF16WithRetry(4, func(buf []uint16, need *uint32) (bool, error) {
		*need = 9999
		return true, nil
	})
	if !ok {
		t.Fatal("query reported success")
	}
	if int(n) > len(got) {
		t.Fatalf("n=%d exceeds buffer length %d: 越界切片会 panic", n, len(got))
	}
	if int(n) != len(got) {
		t.Fatalf("n=%d, want it clamped to %d", n, len(got))
	}
}

// utf16ToASCII 仅用于断言，避开额外依赖。
func utf16ToASCII(b []uint16) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		out = append(out, byte(c))
	}
	return out
}
