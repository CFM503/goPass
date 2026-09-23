//go:build windows

package process

import "testing"

// B6 回归：两段式查询的第二步遇到 122 必须按更新后的尺寸重取。
//
// GetExtendedTcpTable/UdpTable 是"先问尺寸、再取数据"的两段式调用，两次调用之间
// 表一变长，第二步就返回 122 并把新尺寸写回。此前四个调用点都是直接
// `if ret != 0 { return err }` 放弃本轮，而 LookupWithRefresh 是数据包路径上的
// 同步兜底——它失败就等于这一条流识别不出来，直接落回 policyUndecided，
// 白名单程序的连接悄悄走直连，状态页上却看不出任何异常。
//
// 下面全部用注入的桩驱动，不碰真实网卡，因此是确定性的。
func TestFetchWithRetryGrowsBufferAndSucceeds(t *testing.T) {
	const probe = 1024
	grown := uint32(probe * 4)
	calls := 0

	buf, err := fetchWithRetry(probe, func(got []byte, need *uint32) uintptr {
		calls++
		if calls == 1 {
			*need = grown
			return errorInsufficientBuffer
		}
		if len(got) != int(grown) {
			t.Errorf("retry buf len=%d, want %d: 重取时没有用上更新后的尺寸", len(got), grown)
		}
		return 0
	})
	if err != nil {
		t.Fatalf("first attempt returned 122, retry should have succeeded: %v", err)
	}
	if calls != 2 {
		t.Fatalf("fetch called %d times, want 2 (必须真的重试一次)", calls)
	}
	if len(buf) != int(grown) {
		t.Fatalf("returned buf len=%d, want %d", len(buf), grown)
	}
}

// 一次性失败（非 122）不重试，直接把错误交出去。
func TestFetchWithRetryPassesThroughOtherErrors(t *testing.T) {
	const accessDenied = 5
	calls := 0

	_, err := fetchWithRetry(1024, func(got []byte, need *uint32) uintptr {
		calls++
		return accessDenied
	})
	if err == nil {
		t.Fatal("non-122 failure must surface as an error")
	}
	if calls != 1 {
		t.Fatalf("fetch called %d times, want 1: 别的错误码不该被当成尺寸竞态重试", calls)
	}
}

// 返回了 122 却没把尺寸改大：必须立刻停下，不能原地空转反复分配同样大小的缓冲区。
func TestFetchWithRetryStopsWhenSizeDoesNotGrow(t *testing.T) {
	calls := 0

	_, err := fetchWithRetry(1024, func(got []byte, need *uint32) uintptr {
		calls++
		return errorInsufficientBuffer // *need 原样未动
	})
	if err == nil {
		t.Fatal("a size race that never yields a bigger buffer must give up")
	}
	if calls != 1 {
		t.Fatalf("fetch called %d times, want 1: 尺寸没变大时必须立刻放弃", calls)
	}
}

// 表一直变长时靠 maxTableAttempts 收口，而不是无限分配。
func TestFetchWithRetryGivesUpAfterMaxAttempts(t *testing.T) {
	calls := 0

	_, err := fetchWithRetry(1024, func(got []byte, need *uint32) uintptr {
		calls++
		*need = *need * 2
		return errorInsufficientBuffer
	})
	if err == nil {
		t.Fatal("persistent growth must eventually give up")
	}
	if calls != maxTableAttempts {
		t.Fatalf("fetch called %d times, want %d", calls, maxTableAttempts)
	}
}

// 正常路径：一次成功就返回，不额外调用。
func TestFetchWithRetrySucceedsOnFirstTry(t *testing.T) {
	calls := 0

	buf, err := fetchWithRetry(512, func(got []byte, need *uint32) uintptr {
		calls++
		return 0
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("fetch called %d times, want 1", calls)
	}
	if len(buf) != 512 {
		t.Fatalf("buf len=%d, want 512", len(buf))
	}
}
