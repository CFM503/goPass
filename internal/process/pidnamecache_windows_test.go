//go:build windows

package process

import (
	"testing"
	"time"
)

// P1 回归：IPv6 的两条刷新路径此前每行都实打实调 processName（每次三次系统调用），
// 而 IPv4 侧一直有 2 秒 TTL 的 PID 缓存。下面用注入的计数桩驱动，不碰真实进程表。

// TTL 内的第二次取名必须命中缓存。
func TestPIDNameCacheServesWithinTTL(t *testing.T) {
	var calls int
	resolve := func(uint32) string { calls++; return "chrome.exe" }
	c := newPIDNameCache()
	now := time.Now()

	if got := c.get(4242, now, resolve); got != "chrome.exe" {
		t.Fatalf("first get = %q, want chrome.exe", got)
	}
	if got := c.get(4242, now.Add(time.Second), resolve); got != "chrome.exe" {
		t.Fatalf("second get = %q, want chrome.exe", got)
	}
	if calls != 1 {
		t.Fatalf("resolve called %d times, want 1: TTL 内必须命中缓存", calls)
	}
}

// 刚好等于 TTL 就要重新解析（读侧判据是严格小于）。
func TestPIDNameCacheExpiresAfterTTL(t *testing.T) {
	var calls int
	resolve := func(uint32) string { calls++; return "chrome.exe" }
	c := newPIDNameCache()
	now := time.Now()

	c.get(4242, now, resolve)
	c.get(4242, now.Add(pidNameCacheTTL), resolve)
	if calls != 2 {
		t.Fatalf("resolve called %d times, want 2: 过期后必须重新解析", calls)
	}
}

// 解析不出来（返回空串）同样要按 TTL 记账：受保护进程永远解析不出来，不缓存的话
// 每个刷新周期都要白跑三次系统调用。
func TestPIDNameCacheCachesEmptyResult(t *testing.T) {
	var calls int
	resolve := func(uint32) string { calls++; return "" }
	c := newPIDNameCache()
	now := time.Now()

	if got := c.get(7, now, resolve); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
	c.get(7, now.Add(time.Second), resolve)
	if calls != 1 {
		t.Fatalf("resolve called %d times, want 1: 解析失败也必须缓存", calls)
	}
}

// PID 0 直接短路，既不解析也不落缓存。
func TestPIDNameCacheSkipsZeroPID(t *testing.T) {
	var calls int
	resolve := func(uint32) string { calls++; return "chrome.exe" }
	c := newPIDNameCache()

	if got := c.get(0, time.Now(), resolve); got != "" {
		t.Fatalf("pid 0 got %q, want empty", got)
	}
	if calls != 0 {
		t.Fatalf("resolve called %d times for pid 0, want 0", calls)
	}
	if len(c.entries) != 0 {
		t.Fatalf("pid 0 must not be cached, got %d entries", len(c.entries))
	}
}

// sweep 只清过期条目：清多了会让缓存抖动，清少了内存会随 PID 累积。
func TestPIDNameCacheSweepDropsExpiredOnly(t *testing.T) {
	c := newPIDNameCache()
	now := time.Now()
	c.entries[1] = pidCacheEntry{name: "fresh.exe", checkedAt: now.Add(-time.Second)}
	c.entries[2] = pidCacheEntry{name: "stale.exe", checkedAt: now.Add(-2 * pidNameCacheTTL)}

	c.sweep(now)

	if _, ok := c.entries[1]; !ok {
		t.Error("TTL 内的条目被清掉了：缓存会失去意义")
	}
	if _, ok := c.entries[2]; ok {
		t.Error("过期条目没被清掉：内存会随 PID 数量累积")
	}
	if len(c.entries) != 1 {
		t.Errorf("entries = %d, want 1", len(c.entries))
	}
}
