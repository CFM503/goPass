//go:build windows

package process

import (
	"sync"
	"time"
)

// pidNameCache 按 PID 缓存进程名，有效期是 pidNameCacheTTL（2 秒）。
//
// 解析一个进程名要三次系统调用（OpenProcess + QueryFullProcessImageNameW +
// CloseHandle），而进程名本身不会变。IPv4 的 refreshTCP/refreshUDP 一直走
// Resolver 上的 cachedProcessName，IPv6 这两条刷新路径此前没有缓存：每次刷新
// 对每一行都实打实查一遍——刷新每秒一轮，数据包路径上未命中时还会当场再刷一次。
//
// 解析失败（返回空串）同样按 TTL 记账：受保护进程永远解析不出来，不缓存的话
// 每个刷新周期都要白跑三次系统调用。
//
// 清理按 TTL 而不是按“表里还见不见得到”：超过 TTL 的条目本来就不会被读到，删掉
// 永远安全；而“没在某张表里出现”不等于进程没了——UDP-only 的进程、或者只开 IPv6
// 连接的进程，在 IPv4 的 TCP 表里就是看不见的。
type pidNameCache struct {
	mu      sync.RWMutex
	entries map[uint32]pidCacheEntry
}

// ipv6PIDNames 是 IPv6 TCP / UDP 两条刷新路径共用的进程名缓存：同一个 PID 在
// 两张表里是同一个进程，各存一份没有意义。
var ipv6PIDNames = newPIDNameCache()

func newPIDNameCache() *pidNameCache {
	return &pidNameCache{entries: make(map[uint32]pidCacheEntry)}
}

// get 返回 pid 的进程名；命中且未过期直接回缓存，否则调 resolve 并写回。
// resolve 由调用方注入：生产传 processName，测试传桩。
func (c *pidNameCache) get(pid uint32, now time.Time, resolve func(uint32) string) string {
	if pid == 0 {
		return ""
	}
	c.mu.RLock()
	e, ok := c.entries[pid]
	c.mu.RUnlock()
	if ok && now.Sub(e.checkedAt) < pidNameCacheTTL {
		return e.name
	}
	name := resolve(pid)
	c.mu.Lock()
	c.entries[pid] = pidCacheEntry{name: name, checkedAt: now}
	c.mu.Unlock()
	return name
}

// sweep 删掉已过期的条目。刷新路径每次查表前调一次，把内存钉在“最近 2 秒见过
// 的 PID”上。
func (c *pidNameCache) sweep(now time.Time) {
	c.mu.Lock()
	for pid, e := range c.entries {
		if now.Sub(e.checkedAt) >= pidNameCacheTTL {
			delete(c.entries, pid)
		}
	}
	c.mu.Unlock()
}
