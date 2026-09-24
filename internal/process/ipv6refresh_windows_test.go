//go:build windows

package process

import (
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 本文件测两条真实的 IPv6 刷新路径（refreshWith），表、进程名解析、缓存三个依赖
// 全部注入，因此不碰真实网卡与真实进程表。

// buildIPv6UDPRow 构造一行 MIB_UDP6ROW_OWNER_PID（28 字节，udp_mib.h）：
// ucLocalAddr[16]@0  dwLocalScopeId@16  dwLocalPort@20  dwOwningPid@24
func buildIPv6UDPRow(local [16]byte, port uint16, pid uint32) []byte {
	row := make([]byte, 28)
	copy(row[0:16], local[:])
	binary.LittleEndian.PutUint32(row[16:20], 0)
	putNetworkOrderPort(row[20:24], port)
	binary.LittleEndian.PutUint32(row[24:28], pid)
	return row
}

// buildIPv6UDPTable 组装 count 头 + 若干行。
func buildIPv6UDPTable(rows ...[]byte) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(len(rows)))
	for _, r := range rows {
		buf = append(buf, r...)
	}
	return buf
}

// tcpTableWithPID 构造一张 rows 行、全部同 PID、端口各不相同的 IPv6 TCP 表。
func tcpTableWithPID(pid uint32, rows int) []byte {
	table := make([][]byte, 0, rows)
	for i := 0; i < rows; i++ {
		var remote [16]byte
		remote[0], remote[15] = 0x20, byte(i+1)
		table = append(table, buildIPv6TCPRow(testLocalIPv6, remote, uint16(40000+i), 443, mibTCPStateEstab, pid))
	}
	return buildIPv6TCPTable(table...)
}

// udpTableWithPID 同上，UDP 侧。
func udpTableWithPID(pid uint32, rows int) []byte {
	table := make([][]byte, 0, rows)
	for i := 0; i < rows; i++ {
		table = append(table, buildIPv6UDPRow(testLocalIPv6, uint16(50000+i), pid))
	}
	return buildIPv6UDPTable(table...)
}

// P2 回归：200ms 门必须把并发刷新串起来。
//
// 原来的门是「RLock 里读 last、解锁之后才去查表」——检查与行动之间没有任何东西
// 挡着，一次未命中的突发就能放进 N 个 goroutine 同时跑 GetExtendedTcpTable 加全表
// 进程名解析，而这正发生在数据包路径上。
func TestIPv6TCPRefreshSerializesConcurrentCalls(t *testing.T) {
	var inFlight, peak, queries atomic.Int32
	query := func() ([]byte, error) {
		queries.Add(1)
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		inFlight.Add(-1)
		return tcpTableWithPID(4242, 3), nil
	}

	r := &ipv6TCPResolver{flows: make(map[IPv6TCPFlow]string)}
	d := ipv6RefreshDeps{query: query, cache: newPIDNameCache(), resolve: func(uint32) string { return "chrome.exe" }}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r.refreshWith(d) }()
	}
	wg.Wait()

	if peak.Load() != 1 {
		t.Errorf("同时在查表的 goroutine 峰值 = %d, 想要 1: 200ms 门是先读后写，挡不住并发", peak.Load())
	}
	if queries.Load() != 1 {
		t.Errorf("查表 %d 次, 想要 1 次: 窗口内不该重复查询", queries.Load())
	}
	r.mu.RLock()
	n := len(r.flows)
	r.mu.RUnlock()
	if n != 3 {
		t.Errorf("flows = %d, want 3", n)
	}
}

// 对照：串行的第二次调用同样被窗口挡掉，不依赖并发。
func TestIPv6TCPRefreshRateLimitsSequentialCalls(t *testing.T) {
	var queries atomic.Int32
	query := func() ([]byte, error) { queries.Add(1); return tcpTableWithPID(4242, 1), nil }

	r := &ipv6TCPResolver{flows: make(map[IPv6TCPFlow]string)}
	d := ipv6RefreshDeps{query: query, cache: newPIDNameCache(), resolve: func(uint32) string { return "chrome.exe" }}

	r.refreshWith(d)
	r.refreshWith(d)
	if queries.Load() != 1 {
		t.Fatalf("查表 %d 次, 想要 1 次", queries.Load())
	}
}

// 对照：失败既不推进窗口（下一次可立即重试），也不动已有快照。
func TestIPv6TCPRefreshRetriesImmediatelyAfterFailure(t *testing.T) {
	var queries atomic.Int32
	boom := errors.New("boom")
	query := func() ([]byte, error) { queries.Add(1); return nil, boom }

	keep := IPv6TCPFlow{LocalIP: testLocalIPv6, LocalPort: 1, RemoteIP: testRemoteIPv6, RemotePort: 2}
	r := &ipv6TCPResolver{flows: map[IPv6TCPFlow]string{keep: "keepme"}}
	d := ipv6RefreshDeps{query: query, cache: newPIDNameCache(), resolve: func(uint32) string { return "chrome.exe" }}

	r.refreshWith(d)
	r.refreshWith(d)
	if queries.Load() != 2 {
		t.Errorf("查表 %d 次, 想要 2 次: 查询失败后不能把窗口推进，否则下一次重试会被 200ms 挡掉", queries.Load())
	}
	r.mu.RLock()
	name, ok := r.flows[keep]
	r.mu.RUnlock()
	if !ok || name != "keepme" {
		t.Errorf("失败的刷新不该改动快照，got %q/%v", name, ok)
	}
}

// P1 回归：刷新路径必须经缓存取名——6 行同一个 PID 只解析一次。
func TestIPv6TCPRefreshResolvesEachPIDOnce(t *testing.T) {
	var calls atomic.Int32
	resolve := func(uint32) string { calls.Add(1); return "chrome.exe" }

	r := &ipv6TCPResolver{flows: make(map[IPv6TCPFlow]string)}
	d := ipv6RefreshDeps{query: func() ([]byte, error) { return tcpTableWithPID(4242, 6), nil }, cache: newPIDNameCache(), resolve: resolve}

	r.refreshWith(d)
	if calls.Load() != 1 {
		t.Errorf("resolve 调用 %d 次, 想要 1 次: 6 行同一个 PID，刷新绕过了进程名缓存", calls.Load())
	}
	r.mu.RLock()
	n := len(r.flows)
	r.mu.RUnlock()
	if n != 6 {
		t.Errorf("flows = %d, want 6", n)
	}
}

// UDP 侧同样要串起来：它是另一把门、另一个结构体。
func TestIPv6UDPRefreshSerializesConcurrentCalls(t *testing.T) {
	var inFlight, peak, queries atomic.Int32
	query := func() ([]byte, error) {
		queries.Add(1)
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		inFlight.Add(-1)
		return udpTableWithPID(4242, 3), nil
	}

	r := &ipv6UDPResolver{m: make(map[IPv6UDPFlow]string)}
	d := ipv6RefreshDeps{query: query, cache: newPIDNameCache(), resolve: func(uint32) string { return "chrome.exe" }}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r.refreshWith(d) }()
	}
	wg.Wait()

	if peak.Load() != 1 {
		t.Errorf("同时在查表的 goroutine 峰值 = %d, 想要 1", peak.Load())
	}
	if queries.Load() != 1 {
		t.Errorf("查表 %d 次, 想要 1 次", queries.Load())
	}
}

// UDP 侧同样要走缓存。
func TestIPv6UDPRefreshResolvesEachPIDOnce(t *testing.T) {
	var calls atomic.Int32
	resolve := func(uint32) string { calls.Add(1); return "chrome.exe" }

	r := &ipv6UDPResolver{m: make(map[IPv6UDPFlow]string)}
	d := ipv6RefreshDeps{query: func() ([]byte, error) { return udpTableWithPID(4242, 5), nil }, cache: newPIDNameCache(), resolve: resolve}

	r.refreshWith(d)
	if calls.Load() != 1 {
		t.Errorf("resolve 调用 %d 次, 想要 1 次: UDP 刷新绕过了进程名缓存", calls.Load())
	}
	r.mu.RLock()
	n := len(r.m)
	r.mu.RUnlock()
	if n != 5 {
		t.Errorf("flows = %d, want 5", n)
	}
}

// UDP 行布局单独钉死：此前它是 refreshIPv6UDP 里的一段内联代码，没有测试覆盖。
func TestParseIPv6UDPRowsDecodesEveryField(t *testing.T) {
	row := buildIPv6UDPRow(testLocalIPv6, 5353, 4242)
	got := parseIPv6UDPRows(buildIPv6UDPTable(row), nameByPID(4242))
	if len(got) != 1 {
		t.Fatalf("entries=%d, want 1", len(got))
	}
	var key IPv6UDPFlow
	var name string
	for k, v := range got {
		key, name = k, v
	}
	if key.LocalIP != testLocalIPv6 {
		t.Errorf("LocalIP=%v, want %v", key.LocalIP, testLocalIPv6)
	}
	if key.LocalPort != 5353 {
		t.Errorf("LocalPort=%d, want 5353", key.LocalPort)
	}
	if name != "chrome.exe" {
		t.Errorf("name=%q, want chrome.exe", name)
	}
}

// 解析不出进程名的行整行丢弃，否则会把别人的流量算到白名单头上。
func TestParseIPv6UDPRowsDropsUnknownPID(t *testing.T) {
	row := buildIPv6UDPRow(testLocalIPv6, 5353, 4242)
	if got := parseIPv6UDPRows(buildIPv6UDPTable(row), nameByPID(999)); len(got) != 0 {
		t.Fatalf("unresolved pid must be dropped, got %d entries", len(got))
	}
}

// 表在两次查询之间变长时会拿到截断缓冲区：必须安全停下，不得越界 panic。
func TestParseIPv6UDPRowsHandlesTruncatedBuffer(t *testing.T) {
	for _, size := range []int{0, 2, 4, 5, 4 + 27, 4 + 28} {
		buf := make([]byte, size)
		if size >= 4 {
			binary.LittleEndian.PutUint32(buf, 1) // 声称 1 行，缓冲区可能不够
		}
		if got := parseIPv6UDPRows(buf, nameByPID(4242)); len(got) != 0 {
			t.Fatalf("size=%d: truncated buffer must yield 0 entries, got %d", size, len(got))
		}
	}
}
