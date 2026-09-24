//go:build windows

package process

import (
	"encoding/binary"
	"sync"
	"time"
)

// afInet6 是 GetExtendedTcpTable / GetExtendedUdpTable 的地址族参数。
const afInet6 = 23

// ipv6RefreshMinInterval 是 IPv6 两张表的刷新下限：窗口内不重复查询。
const ipv6RefreshMinInterval = 200 * time.Millisecond

// ipv6RefreshDeps 是一次 IPv6 刷新的三个注入点：表从哪来、进程名怎么解析、解析
// 结果缓存在哪。生产用 queryWinTable + processName + ipv6PIDNames，测试三个全
// 传桩，因此刷新路径本身可以脱离真实网卡被测。
type ipv6RefreshDeps struct {
	query   func() ([]byte, error)
	cache   *pidNameCache
	resolve func(uint32) string
}

func liveIPv6TCPDeps() ipv6RefreshDeps {
	return ipv6RefreshDeps{
		query:   func() ([]byte, error) { return queryWinTable(getExtendedTCPTable, 1, afInet6, tcpTableOwnerPidAll, 0) },
		cache:   ipv6PIDNames,
		resolve: processName,
	}
}

func liveIPv6UDPDeps() ipv6RefreshDeps {
	return ipv6RefreshDeps{
		query:   func() ([]byte, error) { return queryWinTable(getExtendedUDPTable, 1, afInet6, udpTableOwnerPid, 0) },
		cache:   ipv6PIDNames,
		resolve: processName,
	}
}

// refreshGate 给一次表刷新串行化并限速。
//
// 原来的门是“先读后写”：RLock 里读 last、解锁之后才去查表，检查与行动之间没有
// 任何东西挡着，于是并发调用能一起通过检查、各自跑一遍完整的表查询加全表进程名
// 解析。而这发生在数据包路径上——一次未命中的突发就能放进 N 个 goroutine 同时
// 查表。
//
// 现在 run 把“检查 + 查询 + 提交”整段串行化（对齐 IPv4 LookupWithRefresh 的
// fallbackMu）：排到队首时若窗口内已有成功快照就直接返回——快照本来就是新的；
// 排在后面的 goroutine 等它查完再进来，看到的同样是新快照，不会重复查询，而重
// 新查一次表正是它们原本想要的。
//
// 失败不推进窗口，下一个排到的仍可立即重试，保留原来“取不到就让下一次立刻重
// 试”的语义。last 只在持有 op 时读写。
type refreshGate struct {
	op   sync.Mutex
	last time.Time
}

// run 在 g 的保护下执行一次刷新。work 返回 true 表示拿到了新快照（并已自行提
// 交），此时才把窗口推到当前时刻；interval 是两次成功刷新之间的下限。
func (g *refreshGate) run(interval time.Duration, work func() bool) {
	g.op.Lock()
	defer g.op.Unlock()
	if time.Since(g.last) < interval {
		return
	}
	if !work() {
		return
	}
	g.last = time.Now()
}

// refreshWith 是 ipv6TCPResolver.refresh 的可测形态：表、解析器、缓存全部注入。
func (r *ipv6TCPResolver) refreshWith(d ipv6RefreshDeps) {
	r.gate.run(ipv6RefreshMinInterval, func() bool {
		buf, err := d.query()
		// 取不到（含空表）就保留上一次快照且不推进窗口，下一次调用可立即重试。
		if err != nil || len(buf) == 0 {
			return false
		}
		now := time.Now()
		d.cache.sweep(now)
		flows := parseIPv6TCPRows(buf, func(pid uint32) string { return d.cache.get(pid, now, d.resolve) })
		r.mu.Lock()
		r.flows = flows
		r.mu.Unlock()
		return true
	})
}

// refreshWith 是 refreshIPv6UDP 的可测形态，语义与 TCP 侧一致。
func (r *ipv6UDPResolver) refreshWith(d ipv6RefreshDeps) {
	r.gate.run(ipv6RefreshMinInterval, func() bool {
		buf, err := d.query()
		if err != nil || len(buf) == 0 {
			return false
		}
		now := time.Now()
		d.cache.sweep(now)
		flows := parseIPv6UDPRows(buf, func(pid uint32) string { return d.cache.get(pid, now, d.resolve) })
		r.mu.Lock()
		r.m = flows
		r.mu.Unlock()
		return true
	})
}

// parseIPv6UDPRows 解析 GetExtendedUdpTable(AF_INET6, UDP_TABLE_OWNER_PID) 的缓冲区。
// MIB_UDP6ROW_OWNER_PID 恰好 28 字节（udp_mib.h）：
//
//	ucLocalAddr[16]@0  dwLocalScopeId@16  dwLocalPort@20  dwOwningPid@24
//
// 端口与 TCP 侧一样以网络字序存进 DWORD。UDP 行没有状态字段，也就没有死行可跳。
// nameOf 生产路径是带缓存的取名函数，测试传桩。
func parseIPv6UDPRows(buf []byte, nameOf func(uint32) string) map[IPv6UDPFlow]string {
	if len(buf) < 4 {
		return nil
	}
	count := binary.LittleEndian.Uint32(buf[0:4])
	const rowSize = 28
	flows := make(map[IPv6UDPFlow]string, count)
	for n := uint32(0); n < count; n++ {
		off := 4 + n*rowSize
		if off+rowSize > uint32(len(buf)) {
			break
		}
		row := buf[off : off+rowSize]
		var localIP [16]byte
		copy(localIP[:], row[0:16])
		localPort := ntohs(uint16(binary.LittleEndian.Uint32(row[20:24])))
		pid := binary.LittleEndian.Uint32(row[24:28])
		name := nameOf(pid)
		if name == "" {
			continue
		}
		flows[IPv6UDPFlow{LocalIP: localIP, LocalPort: localPort}] = name
	}
	return flows
}
