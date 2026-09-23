package engine

import (
	"sync"
	"time"
)

// TCP flags
const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10
)

// isConnectionStart 判断这是不是"我们亲眼看到的连接起点"。
// 只认纯 SYN（SYN=1,ACK=0）：
//   - 反向的 SYN-ACK 是别人连进来的连接，不能被 SOCKS 劫持；
//   - 中途才看到的包一律不算起点。
func isConnectionStart(flags uint8) bool { return flags&tcpSYN != 0 && flags&tcpACK == 0 }

// policyKind 是一条流在第一次被看到时做出的路由决定，之后固定不变：
//
//	policyPass:       IPv4 直连放行 / IPv6 放行（进程识别成功，确定不劫持）
//	policyIntercept:  IPv4 劫持到 TProxy / IPv6 阻断（强制白名单程序回落 IPv4）
//	policyUndecided:  连接起点时没识别出进程，暂按放行处理；
//	                  只允许在"又是纯 SYN"（握手尚未完成）时重新评估一次，
//	                  绝不会对已建立的连接改道。
//
// 关键约束：连接一旦定型就不许再改。否则在 UI 上改白名单的瞬间，
// 正在传输的连接会被中途劫持（串包/RST）或中途阻断（挂死）。
type policyKind uint8

const (
	policyPass policyKind = iota
	policyIntercept
	policyUndecided
)

// flowKey 是原始 TCP 五元组。IPv4 写进前 4 字节，ver 保证两者不串。
type flowKey struct {
	srcIP   [16]byte
	dstIP   [16]byte
	srcPort uint16
	dstPort uint16
	ver     uint8
}

func flowKeyV4(srcIP, dstIP uint32, srcPort, dstPort uint16) flowKey {
	var k flowKey
	k.ver = 4
	k.srcIP[0] = byte(srcIP)
	k.srcIP[1] = byte(srcIP >> 8)
	k.srcIP[2] = byte(srcIP >> 16)
	k.srcIP[3] = byte(srcIP >> 24)
	k.dstIP[0] = byte(dstIP)
	k.dstIP[1] = byte(dstIP >> 8)
	k.dstIP[2] = byte(dstIP >> 16)
	k.dstIP[3] = byte(dstIP >> 24)
	k.srcPort, k.dstPort = srcPort, dstPort
	return k
}

type flowPolicyEntry struct {
	kind policyKind
	// mappedPort: IPv4 劫持时分配的 TProxy 映射端口；IPv6 阻断为 0。
	mappedPort uint16
	createdAt  time.Time
}

const (
	policySweepInterval = time.Minute
	policyPassTTL       = 15 * time.Minute // 直连记录的保留时间；过期后按"非起点→直连"重新推导，结果一致
	// policyBlockTTL 给 IPv6 阻断记录（mappedPort==0）一个上限。这类连接在 SYN 阶段
	// 就被丢弃，永远建立不起来，因而永远不会出现 FIN/RST 来触发清理——照旧"只由
	// FIN/RST 清"的话，正常路径下每条记录都会永久驻留，随白名单程序的 IPv6 重试
	// 无限累积。只需盖住 Windows 的 SYN 重试窗口（默认 4 次、约 45 秒）：到期后若还有
	// SYN 重传，isConnectionStart 为真会重新判定并再次阻断，结果一致；已建立的连接
	// 不可能属于这种记录，所以这里不存在"中途失效"的风险。
	policyBlockTTL = 5 * time.Minute
)

// flowPolicies 保存每条流的路由决定。
// 读路径只有 RLock（不在每包上抢写锁）；清理完全靠后台 sweep：
//   - policyPass           空闲到 TTL 后清除（重新推导仍是 pass，安全）
//   - policyIntercept+端口 代理连接还活着就一直留（以 ConnTrack 为准）
//   - policyIntercept+0    IPv6 阻断，只能由 FIN/RST 清除
type flowPolicies struct {
	mu        sync.RWMutex
	entries   map[flowKey]flowPolicyEntry
	tracker   *ConnTracker
	stopCh    chan struct{}
	closeOnce sync.Once
}

func newFlowPolicies(tracker *ConnTracker) *flowPolicies {
	p := &flowPolicies{
		entries: make(map[flowKey]flowPolicyEntry),
		tracker: tracker,
		stopCh:  make(chan struct{}),
	}
	go p.sweepLoop()
	return p
}

// Get 返回该流的定型结果与劫持时分配的映射端口（IPv6 阻断为 0）。
// 热路径靠 mappedPort 直接改写，不必再查 ConnTracker。
func (p *flowPolicies) Get(k flowKey) (policyKind, uint16, bool) {
	p.mu.RLock()
	e, ok := p.entries[k]
	p.mu.RUnlock()
	if !ok {
		return 0, 0, false
	}
	return e.kind, e.mappedPort, true
}

func (p *flowPolicies) Set(k flowKey, kind policyKind, mappedPort uint16) {
	p.mu.Lock()
	p.entries[k] = flowPolicyEntry{kind: kind, mappedPort: mappedPort, createdAt: time.Now()}
	p.mu.Unlock()
}

func (p *flowPolicies) Delete(k flowKey) {
	p.mu.Lock()
	delete(p.entries, k)
	p.mu.Unlock()
}

func (p *flowPolicies) Size() int {
	p.mu.RLock()
	n := len(p.entries)
	p.mu.RUnlock()
	return n
}

func (p *flowPolicies) sweepLoop() {
	t := time.NewTicker(policySweepInterval)
	defer t.Stop()
	for {
		select {
		case <-p.stopCh:
			return
		case <-t.C:
			p.sweep()
		}
	}
}

func (p *flowPolicies) sweep() {
	now := time.Now()
	p.mu.Lock()
	for k, v := range p.entries {
		keep := false
		switch {
		case v.kind == policyIntercept && v.mappedPort == 0:
			keep = now.Sub(v.createdAt) < policyBlockTTL // IPv6 阻断：FIN/RST 优先，否则等 TTL
		case v.kind == policyIntercept:
			keep = p.tracker != nil && p.tracker.HasMapped(v.mappedPort)
		default:
			keep = now.Sub(v.createdAt) < policyPassTTL
		}
		if !keep {
			delete(p.entries, k)
		}
	}
	p.mu.Unlock()
}

func (p *flowPolicies) Close() {
	p.closeOnce.Do(func() { close(p.stopCh) })
}
