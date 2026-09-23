package engine

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/CFM503/goPass/internal/process"
)

func newTestInterceptor(t *testing.T, whitelist ...string) *Interceptor {
	t.Helper()
	ct := NewConnTracker(60, 600, 7893)
	i := NewInterceptor(ct, "1.2.3.4", 1080, 7893, whitelist)
	t.Cleanup(func() {
		i.Close()
		ct.Close()
	})
	return i
}

func u32le(a, b, c, d byte) uint32 {
	return uint32(a) | uint32(b)<<8 | uint32(c)<<16 | uint32(d)<<24
}

// buildTCPPacket 构造最小 IPv4+TCP 包：20 字节 IP 头 + 20 字节 TCP 头。
func buildTCPPacket(srcIP, dstIP uint32, srcPort, dstPort uint16, flags byte) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45 // v4, IHL=5
	pkt[9] = 6    // TCP
	binary.LittleEndian.PutUint32(pkt[12:16], srcIP)
	binary.LittleEndian.PutUint32(pkt[16:20], dstIP)
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	pkt[33] = flags
	return pkt
}

func testSrcIP() uint32 { return u32le(192, 168, 1, 5) }
func testDstIP() uint32 { return u32le(8, 8, 8, 8) }

func TestIsConnectionStart(t *testing.T) {
	cases := []struct {
		flags byte
		want  bool
	}{
		{tcpSYN, true},           // 纯 SYN = 起点
		{tcpSYN | 0x08, true},    // SYN + ECE 仍算起点
		{tcpSYN | tcpACK, false}, // SYN-ACK = 别人连进来的连接
		{tcpACK, false},          // 中途 ACK
		{tcpACK | 0x08, false},   // PSH-ACK = 中途
		{tcpFIN | tcpACK, false}, // 关闭
		{tcpRST, false},          // 复位
		{0, false},               // 无标志
	}
	for _, c := range cases {
		if got := isConnectionStart(c.flags); got != c.want {
			t.Errorf("isConnectionStart(%#x)=%v want %v", c.flags, got, c.want)
		}
	}
}

func TestDecideNewFlowRules(t *testing.T) {
	i := newTestInterceptor(t, "chrome.exe")
	calls := 0
	lookup := func(name string, ok bool) func() (string, bool) {
		return func() (string, bool) { calls++; return name, ok }
	}

	// 不是连接起点 → 放行，且根本不做进程识别
	calls = 0
	if got := i.decideNewFlow(false, lookup("chrome.exe", true)); got != policyPass {
		t.Fatalf("non-start = %v, want policyPass", got)
	}
	if calls != 0 {
		t.Fatalf("lookup called %d times for non-start flow, want 0", calls)
	}

	// 起点 + 识别失败 → 暂按放行，但允许在握手期间的下一个 SYN 重试
	if got := i.decideNewFlow(true, lookup("", false)); got != policyUndecided {
		t.Fatalf("unknown process = %v, want policyUndecided", got)
	}

	// 起点 + 白名单进程 → 劫持(v4)/阻断(v6)
	if got := i.decideNewFlow(true, lookup("chrome.exe", true)); got != policyIntercept {
		t.Fatalf("whitelisted = %v, want policyIntercept", got)
	}

	// 起点 + 非白名单 → 放行
	if got := i.decideNewFlow(true, lookup("other.exe", true)); got != policyPass {
		t.Fatalf("non-whitelisted = %v, want policyPass", got)
	}
}

// 回归（R1 核心）：流定型后，改白名单不能再改变它的路由。
func TestFlowIsLockedAfterFirstDecision(t *testing.T) {
	i := newTestInterceptor(t) // 初始白名单为空
	lookups := 0
	i.lookupName = func(process.Flow) (string, bool) { lookups++; return "chrome.exe", true }

	// 第一次：白名单为空 → 锁定直连
	i.handleIPv4TCP(nil, buildTCPPacket(testSrcIP(), testDstIP(), 50000, 443, tcpSYN), &winDivertAddress{}, 20)
	if lookups != 1 {
		t.Fatalf("lookups=%d want 1", lookups)
	}
	key := flowKeyV4(testSrcIP(), testDstIP(), 50000, 443)
	if kind, _, ok := i.policies.Get(key); !ok || kind != policyPass {
		t.Fatalf("after first packet: kind=%v ok=%v, want policyPass", kind, ok)
	}

	// 用户现在把 chrome.exe 加进白名单
	i.SetWhitelist([]string{"chrome.exe"})

	// 同一条流的后续包（含 SYN 重传）绝不再重新评估
	i.handleIPv4TCP(nil, buildTCPPacket(testSrcIP(), testDstIP(), 50000, 443, tcpSYN), &winDivertAddress{}, 20)
	i.handleIPv4TCP(nil, buildTCPPacket(testSrcIP(), testDstIP(), 50000, 443, tcpACK|0x08), &winDivertAddress{}, 20)

	if lookups != 1 {
		t.Fatalf("locked flow re-evaluated: lookups=%d want 1", lookups)
	}
	if kind, _, ok := i.policies.Get(key); !ok || kind != policyPass {
		t.Fatalf("locked flow changed: kind=%v ok=%v, want policyPass", kind, ok)
	}
}

// 回归（R1 核心）：中途才看到的连接（没有 SYN）绝不劫持。
func TestMidStreamFlowIsNeverHijacked(t *testing.T) {
	i := newTestInterceptor(t, "chrome.exe")
	lookups := 0
	i.lookupName = func(process.Flow) (string, bool) { lookups++; return "chrome.exe", true }

	// 第一个包就是 PSH-ACK：连接在 GoPass 启动前就建立了
	i.handleIPv4TCP(nil, buildTCPPacket(testSrcIP(), testDstIP(), 50001, 443, tcpACK|0x08), &winDivertAddress{}, 20)

	if lookups != 0 {
		t.Fatalf("mid-stream flow triggered process lookup: %d, want 0", lookups)
	}
	key := flowKeyV4(testSrcIP(), testDstIP(), 50001, 443)
	if kind, _, ok := i.policies.Get(key); !ok || kind != policyPass {
		t.Fatalf("mid-stream kind=%v ok=%v, want policyPass", kind, ok)
	}
}

// 识别失败的连接：暂按直连，但握手期间的下一个 SYN 必须允许重试；
// 中途的 ACK 则不重试（不能对已建立的连接改道）。
func TestUndecidedFlowRetriesOnlyOnSYN(t *testing.T) {
	i := newTestInterceptor(t, "chrome.exe")
	lookups := 0
	unknown := true
	i.lookupName = func(process.Flow) (string, bool) {
		lookups++
		if unknown {
			return "", false
		}
		return "chrome.exe", true
	}
	src, dst := testSrcIP(), testDstIP()

	// SYN：识别失败 → undecided，按直连放行
	i.handleIPv4TCP(nil, buildTCPPacket(src, dst, 50003, 443, tcpSYN), &winDivertAddress{}, 20)
	key := flowKeyV4(src, dst, 50003, 443)
	if kind, _, ok := i.policies.Get(key); !ok || kind != policyUndecided {
		t.Fatalf("kind=%v ok=%v, want policyUndecided", kind, ok)
	}
	if lookups != 1 {
		t.Fatalf("lookups=%d want 1", lookups)
	}

	// 中途 ACK：不重新评估（握手已进行中，不允许改道）
	i.handleIPv4TCP(nil, buildTCPPacket(src, dst, 50003, 443, tcpACK), &winDivertAddress{}, 20)
	if lookups != 1 {
		t.Fatalf("ACK re-evaluated: lookups=%d want 1", lookups)
	}

	// SYN 重传 + 进程表已就绪 → 允许重试
	unknown = false
	i.handleIPv4TCP(nil, buildTCPPacket(src, dst, 50003, 443, tcpSYN), &winDivertAddress{}, 20)
	if lookups != 2 {
		t.Fatalf("SYN retransmit should retry lookup: lookups=%d want 2", lookups)
	}
	// 重试后识别为白名单 → 尝试劫持；测试环境没有真实 WinDivert 句柄，
	// hijack 失败后回落为 policyPass（fail-open），总之不再是 undecided。
	if kind, _, ok := i.policies.Get(key); !ok || kind != policyPass {
		t.Fatalf("kind=%v ok=%v, want policyPass (hijack fallback without real handle)", kind, ok)
	}

	// 再之后的 SYN：已是确定态，不再重新评估
	i.handleIPv4TCP(nil, buildTCPPacket(src, dst, 50003, 443, tcpSYN), &winDivertAddress{}, 20)
	if lookups != 2 {
		t.Fatalf("definitive policy must not re-evaluate: lookups=%d want 2", lookups)
	}
}

func TestFlowPolicyClearedOnFIN(t *testing.T) {
	i := newTestInterceptor(t)
	i.lookupName = func(process.Flow) (string, bool) { return "other.exe", true }

	key := flowKeyV4(testSrcIP(), testDstIP(), 50002, 443)
	i.handleIPv4TCP(nil, buildTCPPacket(testSrcIP(), testDstIP(), 50002, 443, tcpSYN), &winDivertAddress{}, 20)
	if _, _, ok := i.policies.Get(key); !ok {
		t.Fatal("policy not recorded after SYN")
	}

	i.handleIPv4TCP(nil, buildTCPPacket(testSrcIP(), testDstIP(), 50002, 443, tcpFIN|tcpACK), &winDivertAddress{}, 20)
	if kind, _, ok := i.policies.Get(key); ok {
		t.Fatalf("FIN should clear policy, still have kind=%v", kind)
	}
}

func TestFlowPolicySweep(t *testing.T) {
	ct := NewConnTracker(60, 600, 7893)
	defer ct.Close()
	p := newFlowPolicies(ct)
	defer p.Close()

	old := time.Now().Add(-time.Hour)

	k1 := flowKeyV4(testSrcIP(), testDstIP(), 1, 443) // 直连，超过 TTL
	k2 := flowKeyV4(testSrcIP(), testDstIP(), 2, 443) // 劫持，代理连接已结束
	k3 := flowKeyV4(testSrcIP(), testDstIP(), 3, 443) // 劫持，代理连接仍存活
	k4 := flowKey{srcPort: 4, dstPort: 443, ver: 6}   // IPv6 阻断

	p.mu.Lock()
	p.entries[k1] = flowPolicyEntry{kind: policyPass, createdAt: old}
	p.entries[k2] = flowPolicyEntry{kind: policyIntercept, mappedPort: 40001, createdAt: old}
	p.entries[k3] = flowPolicyEntry{kind: policyIntercept, mappedPort: 40002, createdAt: old}
	p.entries[k4] = flowPolicyEntry{kind: policyIntercept, mappedPort: 0, createdAt: old}
	p.mu.Unlock()

	// 只有 40002 对应的代理连接还活着
	ct.mu.Lock()
	ct.entries[ConnKey{"127.0.0.1", 40002}] = ConnTarget{}
	ct.mu.Unlock()

	p.sweep()

	if _, _, ok := p.Get(k1); ok {
		t.Fatal("expired direct entry should be swept")
	}
	if _, _, ok := p.Get(k2); ok {
		t.Fatal("hijack entry with dead proxied conn should be swept")
	}
	if _, _, ok := p.Get(k3); !ok {
		t.Fatal("hijack entry with live proxied conn must survive sweep")
	}
	if _, _, ok := p.Get(k4); !ok {
		t.Fatal("v6 block entry must only be cleared by FIN/RST")
	}
}

// 畸形/截断包必须放行，不能越界 panic。
func TestTruncatedTCPPacketIsPassedNotPanicked(t *testing.T) {
	i := newTestInterceptor(t, "chrome.exe")
	// 完整 40 字节再截掉 TCP 头后半段（flags 读取会越界）
	pkt := buildTCPPacket(testSrcIP(), testDstIP(), 50004, 443, tcpSYN)[:30]
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("truncated packet panicked: %v", r)
		}
	}()
	i.handleIPv4TCP(nil, pkt, &winDivertAddress{}, 20)
	if i.policies.Size() != 0 {
		t.Fatal("truncated packet must not create a flow policy")
	}
}

func TestInterceptorStateDefaultsToStopped(t *testing.T) {
	i := newTestInterceptor(t)
	st, msg := i.State()
	if st != stateStopped || msg != "" {
		t.Fatalf("state=%q msg=%q, want stopped/empty", st, msg)
	}
	i.setState(stateError, "boom")
	st, msg = i.State()
	if st != stateError || msg != "boom" {
		t.Fatalf("state=%q msg=%q, want error/boom", st, msg)
	}
}
