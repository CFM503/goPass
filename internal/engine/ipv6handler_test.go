package engine

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// buildIPv6TCPPacket 构造最小 IPv6+TCP 包：40 字节 IPv6 头 + 20 字节 TCP 头 = 60 字节。
func buildIPv6TCPPacket(src, dst net.IP, srcPort, dstPort uint16, flags byte) []byte {
	pkt := make([]byte, 60)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], 20) // payload length
	pkt[6] = 6                               // next header = TCP
	pkt[7] = 64                              // hop limit
	copy(pkt[8:24], src.To16())
	copy(pkt[24:40], dst.To16())
	binary.BigEndian.PutUint16(pkt[40:42], srcPort)
	binary.BigEndian.PutUint16(pkt[42:44], dstPort)
	pkt[52] = 0x50 // data offset = 5 (20 字节)
	pkt[53] = flags
	return pkt
}

// buildIPv6UDPPacket 构造最小 IPv6+UDP 包：40 字节 IPv6 头 + 8 字节 UDP 头 = 48 字节。
func buildIPv6UDPPacket(src, dst net.IP, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 48)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], 8)
	pkt[6] = 17 // next header = UDP
	pkt[7] = 64
	copy(pkt[8:24], src.To16())
	copy(pkt[24:40], dst.To16())
	binary.BigEndian.PutUint16(pkt[40:42], srcPort)
	binary.BigEndian.PutUint16(pkt[42:44], dstPort)
	binary.BigEndian.PutUint16(pkt[44:46], 8)
	return pkt
}

// 文档前缀地址：本机不可能持有它，因此进程表查询必然落空，结果可复现。
var (
	testV6Src = net.ParseIP("2001:db8::1")
	testV6Dst = net.ParseIP("2606:4700:4700::1111")
)

// 按 next header 分发：只有 TCP(6)/UDP(17) 才会碰策略表，其余一律原样放行。
func TestHandleIPv6DispatchesByNextHeader(t *testing.T) {
	// next=6 → TCP 处理器：非回环目标 + 中途 ACK → 会登记一条直连策略。
	tcp := newTestInterceptor(t)
	pkt := buildIPv6TCPPacket(testV6Src, testV6Dst, 51000, 443, tcpACK|0x08)
	q := newSendQueue()
	tcp.handleIPv6(q, pkt, &winDivertAddress{})
	if tcp.policies.Size() != 1 {
		t.Fatalf("TCP 分支未生效：策略表大小=%d, want 1", tcp.policies.Size())
	}
	if q.count() != 1 {
		t.Fatalf("TCP 中途包应放行, count=%d", q.count())
	}

	// next=58 (ICMPv6) → 直接放行，绝不登记策略。
	icmp := newTestInterceptor(t)
	pkt2 := buildIPv6TCPPacket(testV6Src, testV6Dst, 51001, 443, tcpACK|0x08)
	pkt2[6] = 58
	q2 := newSendQueue()
	icmp.handleIPv6(q2, pkt2, &winDivertAddress{})
	if icmp.policies.Size() != 0 {
		t.Fatalf("非 TCP/UDP 的 IPv6 包不应登记策略, 大小=%d", icmp.policies.Size())
	}
	if q2.count() != 1 {
		t.Fatalf("非 TCP/UDP 的 IPv6 包应放行, count=%d", q2.count())
	}

	// 头部不完整 → 放行，不 panic、不登记。
	short := newTestInterceptor(t)
	q3 := newSendQueue()
	short.handleIPv6(q3, make([]byte, 39), &winDivertAddress{})
	if short.policies.Size() != 0 || q3.count() != 1 {
		t.Fatalf("短包应放行且不登记: policies=%d count=%d", short.policies.Size(), q3.count())
	}
}

// IPv6 的四条放行守卫：包太短 / 回环 / 链路本地 / ULA / v4 映射内网 / 收尾包。
// 它们必须在任何改写之前返回，且一个字节都不能动。
func TestHandleIPv6TCPPassGuardsLeavePacketUntouched(t *testing.T) {
	cases := []struct {
		name  string
		build func() []byte
	}{
		{"包太短(<60)", func() []byte {
			p := buildIPv6TCPPacket(testV6Src, testV6Dst, 51010, 443, tcpSYN)
			return p[:59]
		}},
		{"目标是回环", func() []byte {
			return buildIPv6TCPPacket(testV6Src, net.ParseIP("::1"), 51011, 443, tcpACK|0x08)
		}},
		{"目标是链路本地", func() []byte {
			return buildIPv6TCPPacket(testV6Src, net.ParseIP("fe80::1"), 51012, 443, tcpACK|0x08)
		}},
		{"目标是 ULA", func() []byte {
			return buildIPv6TCPPacket(testV6Src, net.ParseIP("fd12:3456::1"), 51013, 443, tcpACK|0x08)
		}},
		{"目标是未指定地址", func() []byte {
			return buildIPv6TCPPacket(testV6Src, net.ParseIP("::"), 51014, 443, tcpACK|0x08)
		}},
		{"FIN 收尾且无既有策略", func() []byte {
			return buildIPv6TCPPacket(testV6Src, testV6Dst, 51015, 443, tcpFIN|tcpACK)
		}},
		{"RST 收尾且无既有策略", func() []byte {
			return buildIPv6TCPPacket(testV6Src, testV6Dst, 51016, 443, tcpRST)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			i := newTestInterceptor(t)
			pkt := c.build()
			want := append([]byte(nil), pkt...)
			q := newSendQueue()

			i.handleIPv6TCP(q, pkt, &winDivertAddress{})

			if q.count() != 1 {
				t.Fatalf("守卫分支必须放行, count=%d, want 1", q.count())
			}
			if !bytes.Equal(q.buf, want) {
				t.Fatalf("放行时包被改动了:\n got=%x\nwant=%x", q.buf, want)
			}
			if i.policies.Size() != 0 {
				t.Fatalf("守卫分支不应登记策略, 大小=%d", i.policies.Size())
			}
		})
	}
}

// 已定型为"阻断"的流：白名单中途变更也不能把它放活（否则连接会在半路改道）。
func TestHandleIPv6TCPDropsFlowAlreadyBlocked(t *testing.T) {
	i := newTestInterceptor(t)
	pkt := buildIPv6TCPPacket(testV6Src, testV6Dst, 51020, 443, tcpACK|0x08)
	key := flowKeyFromIPv6Packet(pkt)
	i.policies.Set(key, policyIntercept, 0)

	q := newSendQueue()
	i.handleIPv6TCP(q, pkt, &winDivertAddress{})

	if q.count() != 0 {
		t.Fatalf("已定型为阻断的流必须丢弃, count=%d, want 0", q.count())
	}
	kind, _, ok := i.policies.Get(key)
	if !ok || kind != policyIntercept {
		t.Fatalf("策略被改动: kind=%v ok=%v, want policyIntercept", kind, ok)
	}
}

// 已定型为直连的流：必须原样放行，且绝不再查进程表。
func TestHandleIPv6TCPPassesFlowAlreadyAllowed(t *testing.T) {
	i := newTestInterceptor(t)
	pkt := buildIPv6TCPPacket(testV6Src, testV6Dst, 51021, 443, tcpACK|0x08)
	key := flowKeyFromIPv6Packet(pkt)
	i.policies.Set(key, policyPass, 0)

	q := newSendQueue()
	want := append([]byte(nil), pkt...)
	i.handleIPv6TCP(q, pkt, &winDivertAddress{})

	if q.count() != 1 {
		t.Fatalf("已定型为直连的流应放行, count=%d", q.count())
	}
	if !bytes.Equal(q.buf, want) {
		t.Fatalf("放行时包被改动了:\n got=%x\nwant=%x", q.buf, want)
	}
	kind, _, ok := i.policies.Get(key)
	if !ok || kind != policyPass {
		t.Fatalf("策略被改动: kind=%v ok=%v, want policyPass", kind, ok)
	}
}

// IPv6 UDP 只拦白名单程序的 QUIC(443)：太短 / 非 443 / 内网目标都必须放行且不改包。
func TestHandleIPv6UDPPassGuards(t *testing.T) {
	cases := []struct {
		name  string
		build func() []byte
	}{
		{"包太短(<48)", func() []byte {
			p := buildIPv6UDPPacket(testV6Src, testV6Dst, 51030, 443)
			return p[:47]
		}},
		{"目的端口不是 443", func() []byte {
			return buildIPv6UDPPacket(testV6Src, testV6Dst, 51031, 53)
		}},
		{"目标是回环", func() []byte {
			return buildIPv6UDPPacket(testV6Src, net.ParseIP("::1"), 51032, 443)
		}},
		{"目标是链路本地", func() []byte {
			return buildIPv6UDPPacket(testV6Src, net.ParseIP("fe80::1"), 51033, 443)
		}},
		{"目标是 ULA", func() []byte {
			return buildIPv6UDPPacket(testV6Src, net.ParseIP("fc00::1"), 51034, 443)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			i := newTestInterceptor(t, "chrome.exe")
			pkt := c.build()
			want := append([]byte(nil), pkt...)
			q := newSendQueue()

			i.handleIPv6UDP(q, pkt, &winDivertAddress{})

			if q.count() != 1 {
				t.Fatalf("守卫分支必须放行, count=%d, want 1", q.count())
			}
			if !bytes.Equal(q.buf, want) {
				t.Fatalf("放行时包被改动了:\n got=%x\nwant=%x", q.buf, want)
			}
		})
	}
}

// 进程识别不到（本机不可能持有 2001:db8::1，查询必然落空）→ 非白名单 → 放行。
// 白名单为空，因此即便查询意外命中也不会走阻断分支，断言与真实表状态无关。
func TestHandleIPv6UDPPassesWhenProcessUnknown(t *testing.T) {
	i := newTestInterceptor(t, "chrome.exe")
	pkt := buildIPv6UDPPacket(testV6Src, testV6Dst, 51040, 443)
	want := append([]byte(nil), pkt...)
	q := newSendQueue()

	i.handleIPv6UDP(q, pkt, &winDivertAddress{})

	if q.count() != 1 {
		t.Fatalf("识别不到进程的 QUIC 应放行, count=%d, want 1", q.count())
	}
	if !bytes.Equal(q.buf, want) {
		t.Fatalf("放行时包被改动了:\n got=%x\nwant=%x", q.buf, want)
	}
}

// 回归：IPv6 首包 SYN 查不到进程时必须保留 policyUndecided，不能写死成 policyPass。
// 否则 handleIPv6TCP 里 "undecided + 纯 SYN 才允许重新评估" 的判定永远为假，
// 白名单程序会因为一次查表未命中就被永久定型为直连，绕过代理回落 IPv4 的阻断。
func TestHandleIPv6TCPKeepsUndecidedSoSYNRetryFires(t *testing.T) {
	i := newTestInterceptor(t, "chrome.exe")
	pkt := buildIPv6TCPPacket(testV6Src, testV6Dst, 51050, 443, tcpSYN)
	key := flowKeyFromIPv6Packet(pkt)
	q := newSendQueue()

	// 2001:db8::1 是文档前缀，本机不可能持有 → LookupIPv6TCP 必然落空。
	i.handleIPv6TCP(q, pkt, &winDivertAddress{})
	if q.count() != 1 {
		t.Fatalf("识别不到进程的连接应按直连放行, count=%d, want 1", q.count())
	}
	kind, _, ok := i.policies.Get(key)
	if !ok {
		t.Fatal("首包 SYN 必须登记策略")
	}
	if kind != policyUndecided {
		t.Fatalf("首包 SYN 后 kind=%v, want policyUndecided —— "+
			"写死 policyPass 会让重试条件 policyUndecided&&纯SYN 永远为假", kind)
	}

	// 把定型时间回拨，用"是否被重新登记"来观察重试分支是否真的执行了。
	i.policies.mu.Lock()
	e := i.policies.entries[key]
	e.createdAt = time.Now().Add(-time.Minute)
	i.policies.entries[key] = e
	i.policies.mu.Unlock()

	before := time.Now()
	i.handleIPv6TCP(q, buildIPv6TCPPacket(testV6Src, testV6Dst, 51050, 443, tcpSYN), &winDivertAddress{})
	if q.count() != 2 {
		t.Fatalf("重判后的 SYN 应放行, count=%d, want 2", q.count())
	}

	kind, _, ok = i.policies.Get(key)
	if !ok || kind != policyUndecided {
		t.Fatalf("重判后 kind=%v ok=%v, want policyUndecided", kind, ok)
	}
	i.policies.mu.RLock()
	createdAt := i.policies.entries[key].createdAt
	i.policies.mu.RUnlock()
	if createdAt.Before(before) {
		t.Fatalf("createdAt=%v 早于第二次发包时刻 %v：策略没有被删除并重新登记，"+
			"SYN 重传根本没触发重新判定（重试分支不可达）", createdAt, before)
	}
}

// flowKeyFromIPv6Packet 按 handleIPv6TCP 的方式从包里取五元组，
// 供测试预置/校验策略表项。
func flowKeyFromIPv6Packet(pkt []byte) flowKey {
	var k flowKey
	copy(k.srcIP[:], pkt[8:24])
	copy(k.dstIP[:], pkt[24:40])
	k.srcPort = binary.BigEndian.Uint16(pkt[40:42])
	k.dstPort = binary.BigEndian.Uint16(pkt[42:44])
	k.ver = 6
	return k
}
