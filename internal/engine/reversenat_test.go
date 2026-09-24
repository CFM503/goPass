package engine

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// rewriteHijack 只允许改动四元组和 address 标志位，IP/TCP 头其余字段与载荷必须原样。
func TestRewriteHijackTouchesOnlyTupleAndAddress(t *testing.T) {
	pkt := buildTCPPacket(testSrcIP(), testDstIP(), 50020, 443, tcpSYN)
	pkt = append(pkt, []byte("payload-marker")...) // 追加载荷，确认改写不越界
	orig := append([]byte(nil), pkt...)
	addr := &winDivertAddress{Bits: flagOutbound, IfIdx: 5, SubIfIdx: 2}

	rewriteHijack(pkt, addr, 20, 40001, 7893)

	if !bytes.Equal(pkt[12:16], loopbackV4) {
		t.Fatalf("源 IP=%v, want 127.0.0.1", pkt[12:16])
	}
	if !bytes.Equal(pkt[16:20], loopbackV4) {
		t.Fatalf("目的 IP=%v, want 127.0.0.1", pkt[16:20])
	}
	if got := binary.BigEndian.Uint16(pkt[20:22]); got != 40001 {
		t.Fatalf("源端口=%d, want 40001 (mappedPort)", got)
	}
	if got := binary.BigEndian.Uint16(pkt[22:24]); got != 7893 {
		t.Fatalf("目的端口=%d, want 7893 (tproxyPort)", got)
	}
	if !bytes.Equal(pkt[:12], orig[:12]) {
		t.Fatalf("IP 头前 12 字节被改动: %x -> %x", orig[:12], pkt[:12])
	}
	if !bytes.Equal(pkt[24:40], orig[24:40]) {
		t.Fatalf("TCP 头被改动: %x -> %x", orig[24:40], pkt[24:40])
	}
	if !bytes.Equal(pkt[40:], orig[40:]) {
		t.Fatalf("载荷被改动: %x -> %x", orig[40:], pkt[40:])
	}
	if addr.Bits&flagOutbound == 0 || addr.Bits&flagLoopback == 0 {
		t.Fatalf("addr.Bits=%#x 缺少 outbound|loopback", addr.Bits)
	}
	if addr.IfIdx != 5 || addr.SubIfIdx != 2 {
		t.Fatalf("rewriteHijack 不该改 IfIdx/SubIfIdx: got %d/%d, want 5/2", addr.IfIdx, addr.SubIfIdx)
	}
}

// 正向改写 + 反向 NAT 必须把原始五元组完整还原，否则回程包会被内核丢弃（连接卡死）。
func TestReverseNATRestoresOriginalTuple(t *testing.T) {
	i := newTestInterceptor(t)

	origSrc := net.IPv4(192, 168, 1, 5)
	origDst := net.IPv4(8, 8, 8, 8)
	mapped, ok := i.tracker.Set(origSrc, 50020, origDst, 443, 7, 3)
	if !ok {
		t.Fatal("登记映射失败")
	}

	// TProxy 回程包：127.0.0.1:7893 -> 127.0.0.1:mapped
	reply := buildTCPPacket(u32le(127, 0, 0, 1), u32le(127, 0, 0, 1), 7893, mapped, tcpACK|0x08)
	addr := &winDivertAddress{Bits: flagOutbound | flagLoopback, IfIdx: 9, SubIfIdx: 4}
	q := newSendQueue()

	i.reverseNAT(q, reply, addr, 20)

	want := buildTCPPacket(u32le(8, 8, 8, 8), u32le(192, 168, 1, 5), 443, 50020, tcpACK|0x08)
	if !bytes.Equal(reply, want) {
		t.Fatalf("回程包未还原为\"原服务端 -> 原客户端\":\n got=%x\nwant=%x", reply, want)
	}
	if addr.Bits&flagOutbound != 0 || addr.Bits&flagLoopback != 0 {
		t.Fatalf("回程包必须清掉 outbound|loopback，addr.Bits=%#x", addr.Bits)
	}
	if addr.IfIdx != 7 || addr.SubIfIdx != 3 {
		t.Fatalf("IfIdx/SubIfIdx=%d/%d, want 7/3（原始接口）", addr.IfIdx, addr.SubIfIdx)
	}
	// 无驱动句柄 → calcAndSend 失败，但包体改写已经完成（调用方不得补发）。
	if q.count() != 0 {
		t.Fatalf("无句柄时不应入队, count=%d", q.count())
	}
}

// 查不到映射时必须原样放行：这时任何改写都会把别人的连接改坏。
func TestReverseNATPassesThroughUnknownMapping(t *testing.T) {
	i := newTestInterceptor(t)

	reply := buildTCPPacket(u32le(127, 0, 0, 1), u32le(127, 0, 0, 1), 7893, 40099, tcpACK|0x08)
	want := append([]byte(nil), reply...)
	addr := &winDivertAddress{Bits: flagOutbound | flagLoopback, IfIdx: 9}
	q := newSendQueue()

	i.reverseNAT(q, reply, addr, 20)

	if q.count() != 1 {
		t.Fatalf("未登记的映射必须放行, count=%d, want 1", q.count())
	}
	if !bytes.Equal(q.buf, want) {
		t.Fatalf("未登记的映射被改写了: got=%x, want=%x", q.buf, want)
	}
}

// 端口池耗尽时 hijackTCP 必须"放行一个未改写的包"——
// 改写过再放行等于把一个 127.0.0.1:mapped 的半成品包注入内核。
func TestHijackTCPPassesUnrewrittenPacketWhenPortPoolExhausted(t *testing.T) {
	i := newTestInterceptor(t)

	// 直接占满映射端口池，避免真的分配 2.8 万条连接记录。
	i.tracker.mu.Lock()
	for p := mappedPortMin; p <= mappedPortMax; p++ {
		i.tracker.entries[ConnKey{"127.0.0.1", uint16(p)}] = ConnTarget{}
	}
	i.tracker.mu.Unlock()

	pkt := buildTCPPacket(testSrcIP(), testDstIP(), 50060, 443, tcpSYN)
	want := append([]byte(nil), pkt...)
	q := newSendQueue()

	mapped := i.hijackTCP(q, pkt, &winDivertAddress{IfIdx: 4},
		net.IPv4(192, 168, 1, 5), net.IPv4(8, 8, 8, 8), 50060, 443, 20)

	if mapped != 0 {
		t.Fatalf("端口池耗尽时应返回 0, got %d", mapped)
	}
	if q.count() != 1 {
		t.Fatalf("端口池耗尽必须放行, count=%d, want 1", q.count())
	}
	if !bytes.Equal(q.buf, want) {
		t.Fatalf("端口池耗尽时包被改写了（会注入半成品包）:\n got=%x\nwant=%x", q.buf, want)
	}
}

// 发送失败时包已被改写 → 不得补发，但必须释放映射端口，否则端口池随每次失败泄漏。
func TestHijackTCPReleasesMappingWhenSendFails(t *testing.T) {
	i := newTestInterceptor(t)

	origSrc := net.IPv4(192, 168, 1, 5)
	origDst := net.IPv4(8, 8, 8, 8)
	// 先登记一次拿到映射端口；hijackTCP 对同一条流会复用同一个端口。
	port, ok := i.tracker.Set(origSrc, 50070, origDst, 443, 4, 0)
	if !ok {
		t.Fatal("登记映射失败")
	}
	if _, found := i.tracker.Get("127.0.0.1", port); !found {
		t.Fatal("前置登记失败")
	}

	pkt := buildTCPPacket(testSrcIP(), testDstIP(), 50070, 443, tcpSYN)
	q := newSendQueue()
	mapped := i.hijackTCP(q, pkt, &winDivertAddress{IfIdx: 4}, origSrc, origDst, 50070, 443, 20)

	if mapped != 0 {
		t.Fatalf("无驱动句柄时应返回 0, got %d", mapped)
	}
	// 包已被改写 —— 这正是"失败不补发"契约的前提。
	if !bytes.Equal(pkt[12:16], loopbackV4) || !bytes.Equal(pkt[16:20], loopbackV4) {
		t.Fatalf("改写应已发生: %v -> %v", pkt[12:16], pkt[16:20])
	}
	if q.count() != 0 {
		t.Fatalf("发送失败不应入队, count=%d", q.count())
	}
	if _, found := i.tracker.Get("127.0.0.1", port); found {
		t.Fatal("发送失败后映射端口必须释放，否则端口池随每次失败泄漏")
	}
}
