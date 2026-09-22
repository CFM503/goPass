package engine

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/CFM503/goPass/internal/process"
)

// WINDIVERT_ADDRESS 在 WinDivert 2.2 头文件里是 80 字节。
// 批量收发全靠 sizeof 把"字节数"换算成"包数"，Go 结构与 C 差一个字节
// 就会把地址数组整体串位，所以这里把它钉死。
func TestWinDivertAddressIsEightyBytes(t *testing.T) {
	if got := unsafe.Sizeof(winDivertAddress{}); got != 80 {
		t.Fatalf("sizeof(winDivertAddress)=%d, want 80 (WINDIVERT_ADDRESS)", got)
	}
	if winDivertAddressSize != 80 {
		t.Fatalf("winDivertAddressSize=%d, want 80", winDivertAddressSize)
	}
	// WINDIVERT_BATCH_MAX = 255
	if batchPackets < 1 || batchPackets > 255 {
		t.Fatalf("batchPackets=%d 超出 WINDIVERT_BATCH_MAX(1..255)", batchPackets)
	}
	// WINDIVERT_MTU_MAX = 40 + 0xFFFF；一批全是最长包时缓冲区必须放得下。
	if maxPacketSize != 40+0xFFFF {
		t.Fatalf("maxPacketSize=%d, want %d (WINDIVERT_MTU_MAX)", maxPacketSize, 40+0xFFFF)
	}
	if recvBufSize != batchPackets*maxPacketSize {
		t.Fatalf("recvBufSize=%d, want %d", recvBufSize, batchPackets*maxPacketSize)
	}
}

// withTotalLength 补齐 IPv4 TotalLength（buildTCPPacket 不写它，而批量切分要靠它）。
func withTotalLength(pkt []byte) []byte {
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	return pkt
}

func TestPacketLen(t *testing.T) {
	v4 := func() []byte {
		return withTotalLength(buildTCPPacket(testSrcIP(), testDstIP(), 50000, 443, tcpSYN))
	}
	v6 := func(payloadLen, size int) []byte {
		p := make([]byte, size)
		p[0] = 0x60
		binary.BigEndian.PutUint16(p[4:6], uint16(payloadLen))
		return p
	}

	cases := []struct {
		name    string
		pkt     []byte
		want    int
		wantErr bool
	}{
		{"空包", nil, 0, true},
		{"IPv4 正常", v4(), 40, false},
		{"IPv4 头不完整", []byte{0x45, 0, 0, 0, 0, 0}, 0, true},
		{"IPv4 TotalLength=0", func() []byte { p := make([]byte, 40); p[0] = 0x45; return p }(), 0, true},
		{"IPv4 TotalLength 越界", func() []byte {
			p := v4()
			binary.BigEndian.PutUint16(p[2:4], 1000)
			return p
		}(), 0, true},
		// TotalLength 小于缓冲区是合法的：剩余字节属于批次里的下一个包。
		{"IPv4 TotalLength 小于缓冲区", func() []byte {
			p := append(v4(), v4()...)
			binary.BigEndian.PutUint16(p[2:4], 40)
			return p
		}(), 40, false},
		{"未知 IP 版本", []byte{0x35, 0, 0, 0}, 0, true},
		{"IPv6 正常", v6(20, 60), 60, false},
		{"IPv6 头不完整", func() []byte { p := make([]byte, 20); p[0] = 0x60; return p }(), 0, true},
		{"IPv6 长度越界", v6(0xFFFF, 60), 0, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := packetLen(c.pkt)
			if c.wantErr {
				if err == nil {
					t.Fatalf("packetLen=%d, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("packetLen error: %v", err)
			}
			if got != c.want {
				t.Fatalf("packetLen=%d, want %d", got, c.want)
			}
		})
	}
}

func TestSendQueueOrderAndReset(t *testing.T) {
	q := newSendQueue()
	if q.count() != 0 {
		t.Fatalf("新队列 count=%d", q.count())
	}

	var addr winDivertAddress
	addr.Bits = 1
	addr.IfIdx = 7
	p1 := []byte{1, 2, 3}
	p2 := []byte{4, 5, 6, 7}

	q.push(p1, &addr)
	q.push(p2, &addr)
	q.push(nil, &addr) // 空包必须被忽略，不能写坏 lens/addr 对齐

	if q.count() != 2 {
		t.Fatalf("count=%d, want 2", q.count())
	}
	if q.wouldOverflow(1) {
		t.Fatal("预留容量内不应报溢出")
	}

	off := 0
	for idx, want := range [][]byte{p1, p2} {
		if q.lens[idx] != len(want) {
			t.Fatalf("lens[%d]=%d, want %d", idx, q.lens[idx], len(want))
		}
		if !bytes.Equal(q.buf[off:off+q.lens[idx]], want) {
			t.Fatalf("第 %d 个包内容错位: %v, want %v", idx, q.buf[off:off+q.lens[idx]], want)
		}
		if q.addrs[idx] != addr {
			t.Fatalf("addrs[%d]=%+v, want %+v（addr 必须按值拷贝）", idx, q.addrs[idx], addr)
		}
		off += q.lens[idx]
	}
	if off != len(q.buf) {
		t.Fatalf("buf 长度 %d 与逐包长度和 %d 不符", len(q.buf), off)
	}

	q.reset()
	if q.count() != 0 || len(q.buf) != 0 || len(q.addrs) != 0 {
		t.Fatalf("reset 后未清空: count=%d buf=%d addrs=%d", q.count(), len(q.buf), len(q.addrs))
	}
	// reset 必须保留容量，否则稳态下每次冲刷都会重新分配。
	if q.wouldOverflow(recvBufSize) {
		t.Fatal("reset 后容量应保留")
	}

	// nil 队列（单测/降级路径）push 必须是安全 no-op。
	var nilQ *sendQueue
	nilQ.push(p1, &addr)
}

// 批量收包把 N 个包无间隙拼在一起，切分必须完全依赖 IP 头长度字段，
// 且切开后仍按收到的顺序回注。
func TestProcessBatchSplitsAndKeepsOrder(t *testing.T) {
	i := newTestInterceptor(t)

	p1 := withTotalLength(buildTCPPacket(testSrcIP(), u32le(192, 168, 1, 1), 50010, 80, tcpSYN))
	p2 := withTotalLength(buildTCPPacket(testSrcIP(), u32le(192, 168, 1, 2), 50011, 80, tcpACK|0x08))
	want1 := append([]byte(nil), p1...)
	want2 := append([]byte(nil), p2...)

	buf := append(append([]byte(nil), p1...), p2...)
	addrs := make([]winDivertAddress, 2)
	q := newSendQueue()

	if err := i.processBatch(buf, addrs, q); err != nil {
		t.Fatalf("processBatch: %v", err)
	}
	// 两个目的地址都是内网 → 都走原样放行 → 各入队一次。
	if q.count() != 2 {
		t.Fatalf("入队 %d 个包, want 2", q.count())
	}
	if !bytes.Equal(q.buf[:q.lens[0]], want1) {
		t.Fatalf("第 1 个包被改动/错位: %v", q.buf[:q.lens[0]])
	}
	if !bytes.Equal(q.buf[q.lens[0]:], want2) {
		t.Fatalf("第 2 个包被改动/错位: %v", q.buf[q.lens[0]:])
	}
}

// 长度对不上说明缓冲区解析已不可信，必须报错而不是猜着继续。
func TestProcessBatchRejectsLengthMismatch(t *testing.T) {
	i := newTestInterceptor(t)
	p := withTotalLength(buildTCPPacket(testSrcIP(), u32le(192, 168, 1, 1), 50012, 80, tcpSYN))
	q := newSendQueue()

	cases := []struct {
		name  string
		buf   []byte
		nAddr int
	}{
		{"TotalLength 超出缓冲区", append([]byte(nil), p[:30]...), 1},
		{"字节数多于地址数", append(append([]byte(nil), p...), p...), 1},
		{"地址数多于包数", append([]byte(nil), p...), 2},
		{"未知 IP 版本", func() []byte { b := make([]byte, 40); b[0] = 0x35; return b }(), 1},
		{"空缓冲区", nil, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := i.processBatch(c.buf, make([]winDivertAddress, c.nAddr), q); err == nil {
				t.Fatal("length mismatch 必须报错")
			}
		})
	}
}

// 劫持热路径只按策略表里已有的映射端口改写包，绝不重新登记 ConnTracker
// （那正是每个包都要付的写锁 + 字符串分配）。
func TestHijackWithPortRewritesWithoutTouchingTracker(t *testing.T) {
	i := newTestInterceptor(t)
	pkt := buildTCPPacket(testSrcIP(), testDstIP(), 50020, 443, tcpSYN)
	addr := &winDivertAddress{Bits: 1, IfIdx: 3}
	q := newSendQueue()

	i.hijackWithPort(q, pkt, addr, 40001, 7893, 20)

	if !bytes.Equal(pkt[12:16], loopbackV4) || !bytes.Equal(pkt[16:20], loopbackV4) {
		t.Fatalf("劫持后源/目的 IP 应为回环: %v -> %v", pkt[12:16], pkt[16:20])
	}
	if got := binary.BigEndian.Uint16(pkt[20:22]); got != 40001 {
		t.Fatalf("源端口=%d, want 40001 (mappedPort)", got)
	}
	if got := binary.BigEndian.Uint16(pkt[22:24]); got != 7893 {
		t.Fatalf("目的端口=%d, want 7893 (tproxyPort)", got)
	}
	if addr.Bits&flagOutbound == 0 || addr.Bits&flagLoopback == 0 {
		t.Fatalf("addr.Bits=%#x 缺少 outbound|loopback", addr.Bits)
	}
	// 句柄未就绪 → calcAndSend 报错，包不入队（由调用方语义决定是否补发）。
	if q.count() != 0 {
		t.Fatalf("无句柄时不应入队, count=%d", q.count())
	}
	// 关键回归点：这条快路径不能往 ConnTracker 写任何东西。
	if _, ok := i.tracker.Get("127.0.0.1", 40001); ok {
		t.Fatal("hijackWithPort 不应登记 ConnTracker 映射")
	}
}

// 已定型的直连流：不重新查进程、不改策略表，全程零堆分配。
func TestDecidedFlowSkipsProcessLookup(t *testing.T) {
	i := newTestInterceptor(t, "chrome.exe")
	lookups := 0
	i.lookupName = func(process.Flow) (string, bool) { lookups++; return "chrome.exe", true }

	src, dst := testSrcIP(), testDstIP()
	key := flowKeyV4(src, dst, 50030, 443)
	i.policies.Set(key, policyPass, 0)

	pkt := buildTCPPacket(src, dst, 50030, 443, tcpACK|0x08)
	addr := winDivertAddress{}
	i.handleIPv4TCP(nil, pkt, &addr, 20)
	i.handleIPv4TCP(nil, pkt, &addr, 20)

	if lookups != 0 {
		t.Fatalf("已定型的流触发了 %d 次进程识别, want 0", lookups)
	}
	kind, _, ok := i.policies.Get(key)
	if !ok || kind != policyPass {
		t.Fatalf("policy 变成 kind=%v ok=%v, want 未改动的 policyPass", kind, ok)
	}

	allocs := testing.AllocsPerRun(200, func() {
		i.handleIPv4TCP(nil, pkt, &addr, 20)
	})
	if allocs > 0 {
		t.Fatalf("热路径每次分配 %.1f 次堆对象, want 0", allocs)
	}
}

func BenchmarkHandleIPv4TCPDecidedFastPath(b *testing.B) {
	ct := NewConnTracker(60, 600, 7893)
	i := NewInterceptor(ct, "1.2.3.4", 1080, 7893, nil)
	b.Cleanup(func() { i.Close(); ct.Close() })

	src, dst := testSrcIP(), testDstIP()
	pkt := buildTCPPacket(src, dst, 50040, 443, tcpACK|0x08)
	addr := winDivertAddress{}
	i.policies.Set(flowKeyV4(src, dst, 50040, 443), policyPass, 0)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		i.handleIPv4TCP(nil, pkt, &addr, 20)
	}
}

func BenchmarkPacketLen(b *testing.B) {
	pkt := withTotalLength(buildTCPPacket(testSrcIP(), testDstIP(), 50000, 443, tcpSYN))
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if _, err := packetLen(pkt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSendQueuePush(b *testing.B) {
	q := newSendQueue()
	pkt := withTotalLength(buildTCPPacket(testSrcIP(), testDstIP(), 50000, 443, tcpSYN))
	addr := winDivertAddress{}
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if q.wouldOverflow(len(pkt)) {
			q.reset()
		}
		q.push(pkt, &addr)
	}
}
