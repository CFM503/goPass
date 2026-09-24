package engine

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func tlsAppendU16(dst []byte, v uint16) []byte { return append(dst, byte(v>>8), byte(v)) }

// buildClientHelloRecord 构造一条合法的 TLS ClientHello 记录（content type=22）。
// host 非空时写入 server_name 扩展；nameType 可改成非 0 来验证解析器只认 host_name；
// extraExts 用来把 SNI 挤到非首位（真实客户端几乎都不会把 SNI 放第一个）。
func buildClientHelloRecord(host string, nameType byte, extraExts int) []byte {
	var hs []byte
	hs = append(hs, 0x01)                // handshake type = ClientHello
	hs = append(hs, 0, 0, 0)             // 3 字节长度，最后回填
	hs = append(hs, 0x03, 0x03)          // legacy_version
	hs = append(hs, make([]byte, 32)...) // random
	hs = append(hs, 0)                   // session_id_length = 0

	cs := []byte{0x13, 0x01, 0xc0, 0x2f}
	hs = tlsAppendU16(hs, uint16(len(cs)))
	hs = append(hs, cs...)
	hs = append(hs, 0x01, 0x00) // compression_methods_length = 1, null

	var exts []byte
	for n := 0; n < extraExts; n++ {
		body := []byte{0xde, 0xad, 0xbe, 0xef}
		exts = tlsAppendU16(exts, 0x000a) // supported_groups，占位，类型非 0
		exts = tlsAppendU16(exts, uint16(len(body)))
		exts = append(exts, body...)
	}
	if host != "" {
		name := []byte(host)
		var list []byte
		list = append(list, nameType)
		list = tlsAppendU16(list, uint16(len(name)))
		list = append(list, name...)
		var sn []byte
		sn = tlsAppendU16(sn, uint16(len(list)))
		sn = append(sn, list...)
		exts = tlsAppendU16(exts, 0x0000) // server_name
		exts = tlsAppendU16(exts, uint16(len(sn)))
		exts = append(exts, sn...)
	}
	hs = tlsAppendU16(hs, uint16(len(exts)))
	hs = append(hs, exts...)

	msgLen := len(hs) - 4
	hs[1], hs[2], hs[3] = byte(msgLen>>16), byte(msgLen>>8), byte(msgLen)

	rec := []byte{0x16, 0x03, 0x03}
	rec = tlsAppendU16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

func TestExtractSNIReadsHostnameFromClientHello(t *testing.T) {
	cases := []struct {
		name      string
		host      string
		nameType  byte
		extraExts int
	}{
		{"SNI 是唯一扩展", "example.com", 0, 0},
		{"SNI 排在其他扩展之后", "www.youtube.com", 0, 3},
		{"长域名", strings.Repeat("a", 80) + ".example.org", 0, 1},
		{"带连字符的域名", "my-sub.example-site.co.uk", 0, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ExtractSNI(buildClientHelloRecord(c.host, c.nameType, c.extraExts))
			if err != nil {
				t.Fatalf("ExtractSNI 报错: %v", err)
			}
			if got != c.host {
				t.Fatalf("ExtractSNI=%q, want %q", got, c.host)
			}
		})
	}
}

func TestExtractSNIRejectsMalformedInput(t *testing.T) {
	valid := buildClientHelloRecord("example.com", 0, 1)

	// 各处长度字段的偏移：记录头 5 字节，其后是握手头(1+3)+version(2)+random(32)。
	// 也就是 sessionIDLen 在 rest[38]（绝对 43），cipherSuitesLen 在 rest[39]（绝对 44），
	// compressionLen 在 rest[41]（绝对 46），extsLen 在 rest[43]（绝对 48）。
	patch := func(fn func(b []byte)) []byte {
		b := append([]byte(nil), valid...)
		fn(b)
		return b
	}

	cases := []struct {
		name string
		data []byte
	}{
		{"长度不足 5 字节", []byte{0x16, 0x03, 0x03, 0x00}},
		{"不是握手记录(content type 23)", patch(func(b []byte) { b[0] = 0x17 })},
		{"记录长度为 0", patch(func(b []byte) { b[3], b[4] = 0, 0 })},
		{"记录被截断", valid[:len(valid)-4]},
		{"不是 ClientHello(handshake type 2)", patch(func(b []byte) { b[5] = 0x02 })},
		{"ClientHello 长度声明过大", patch(func(b []byte) { b[6], b[7], b[8] = 0xff, 0xff, 0xff })},
		{"session ID 长度越界", patch(func(b []byte) { b[43] = 0xff })},                 // hs[38]
		{"cipher suites 长度越界", patch(func(b []byte) { b[44], b[45] = 0xff, 0xff })}, // hs[39:41]
		{"compression methods 长度越界", patch(func(b []byte) { b[50] = 0xff })},        // hs[45]
		{"extensions 长度越界", patch(func(b []byte) { b[52], b[53] = 0xff, 0xff })},    // hs[47:49]
		{"扩展自身长度越界", patch(func(b []byte) { b[56], b[57] = 0xff, 0xff })},           // 首个扩展的 extLen, hs[51:53]
		{"没有 server_name 扩展", buildClientHelloRecord("", 0, 2)},
		{"name_type 不是 host_name", buildClientHelloRecord("example.com", 1, 1)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ExtractSNI(c.data)
			if err == nil {
				t.Fatalf("必须报错，却返回了 %q", got)
			}
		})
	}
}

// 截断扫描：把合法 ClientHello 逐字节截断（并同步修正记录长度字段，
// 否则外层记录校验会先挡掉，根本走不到内部解析），每个前缀都必须报错且绝不 panic。
func TestExtractSNITruncationNeverPanics(t *testing.T) {
	full := buildClientHelloRecord("truncation.example.com", 0, 1)
	for n := 0; n <= len(full); n++ {
		p := append([]byte(nil), full[:n]...)
		if n >= 5 {
			// 让解析器认为"这个前缀就是完整记录"，从而进入内部逐字段解析。
			binary.BigEndian.PutUint16(p[3:5], uint16(n-5))
		}
		err, panicked := extractSNISafely(p)
		if panicked {
			t.Fatalf("ExtractSNI(截断到 %d 字节) panic 了: %v", n, err)
		}
		if n < len(full) && err == nil {
			t.Fatalf("ExtractSNI(截断到 %d 字节) 返回 nil error，必须报错", n)
		}
	}
	// 完整记录本身必须仍然可用（上面 n==len(full) 时不作报错断言）。
	if _, err := ExtractSNI(full); err != nil {
		t.Fatalf("完整记录反而报错: %v", err)
	}
}

func extractSNISafely(p []byte) (err error, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	_, e := ExtractSNI(p)
	return e, false
}

// sni.go 的契约是"不随主机名长度增长的分配次数"，这里把分配次数钉死。
func TestExtractSNIAllocationCountDoesNotGrowWithHostname(t *testing.T) {
	short := buildClientHelloRecord("a.com", 0, 1)
	long := buildClientHelloRecord(strings.Repeat("x", 200)+".com", 0, 1)

	allocsShort := testing.AllocsPerRun(100, func() { _, _ = ExtractSNI(short) })
	allocsLong := testing.AllocsPerRun(100, func() { _, _ = ExtractSNI(long) })

	if allocsShort > 1 {
		t.Fatalf("短主机名每次分配 %.1f 次，want <= 1", allocsShort)
	}
	if allocsLong > allocsShort {
		t.Fatalf("主机名变长后分配次数 %.1f > %.1f，分配必须与主机名长度无关",
			allocsLong, allocsShort)
	}
}

// readTLSClientHello 的核心契约：读到的字节必须原样全部返回，
// 否则 ClientHello 会被吞掉，上游代理拿不到 SNI，YouTube 之类的历史兼容性问题就回来了。
func TestReadTLSClientHelloReturnsEveryByteItRead(t *testing.T) {
	rec := buildClientHelloRecord("example.com", 0, 1)
	conn, writer := helloConn(t, rec)

	got, sni, err := readTLSClientHello(conn)
	if err != nil {
		t.Fatalf("readTLSClientHello 报错: %v", err)
	}
	if sni != "example.com" {
		t.Fatalf("sni=%q, want example.com", sni)
	}
	if len(got) != len(rec) {
		t.Fatalf("返回 %d 字节，写入 %d 字节——ClientHello 被吞了一部分", len(got), len(rec))
	}
	if string(got) != string(rec) {
		t.Fatalf("返回内容与写入不一致:\n got=%x\nwant=%x", got, rec)
	}
	// 关键回归点：返回的字节必须还能再解析出同一个 SNI。
	if again, err := ExtractSNI(got); err != nil || again != "example.com" {
		t.Fatalf("对返回字节重新 ExtractSNI = %q, err=%v", again, err)
	}
	_ = writer
}

// 任何一条失败路径都必须把已读到的字节带回去（供调用方透传/排错），不能只返回 nil。
func TestReadTLSClientHelloReturnsBytesOnFailure(t *testing.T) {
	full := buildClientHelloRecord("example.com", 0, 1)

	cases := []struct {
		name string
		data []byte
	}{
		{"头部只有 3 字节", full[:3]},
		{"头部完整但记录体被截断", full[:20]},
		{"头部完整但记录体被截断(靠后)", full[:len(full)-4]},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn, _ := helloConn(t, c.data)
			got, sni, err := readTLSClientHello(conn)
			if err == nil {
				t.Fatal("截断输入必须报错")
			}
			if sni != "" {
				t.Fatalf("失败时不应返回 sni=%q", sni)
			}
			if len(got) != len(c.data) {
				t.Fatalf("返回 %d 字节，实际只写入 %d 字节——已读字节丢失", len(got), len(c.data))
			}
			if string(got) != string(c.data) {
				t.Fatalf("返回内容与已读内容不一致:\n got=%x\nwant=%x", got, c.data)
			}
		})
	}
}

func TestReadTLSClientHelloRejectsBadRecordHeader(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"content type 不是 handshake", []byte{0x17, 0x03, 0x03, 0x00, 0x05}},
		{"记录长度为 0", []byte{0x16, 0x03, 0x03, 0x00, 0x00}},
		{"记录长度超过 16384 上限", []byte{0x16, 0x03, 0x03, 0x40, 0x01}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn, _ := helloConn(t, c.data)
			got, sni, err := readTLSClientHello(conn)
			if err == nil {
				t.Fatal("非法记录头必须报错")
			}
			if sni != "" {
				t.Fatalf("失败时不应返回 sni=%q", sni)
			}
			if len(got) != 5 {
				t.Fatalf("返回 %d 字节，want 5（头部已读到）", len(got))
			}
		})
	}
}

// 慢速/沉默对端必须被 2s 读超时打断，否则一个挂着不回数据的客户端
// 能把 TProxy 的协程永久占住。
func TestReadTLSClientHelloGivesUpOnSilentPeer(t *testing.T) {
	conn, writer := net.Pipe()
	defer conn.Close()
	defer writer.Close() // 一直不写任何字节

	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		buf, _, err := readTLSClientHello(conn)
		ch <- result{len(buf), err}
	}()

	select {
	case got := <-ch:
		if got.err == nil {
			t.Fatal("对端一直不回数据时必须报错")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("2s 读超时没生效：静默对端让 readTLSClientHello 卡住超过 5s")
	}
}

// helloConn 用管道把 data 从写端泵出去，返回读端；两端都在测试结束时关闭，
// 即使读端提前放弃读取，写端的阻塞写也会被 Close 打断，不会泄漏 goroutine。
func helloConn(t *testing.T, data []byte) (net.Conn, net.Conn) {
	t.Helper()
	r, w := net.Pipe()
	t.Cleanup(func() { r.Close(); w.Close() })
	go func() {
		if len(data) > 0 {
			_, _ = w.Write(data)
		}
		_ = w.Close()
	}()
	return r, w
}
