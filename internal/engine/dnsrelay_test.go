package engine

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/CFM503/goPass/internal/config"
)

func TestIsPrivateOrLocal(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.32.0.1", false},
		{"192.168.1.1", true},
		{"169.254.1.1", true},
		{"224.0.0.251", true},   // 组播
		{"255.255.255.255", true},
		{"198.18.0.1", true},    // fake-IP 段
		{"100.64.0.1", true},    // CGNAT
		{"8.8.8.8", false},
		{"114.114.114.114", false},
		{"1.1.1.1", false},
	}
	for _, c := range cases {
		if got := isPrivateOrLocal(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("isPrivateOrLocal(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestDNSCache(t *testing.T) {
	c := newDNSCache()
	c.Set("example.com|1", []byte("resp"), 30)
	if _, ok := c.Get("example.com|1"); !ok {
		t.Fatal("缓存命中失败")
	}
	// 过期
	c.Set("expired.com|1", []byte("resp"), 1)
	time.Sleep(1100 * time.Millisecond)
	if _, ok := c.Get("expired.com|1"); ok {
		t.Error("过期缓存不应命中")
	}
}

// buildTestQuery 构造一个 DNS 查询报文。
func buildTestQuery(qname string, qtype uint16) []byte {
	var q []byte
	q = append(q, 0x12, 0x34) // ID
	q = append(q, 0x01, 0x00) // flags: RD
	q = append(q, 0x00, 0x01) // QDCOUNT
	q = append(q, 0, 0, 0, 0, 0, 0)
	for _, label := range stringsSplit(qname, ".") {
		q = append(q, byte(len(label)))
		q = append(q, []byte(label)...)
	}
	q = append(q, 0)
	q = append(q, byte(qtype>>8), byte(qtype))
	q = append(q, 0x00, 0x01)
	return q
}

func stringsSplit(s, sep string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if string(r) == sep {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(r)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// 测试 DNS 中继的中国域名路径：转发到伪造的本地 DNS 服务器并回传。
func TestDNSRelaySystemPath(t *testing.T) {
	// 伪造一个 DNS 服务器（UDP），响应固定内容
	fakeResp := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0, 1, 0, 1, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 93, 184, 216, 34}

	dnsSrv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer dnsSrv.Close()
	dnsAddr := dnsSrv.LocalAddr().(*net.UDPAddr)

	var mu sync.Mutex
	gotQuery := []byte(nil)
	go func() {
		buf := make([]byte, 4096)
		n, client, err := dnsSrv.ReadFromUDP(buf)
		if err != nil {
			return
		}
		mu.Lock()
		gotQuery = append([]byte(nil), buf[:n]...)
		mu.Unlock()
		dnsSrv.WriteToUDP(fakeResp, client)
	}()

	query := buildTestQuery("example.com", 1)

	// 直接测 querySystemDNS（SystemDNS 指向伪造服务器）
	relay := &DNSRelay{
		resolved: config.ResolvedSplit{
			SystemDNS: dnsAddr.String(),
		},
	}
	resp, err := relay.querySystemDNS(query, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000})
	if err != nil {
		t.Fatalf("querySystemDNS: %v", err)
	}
	if len(resp) == 0 || resp[0] != fakeResp[0] {
		t.Error("响应与伪造 DNS 服务器不一致")
	}
	mu.Lock()
	defer mu.Unlock()
	if gotQuery == nil {
		t.Fatal("伪造 DNS 服务器未收到查询")
	}
	if name, _, ok := parseDNSQuery(gotQuery); !ok || name != "example.com" {
		t.Errorf("伪造 DNS 服务器收到的查询名 = %q, want example.com", name)
	}
}

func TestSendSERVFAIL(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	addr := conn.LocalAddr().(*net.UDPAddr)

	appConn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer appConn.Close()

	query := buildTestQuery("bad.domain", 1)
	appConn.Write(query)

	buf := make([]byte, 4096)
	n, client, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	relay := &DNSRelay{}
	relay.sendSERVFAIL(buf[:n], client, conn)

	resp := make([]byte, 4096)
	n, err = appConn.Read(resp)
	if err != nil {
		t.Fatal(err)
	}
	if n < 12 {
		t.Fatalf("SERVFAIL 响应太短: %d", n)
	}
	flags := uint16(resp[2])<<8 | uint16(resp[3])
	if flags&0x8000 == 0 {
		t.Error("SERVFAIL 响应未设置 QR 位")
	}
	if flags&0x000F != 2 {
		t.Errorf("RCODE = %d, want 2 (SERVFAIL)", flags&0x000F)
	}
}

func TestIsSystemDNS(t *testing.T) {
	// 无规则文件（matcher=nil）-> fail-safe 走 DoT（不泄漏）
	r := &Router{}
	relay := &DNSRelay{router: r}
	if relay.isSystemDNS("example.com") {
		t.Error("无规则时应 fail-safe 走 DoT")
	}
}
