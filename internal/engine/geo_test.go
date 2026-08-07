package engine

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/CFM503/goPass/internal/config"
)

// loadTestMatcher 从内置规则（编译进二进制的 geosite:cn / geoip:cn）构建匹配器。
func loadTestMatcher(t *testing.T) *GeoMatcher {
	t.Helper()
	m := &GeoMatcher{
		cnDomains:           newDomainMatcher(),
		cnIPs:               &ipSet{},
		customDirectDomains: newDomainMatcher(),
		customProxyDomains:  newDomainMatcher(),
		customDirectIPs:     &ipSet{},
		customProxyIPs:      &ipSet{},
	}
	if len(embeddedGeoSite) == 0 || len(embeddedGeoIP) == 0 {
		t.Fatal("内置规则为空")
	}
	if err := m.loadGeoSiteText(embeddedGeoSite); err != nil {
		t.Fatalf("加载内置 geosite: %v", err)
	}
	if err := m.loadGeoIPText(embeddedGeoIP); err != nil {
		t.Fatalf("加载内置 geoip: %v", err)
	}
	m.cnIPs.build()

	// 自定义规则
	directDoms, directIPs, _ := parseCustomList([]string{"full:www.custom-direct-test.com", "1.2.3.0/24"})
	proxyDoms, proxyIPs, _ := parseCustomList([]string{"full:www.custom-proxy-test.com", "9.9.9.0/24"})
	m.customDirectDomains = directDoms
	m.customDirectIPs = directIPs
	m.customProxyDomains = proxyDoms
	m.customProxyIPs = proxyIPs

	m.stats = GeoMatcherStats{
		GeoSiteCNEntries:  m.cnDomains.Count(),
		GeoIPCNCIDRs:      m.cnIPs.Count(),
		CustomDirectDom:   directDoms.Count(),
		CustomDirectIPs:   directIPs.Count(),
		CustomProxyDom:    proxyDoms.Count(),
		CustomProxyIPs:    proxyIPs.Count(),
		GeoSiteFile:       "embedded",
		GeoIPFile:         "embedded",
		LoadedAt:          nowStr(),
	}
	return m
}

func TestParseGeoSiteDat(t *testing.T) {
	m := loadTestMatcher(t)
	stats := m.Stats()
	t.Logf("geosite:cn 域名规则数=%d, geoip:cn 网段数=%d", stats.GeoSiteCNEntries, stats.GeoIPCNCIDRs)
	t.Logf("自定义直连: %d 域名 / %d IP, 自定义代理: %d 域名 / %d IP",
		stats.CustomDirectDom, stats.CustomDirectIPs, stats.CustomProxyDom, stats.CustomProxyIPs)
	if stats.GeoSiteCNEntries == 0 {
		t.Fatal("geosite:cn 没有解析出任何域名")
	}
	if stats.GeoIPCNCIDRs == 0 {
		t.Fatal("geoip:cn 没有解析出任何网段")
	}
}

func TestGeoSiteCNMatches(t *testing.T) {
	m := loadTestMatcher(t)
	cases := []struct {
		domain string
		want   bool
	}{
		{"baidu.com", true},          // 知名中国域名
		{"www.baidu.com", true},      // 子域
		{"qq.com", true},             //
		{"google.com", false},        // 国外
		{"www.google.com", false},    //
		{"youtube.com", false},       //
		{"", false},                  //
	}
	for _, c := range cases {
		got := m.IsCNDomain(c.domain)
		if got != c.want {
			t.Errorf("IsCNDomain(%q) = %v, want %v", c.domain, got, c.want)
		}
	}
}

func TestGeoIPCNMatches(t *testing.T) {
	m := loadTestMatcher(t)
	cases := []struct {
		ip   string
		want bool
	}{
		{"114.114.114.114", true},   // 南京信风（中国）
		{"223.5.5.5", true},         // AliDNS（中国）
		{"1.1.1.1", false},          // Cloudflare（国外）
		{"8.8.8.8", false},          // Google（国外）
	}
	for _, c := range cases {
		got := m.IsCNIP(net.ParseIP(c.ip))
		if got != c.want {
			t.Errorf("IsCNIP(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestCustomRules(t *testing.T) {
	m := loadTestMatcher(t)
	if !m.MatchCustomDirect("www.custom-direct-test.com", nil) {
		t.Error("自定义直连域名未命中")
	}
	if !m.MatchCustomDirect("sub.custom-direct-test.com", nil) {
		// full: 只精确匹配，子域不应命中
		t.Log("full 规则不匹配子域（符合预期）")
	}
	if !m.MatchCustomDirect("", net.ParseIP("1.2.3.4")) {
		t.Error("自定义直连 IP 段未命中")
	}
	if m.MatchCustomDirect("", net.ParseIP("1.2.4.4")) {
		t.Error("自定义直连 IP 段误命中（1.2.4.4 不在 1.2.3.0/24）")
	}
	if !m.MatchCustomProxy("www.custom-proxy-test.com", nil) {
		t.Error("自定义代理域名未命中")
	}
	if !m.MatchCustomProxy("", net.ParseIP("9.9.9.9")) {
		t.Error("自定义代理 IP 段未命中")
	}
}

func TestDomainMatcherSuffix(t *testing.T) {
	dm := newDomainMatcher()
	dm.addSuffix("example.com")
	if !dm.Match("example.com") {
		t.Error("后缀规则应匹配自身")
	}
	if !dm.Match("www.example.com") {
		t.Error("后缀规则应匹配子域")
	}
	if !dm.Match("a.b.example.com") {
		t.Error("后缀规则应匹配多级子域")
	}
	if dm.Match("notexample.com") {
		t.Error("后缀规则不应匹配前缀相似域名")
	}
	if dm.Match("example.com.evil.org") {
		t.Error("后缀规则不应错误匹配")
	}
}

func TestDomainMatcherFullAndKeyword(t *testing.T) {
	dm := newDomainMatcher()
	dm.addFull("exact.com")
	dm.addKeyword("microsoft")
	if !dm.Match("exact.com") {
		t.Error("full 规则应匹配精确域名")
	}
	if dm.Match("sub.exact.com") {
		t.Error("full 规则不应匹配子域")
	}
	if !dm.Match("login.microsoftonline.com") {
		t.Error("keyword 规则应命中子串")
	}
}

func TestIPSetMatch(t *testing.T) {
	is := &ipSet{}
	is.addCIDR("114.114.114.0/24")
	is.addCIDR("1.1.1.0/24")
	is.addCIDR("8.8.8.8")
	is.build()
	if !is.Match(net.ParseIP("114.114.114.114")) {
		t.Error("网段内 IP 未命中")
	}
	if !is.Match(net.ParseIP("1.1.1.1")) {
		t.Error("网段内 IP 未命中")
	}
	if !is.Match(net.ParseIP("8.8.8.8")) {
		t.Error("裸 IP 未命中")
	}
	if is.Match(net.ParseIP("114.114.115.1")) {
		t.Error("网段外 IP 误命中")
	}
	if is.Match(net.ParseIP("2001:db8::1")) {
		t.Error("IPv6 不应命中 IPv4 集合")
	}
}

func TestRouterDecide(t *testing.T) {
	m := loadTestMatcher(t)
	r := &Router{matcher: m}
	r.mu.Lock()
	r.resolved = config.ResolvedSplit{
		Enabled:      true,
		Mode:         "both",
		GeoPriority:  true,
		CNDirect:     true,
		ForeignProxy: true,
		BlockIPv6:    true,
	}
	r.whitelist = map[string]struct{}{"chrome.exe": {}}
	r.mu.Unlock()

	cases := []struct {
		name    string
		domain  string
		ip      string
		process string
		want    Decision
		reason  string
	}{
		{"cn-domain-direct", "www.baidu.com", "8.8.8.8", "chrome.exe", DecisionDirect, "geo:cn"},
		{"cn-ip-direct", "", "114.114.114.114", "chrome.exe", DecisionDirect, "geo:cn"},
		{"foreign-domain-proxy", "www.google.com", "1.1.1.1", "chrome.exe", DecisionProxy, "geo:foreign"},
		{"foreign-ip-proxy", "", "8.8.8.8", "chrome.exe", DecisionProxy, "geo:foreign"},
		{"custom-direct", "www.custom-direct-test.com", "1.1.1.1", "chrome.exe", DecisionDirect, "custom:direct"},
		{"custom-proxy", "www.custom-proxy-test.com", "114.114.114.114", "chrome.exe", DecisionProxy, "custom:proxy"},
		{"cn-domain-wins-over-foreign-ip", "www.baidu.com", "8.8.8.8", "chrome.exe", DecisionDirect, "geo:cn"},
		{"foreign-domain-wins-over-cn-ip", "www.google.com", "114.114.114.114", "chrome.exe", DecisionProxy, "geo:foreign"},
	}
	for _, c := range cases {
		res := r.Decide(c.domain, net.ParseIP(c.ip), c.process)
		if res.Decision != c.want || res.Reason != c.reason {
			t.Errorf("Decide(%q, %q, %q) = (%v, %q), want (%v, %q)",
				c.domain, c.ip, c.process, res.Decision, res.Reason, c.want, c.reason)
		}
	}

	// geo_priority=false：非白名单进程 -> 直连旁路
	r.mu.Lock()
	r.resolved.GeoPriority = false
	r.mu.Unlock()
	res := r.Decide("www.google.com", net.ParseIP("8.8.8.8"), "firefox.exe")
	if res.Decision != DecisionDirect || res.Reason != "process:bypass" {
		t.Errorf("非白名单进程应直连旁路, got (%v, %q)", res.Decision, res.Reason)
	}
	// 白名单进程仍走地理分流
	res = r.Decide("www.google.com", net.ParseIP("8.8.8.8"), "chrome.exe")
	if res.Decision != DecisionProxy {
		t.Errorf("白名单进程国外域名应走代理, got %v", res.Decision)
	}

	// split 关闭 -> 全部走代理（保持原行为）
	r.mu.Lock()
	r.resolved.Enabled = false
	r.mu.Unlock()
	res = r.Decide("www.baidu.com", net.ParseIP("114.114.114.114"), "chrome.exe")
	if res.Decision != DecisionProxy {
		t.Errorf("split 关闭时应全部走代理, got %v", res.Decision)
	}
}

func TestParseDNSQuery(t *testing.T) {
	// 构造一个最简单的 A 查询：example.com A
	q := make([]byte, 0, 64)
	q = append(q, 0x12, 0x34)          // ID
	q = append(q, 0x01, 0x00)          // flags: RD
	q = append(q, 0x00, 0x01)          // QDCOUNT
	q = append(q, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // AN/NS/AR
	q = append(q, 7)                   // label len
	q = append(q, []byte("example")...)
	q = append(q, 3)
	q = append(q, []byte("com")...)
	q = append(q, 0) // root
	q = append(q, 0x00, 0x01)          // QTYPE A
	q = append(q, 0x00, 0x01)          // QCLASS IN

	name, qtype, ok := parseDNSQuery(q)
	if !ok {
		t.Fatal("parseDNSQuery 失败")
	}
	if name != "example.com" {
		t.Errorf("qname = %q, want example.com", name)
	}
	if qtype != 1 {
		t.Errorf("qtype = %d, want 1", qtype)
	}

	// 畸形查询
	if _, _, ok := parseDNSQuery([]byte{0x12, 0x34}); ok {
		t.Error("畸形查询不应解析成功")
	}
}

func TestMinAnswerTTL(t *testing.T) {
	// 构造响应：1 个问题 + 1 个答案（A 记录，TTL=300）
	resp := make([]byte, 0, 64)
	resp = append(resp, 0x12, 0x34)
	resp = append(resp, 0x81, 0x80)                // QR+RD+RA
	resp = append(resp, 0x00, 0x01)                // QDCOUNT
	resp = append(resp, 0x00, 0x01)                // ANCOUNT
	resp = append(resp, 0x00, 0x00, 0x00, 0x00)    // NS/AR
	// question
	resp = append(resp, 7)
	resp = append(resp, []byte("example")...)
	resp = append(resp, 3)
	resp = append(resp, []byte("com")...)
	resp = append(resp, 0)
	resp = append(resp, 0x00, 0x01, 0x00, 0x01)
	// answer: name pointer 0xC00C, type A, class IN, ttl 300, rdlen 4, rdata
	resp = append(resp, 0xC0, 0x0C)
	resp = append(resp, 0x00, 0x01, 0x00, 0x01)
	var ttl [4]byte
	binary.BigEndian.PutUint32(ttl[:], 300)
	resp = append(resp, ttl[:]...)
	resp = append(resp, 0x00, 0x04)
	resp = append(resp, 93, 184, 216, 34)

	got := minAnswerTTL(resp)
	if got < 300 || got > 300 {
		t.Errorf("minAnswerTTL = %d, want 300", got)
	}
}
