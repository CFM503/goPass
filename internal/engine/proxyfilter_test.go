package engine

import (
	"net"
	"strings"
	"testing"
)

// parseIPv4Bytes 是逐包比对的上游地址豁免，它只负责"能不能解析"，
// 不做回环剔除（那是 proxyFilterIP / buildFilter 的事）。
func TestParseIPv4Bytes(t *testing.T) {
	cases := []struct {
		in     string
		want   [4]byte
		wantOK bool
		note   string
	}{
		{"1.2.3.4", [4]byte{1, 2, 3, 4}, true, "普通地址"},
		{"255.255.255.255", [4]byte{255, 255, 255, 255}, true, "广播地址"},
		{"127.0.0.1", [4]byte{127, 0, 0, 1}, true, "回环在这里仍然解析成功"},
		{"192.168.1.1", [4]byte{192, 168, 1, 1}, true, "内网地址照样解析"},
		{"::ffff:8.8.8.8", [4]byte{8, 8, 8, 8}, true, "v4 映射地址必须等价于 v4"},
		{"", [4]byte{}, false, "空串：不做上游豁免"},
		{"example.com", [4]byte{}, false, "主机名：这里不做 DNS"},
		{"::1", [4]byte{}, false, "纯 IPv6"},
		{"2001:db8::1", [4]byte{}, false, "纯 IPv6"},
		{"1.2.3", [4]byte{}, false, "不完整的 v4"},
		{"256.1.1.1", [4]byte{}, false, "越界分量"},
		{" 1.2.3.4", [4]byte{}, false, "前导空白不 trim"},
	}
	for _, c := range cases {
		t.Run(c.in+"/"+c.note, func(t *testing.T) {
			got, ok := parseIPv4Bytes(c.in)
			if ok != c.wantOK {
				t.Fatalf("parseIPv4Bytes(%q) ok=%v, want %v", c.in, ok, c.wantOK)
			}
			if ok && got != c.want {
				t.Fatalf("parseIPv4Bytes(%q)=%v, want %v", c.in, got, c.want)
			}
		})
	}
}

// proxyFilterIP 的结果会被拼进 WinDivert 过滤器做 "ip.DstAddr != X" 豁免。
// 回环必须被剔除：TProxy 自己的流量就走 127.0.0.1，豁免掉它等于放走全部代理流量。
func TestProxyFilterIPReturnsLiteralIPv4(t *testing.T) {
	for _, in := range []string{"1.2.3.4", "8.8.8.8", "192.168.1.1"} {
		if got := proxyFilterIP(in); got != in {
			t.Fatalf("proxyFilterIP(%q)=%q, want %q（字面量必须原样返回，不走 DNS）", in, got, in)
		}
	}
}

func TestProxyFilterIPExcludesLoopbackAndUnresolvable(t *testing.T) {
	cases := []struct {
		in   string
		note string
	}{
		{"127.0.0.1", "回环字面量"},
		{"127.0.0.53", "回环字面量（非 .1）"},
		{"::1", "IPv6 回环"},
		{"", "空配置"},
		{"localhost", "经 LookupIP 解析后只剩回环"},
	}
	for _, c := range cases {
		t.Run(c.in+"/"+c.note, func(t *testing.T) {
			if got := proxyFilterIP(c.in); got != "" {
				t.Fatalf("proxyFilterIP(%q)=%q, want \"\"", c.in, got)
			}
		})
	}
}

// 把 proxyFilterIP 的结论接到真实的过滤器字符串上，
// 钉死"回环上游不得被加入豁免"这条不变式。
func TestBuildFilterDoesNotExemptLoopbackProxy(t *testing.T) {
	ct := NewConnTracker(60, 600, 7893)
	defer ct.Close()

	// 上游是回环：过滤器里 127.0.0.1 只应出现基础豁免各 1 次（tcp / quic 各一），
	// 绝不能因为上游地址而再多加一条豁免。
	loopback := NewInterceptor(ct, "127.0.0.1", 1080, 7893, nil)
	defer loopback.Close()
	if n := strings.Count(loopback.buildFilter(), "127.0.0.1"); n != 2 {
		t.Fatalf("回环上游的过滤器里 127.0.0.1 出现 %d 次, want 2（tcp+quic 基础豁免，无额外豁免）", n)
	}

	// 上游是普通 v4：豁免必须出现在 tcp 与 quic 两段里。
	normal := NewInterceptor(ct, "1.2.3.4", 1080, 7893, nil)
	defer normal.Close()
	if n := strings.Count(normal.buildFilter(), "ip.DstAddr != 1.2.3.4"); n != 2 {
		t.Fatalf("普通上游的过滤器里豁免出现 %d 次, want 2（tcp + quic）", n)
	}
}

// net.ParseIP 对空白/非法输入的行为是 parseIPv4Bytes 的前置假设，一并钉住。
func TestNetParseIPAssumptionsUsedByProxyFilter(t *testing.T) {
	if net.ParseIP("") != nil {
		t.Fatal("net.ParseIP(\"\") 应为 nil")
	}
	if net.ParseIP("::1").To4() != nil {
		t.Fatal("纯 IPv6 的 To4() 应为 nil")
	}
	if got := net.ParseIP("::ffff:8.8.8.8").To4(); got == nil {
		t.Fatal("v4 映射地址的 To4() 不应为 nil")
	}
}
