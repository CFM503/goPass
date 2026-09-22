package engine

import (
	"net"
	"testing"
)

func TestIsPrivateOrLocalV4(t *testing.T) {
	private := []string{"0.1.2.3", "10.0.0.1", "127.0.0.1", "169.254.1.1", "172.16.0.1",
		"172.31.255.255", "192.168.1.1", "100.64.0.1", "100.127.255.255", "192.0.0.1", "224.0.0.1", "255.255.255.255"}
	public := []string{"1.1.1.1", "8.8.8.8", "172.32.0.1", "100.63.255.255", "100.128.0.1", "192.0.1.1", "223.255.255.255"}
	for _, s := range private {
		if !isPrivateOrLocal(net.ParseIP(s)) {
			t.Errorf("%s should be private/local", s)
		}
	}
	for _, s := range public {
		if isPrivateOrLocal(net.ParseIP(s)) {
			t.Errorf("%s should NOT be private/local", s)
		}
	}
}

// 回归：白名单进程访问 [::1]/链路本地/ULA 必须放行，否则本机服务被黑洞。
func TestIsPrivateOrLocalV6(t *testing.T) {
	local := []string{"::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "fec0::1",
		"ff02::1", "::ffff:192.168.1.1", "::ffff:127.0.0.1"}
	remote := []string{"2606:4700:4700::1111", "2001:4860:4860::8888", "::ffff:8.8.8.8"}
	for _, s := range local {
		if !isPrivateOrLocalV6(net.ParseIP(s)) {
			t.Errorf("%s should be private/local", s)
		}
	}
	for _, s := range remote {
		if isPrivateOrLocalV6(net.ParseIP(s)) {
			t.Errorf("%s should NOT be private/local", s)
		}
	}
}

func TestIsPrivateOrLocal4MatchesIPLess(t *testing.T) {
	// 字节版与 net.IP 版必须完全一致，避免两条路径行为分叉
	for _, s := range []string{"1.2.3.4", "10.1.2.3", "127.0.0.1", "169.254.0.1", "172.20.0.1",
		"192.168.0.1", "100.100.100.100", "192.0.0.9", "230.1.1.1", "255.0.0.0"} {
		ip := net.ParseIP(s).To4()
		if got, want := isPrivateOrLocal4(ip[0], ip[1], ip[2], ip[3]), isPrivateOrLocal(ip); got != want {
			t.Errorf("%s: byte=%v ip=%v, want same result", s, got, want)
		}
	}
}
