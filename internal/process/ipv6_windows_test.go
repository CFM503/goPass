//go:build windows

package process

import (
	"encoding/binary"
	"net"
	"testing"
)

// 本文件刻意不引用任何被测侧的偏移常量：字段偏移按 Windows SDK 头 tcpmib.h
// 独立写死。历史上实现方把行布局整体错位 4 字节，如果测试也照抄实现的偏移，
// 两侧会一起错并互相“验证通过”——正是当初漏掉该 bug 的原因。

const (
	mibTCP6RowSize = 56

	// MIB_TCP_STATE 取自 tcpmib.h：CLOSED=1、LISTEN=2、SYN_SENT=3、
	// SYN_RCVD=4、ESTAB=5……（不是 iprtrmib.h 那套以 ESTABLISHED=1 开头的枚举，
	// 实测 GetExtendedTcpTable 返回的是前者）。
	mibTCPStateClosed = 1
	mibTCPStateEstab  = 5
)

// 端口以网络字序存进 DWORD：高字节在前，低 16 位补 0。
func putNetworkOrderPort(dst []byte, port uint16) {
	dst[0], dst[1], dst[2], dst[3] = byte(port>>8), byte(port), 0, 0
}

// buildIPv6TCPRow 构造一行 MIB_TCP6ROW_OWNER_PID（56 字节）。
func buildIPv6TCPRow(local, remote [16]byte, localPort, remotePort uint16, state, pid uint32) []byte {
	row := make([]byte, mibTCP6RowSize)
	copy(row[0:16], local[:])                        // ucLocalAddr @0
	binary.LittleEndian.PutUint32(row[16:20], 0)     // dwLocalScopeId @16
	putNetworkOrderPort(row[20:24], localPort)       // dwLocalPort @20
	copy(row[24:40], remote[:])                      // ucRemoteAddr @24
	binary.LittleEndian.PutUint32(row[40:44], 0)     // dwRemoteScopeId @40
	putNetworkOrderPort(row[44:48], remotePort)      // dwRemotePort @44
	binary.LittleEndian.PutUint32(row[48:52], state) // dwState @48
	binary.LittleEndian.PutUint32(row[52:56], pid)   // dwOwningPid @52
	return row
}

// buildIPv6TCPTable 组装 count 头 + 若干行。
func buildIPv6TCPTable(rows ...[]byte) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(len(rows)))
	for _, r := range rows {
		buf = append(buf, r...)
	}
	return buf
}

// nameByPID 返回一个只认指定 PID 的进程名解析桩。
func nameByPID(pid uint32) func(uint32) string {
	return func(got uint32) string {
		if got == pid {
			return "chrome.exe"
		}
		return ""
	}
}

var (
	testLocalIPv6  = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1} // 2001:db8::1
	testRemoteIPv6 = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2} // 2001:db8::2
)

// 每个字段单独断言：任何一处偏移错位都会报出具体是哪个字段，
// 而不是笼统的“键不匹配”，方便定位。
func TestParseIPv6TCPRowsDecodesEveryField(t *testing.T) {
	row := buildIPv6TCPRow(testLocalIPv6, testRemoteIPv6, 64681, 443, mibTCPStateEstab, 4242)
	got := parseIPv6TCPRows(buildIPv6TCPTable(row), nameByPID(4242))
	if len(got) != 1 {
		t.Fatalf("entries=%d, want 1", len(got))
	}
	var key IPv6TCPFlow
	var name string
	for k, v := range got {
		key, name = k, v
	}
	if key.LocalIP != testLocalIPv6 {
		t.Errorf("LocalIP=%s, want %s", net.IP(key.LocalIP[:]), net.IP(testLocalIPv6[:]))
	}
	if key.LocalPort != 64681 {
		t.Errorf("LocalPort=%d, want 64681", key.LocalPort)
	}
	if key.RemoteIP != testRemoteIPv6 {
		t.Errorf("RemoteIP=%s, want %s", net.IP(key.RemoteIP[:]), net.IP(testRemoteIPv6[:]))
	}
	if key.RemotePort != 443 {
		t.Errorf("RemotePort=%d, want 443", key.RemotePort)
	}
	if name != "chrome.exe" {
		t.Errorf("name=%q, want chrome.exe", name)
	}
}

// dwState 在行尾而非行首：读错位置会让 CLOSED 死行漏进来。
func TestParseIPv6TCPRowsSkipsClosedState(t *testing.T) {
	closed := buildIPv6TCPRow(testLocalIPv6, testRemoteIPv6, 64681, 443, mibTCPStateClosed, 4242)
	if got := parseIPv6TCPRows(buildIPv6TCPTable(closed), nameByPID(4242)); len(got) != 0 {
		t.Fatalf("CLOSED row must be dropped, got %d entries", len(got))
	}
	estab := buildIPv6TCPRow(testLocalIPv6, testRemoteIPv6, 64681, 443, mibTCPStateEstab, 4242)
	if got := parseIPv6TCPRows(buildIPv6TCPTable(estab), nameByPID(4242)); len(got) != 1 {
		t.Fatalf("ESTAB row must be kept, got %d entries", len(got))
	}
}

// 解析不出进程名的行必须整行丢弃，否则会把别人的流量算到白名单头上。
func TestParseIPv6TCPRowsDropsUnknownPID(t *testing.T) {
	row := buildIPv6TCPRow(testLocalIPv6, testRemoteIPv6, 64681, 443, mibTCPStateEstab, 4242)
	if got := parseIPv6TCPRows(buildIPv6TCPTable(row), nameByPID(999)); len(got) != 0 {
		t.Fatalf("unresolved pid must be dropped, got %d entries", len(got))
	}
}

// 表在两次查询之间变长时会拿到截断缓冲区：必须安全停下，不得越界 panic。
func TestParseIPv6TCPRowsHandlesTruncatedBuffer(t *testing.T) {
	for _, size := range []int{0, 2, 4, 5, 4 + 55, 4 + 56} {
		buf := make([]byte, size)
		if size >= 4 {
			binary.LittleEndian.PutUint32(buf, 1) // 声称 1 行，缓冲区可能不够
		}
		if got := parseIPv6TCPRows(buf, nameByPID(4242)); len(got) != 0 {
			t.Fatalf("size=%d: truncated buffer must yield 0 entries, got %d", size, len(got))
		}
	}
}
