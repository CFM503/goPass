//go:build windows

package process

import (
    "encoding/binary"
    "sync"
    "time"
    "unsafe"
)

type IPv6TCPFlow struct { LocalIP [16]byte; LocalPort uint16; RemoteIP [16]byte; RemotePort uint16 }
type ipv6TCPResolver struct { mu sync.RWMutex; flows map[IPv6TCPFlow]string; last time.Time }
var ipv6TCP = &ipv6TCPResolver{flows: make(map[IPv6TCPFlow]string)}
func RefreshIPv6TCP() { ipv6TCP.refresh() }
func LookupIPv6TCP(flow IPv6TCPFlow) (string, bool) { ipv6TCP.mu.RLock(); name, ok := ipv6TCP.flows[flow]; ipv6TCP.mu.RUnlock(); return name, ok }

// parseIPv6TCPRows 解析 GetExtendedTcpTable(AF_INET6, TCP_TABLE_OWNER_PID_ALL) 的缓冲区。
// MIB_TCP6ROW_OWNER_PID 恰好 56 字节，字段顺序来自 tcpmib.h（注意 dwState 在尾部，
// 不像 IPv4 的 MIB_TCPROW_OWNER_PID 那样在开头）：
//
//	ucLocalAddr[16]@0   dwLocalScopeId@16  dwLocalPort@20
//	ucRemoteAddr[16]@24 dwRemoteScopeId@40 dwRemotePort@44
//	dwState@48           dwOwningPid@52
//
// 早期实现照搬了 IPv4 的"dwState 在开头"，把除 pid 外的所有字段整体错位 4 字节
// （remotePort 甚至读到了 dwState，ntohs(5)=1280），导致 IPv6 流量键永远匹配不上、
// 白名单进程的 IPv6 TCP 从未被阻断。偏移由 ipv6_windows_test.go 逐字段钉死。
// nameOf 生产路径传 processName，测试传桩。
func parseIPv6TCPRows(buf []byte, nameOf func(uint32) string) map[IPv6TCPFlow]string {
    if len(buf) < 4 { return nil }
    count := binary.LittleEndian.Uint32(buf[0:4]); const rowSize = 56
    flows := make(map[IPv6TCPFlow]string, count)
    for n := uint32(0); n < count; n++ {
        off := 4 + n*rowSize; if off+rowSize > uint32(len(buf)) { break }; row := buf[off:off+rowSize]
        if binary.LittleEndian.Uint32(row[48:52]) == 1 { continue } // 跳过 CLOSED 死行
        var localIP, remoteIP [16]byte; copy(localIP[:], row[0:16]); copy(remoteIP[:], row[24:40])
        localPort := ntohs(uint16(binary.LittleEndian.Uint32(row[20:24]))); remotePort := ntohs(uint16(binary.LittleEndian.Uint32(row[44:48])))
        pid := binary.LittleEndian.Uint32(row[52:56]); name := nameOf(pid); if name == "" { continue }
        flows[IPv6TCPFlow{LocalIP: localIP, LocalPort: localPort, RemoteIP: remoteIP, RemotePort: remotePort}] = name
    }
    return flows
}

func (r *ipv6TCPResolver) refresh() {
    r.mu.RLock(); if time.Since(r.last) < 200*time.Millisecond { r.mu.RUnlock(); return }; r.mu.RUnlock()
    // 取不到（含空表）就保留上一次快照且不推进 last，下一次调用可立即重试。
    buf, err := queryWinTable(getExtendedTCPTable, 1, 23, tcpTableOwnerPidAll, 0)
    if err != nil || len(buf) == 0 { return }
    flows := parseIPv6TCPRows(buf, processName)
    r.mu.Lock(); r.flows = flows; r.last = time.Now(); r.mu.Unlock()
}

type IPv6UDPFlow struct { LocalIP [16]byte; LocalPort uint16 }
var ipv6UDP = struct { mu sync.RWMutex; m map[IPv6UDPFlow]string; last time.Time }{m: make(map[IPv6UDPFlow]string)}
func RefreshIPv6UDP() { refreshIPv6UDP() }
func LookupIPv6UDP(flow IPv6UDPFlow) (string, bool) { ipv6UDP.mu.RLock(); name, ok := ipv6UDP.m[flow]; ipv6UDP.mu.RUnlock(); return name, ok }
func refreshIPv6UDP() {
    ipv6UDP.mu.RLock(); if time.Since(ipv6UDP.last) < 200*time.Millisecond { ipv6UDP.mu.RUnlock(); return }; ipv6UDP.mu.RUnlock()
    buf, err := queryWinTable(getExtendedUDPTable, 1, 23, udpTableOwnerPid, 0)
    if err != nil || len(buf) == 0 { return }
    count := *(*uint32)(unsafe.Pointer(&buf[0])); const rowSize = 28
    flows := make(map[IPv6UDPFlow]string, count)
    for n := uint32(0); n < count; n++ {
        off := 4 + n*rowSize; if off+rowSize > uint32(len(buf)) { break }; row := buf[off:off+rowSize]
        var localIP [16]byte; copy(localIP[:], row[0:16]); localPort := ntohs(uint16(binary.LittleEndian.Uint32(row[20:24])))
        pid := binary.LittleEndian.Uint32(row[24:28]); name := processName(pid); if name != "" { flows[IPv6UDPFlow{LocalIP: localIP, LocalPort: localPort}] = name }
    }
    ipv6UDP.mu.Lock(); ipv6UDP.m = flows; ipv6UDP.last = time.Now(); ipv6UDP.mu.Unlock()
}
