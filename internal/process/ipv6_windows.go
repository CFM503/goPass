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
func (r *ipv6TCPResolver) refresh() {
    r.mu.RLock(); if time.Since(r.last) < 200*time.Millisecond { r.mu.RUnlock(); return }; r.mu.RUnlock()
    size := uint32(0)
    ret, _, _ := getExtendedTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, 23, tcpTableOwnerPidAll, 0)
    if size == 0 || (ret != 0 && ret != 122) { return }
    buf := make([]byte, size)
    ret, _, _ = getExtendedTCPTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, 23, tcpTableOwnerPidAll, 0)
    if ret != 0 { return }
    count := *(*uint32)(unsafe.Pointer(&buf[0])); const rowSize = 56
    flows := make(map[IPv6TCPFlow]string, count)
    for n := uint32(0); n < count; n++ {
        off := 4 + n*rowSize; if off+rowSize > uint32(len(buf)) { break }; row := buf[off:off+rowSize]
        if binary.LittleEndian.Uint32(row[0:4]) == 1 { continue }
        var localIP, remoteIP [16]byte; copy(localIP[:], row[4:20]); copy(remoteIP[:], row[28:44])
        localPort := ntohs(uint16(binary.LittleEndian.Uint32(row[24:28]))); remotePort := ntohs(uint16(binary.LittleEndian.Uint32(row[48:52])))
        pid := binary.LittleEndian.Uint32(row[52:56]); name := processName(pid); if name == "" { continue }
        flows[IPv6TCPFlow{LocalIP: localIP, LocalPort: localPort, RemoteIP: remoteIP, RemotePort: remotePort}] = name
    }
    r.mu.Lock(); r.flows = flows; r.last = time.Now(); r.mu.Unlock()
}

type IPv6UDPFlow struct { LocalIP [16]byte; LocalPort uint16 }
var ipv6UDP = struct { mu sync.RWMutex; m map[IPv6UDPFlow]string; last time.Time }{m: make(map[IPv6UDPFlow]string)}
func RefreshIPv6UDP() { refreshIPv6UDP() }
func LookupIPv6UDP(flow IPv6UDPFlow) (string, bool) { ipv6UDP.mu.RLock(); name, ok := ipv6UDP.m[flow]; ipv6UDP.mu.RUnlock(); return name, ok }
func refreshIPv6UDP() {
    ipv6UDP.mu.RLock(); if time.Since(ipv6UDP.last) < 200*time.Millisecond { ipv6UDP.mu.RUnlock(); return }; ipv6UDP.mu.RUnlock()
    size := uint32(0)
    ret, _, _ := getExtendedUDPTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, 23, udpTableOwnerPid, 0)
    if size == 0 || (ret != 0 && ret != 122) { return }
    buf := make([]byte, size)
    ret, _, _ = getExtendedUDPTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, 23, udpTableOwnerPid, 0)
    if ret != 0 { return }
    count := *(*uint32)(unsafe.Pointer(&buf[0])); const rowSize = 28
    flows := make(map[IPv6UDPFlow]string, count)
    for n := uint32(0); n < count; n++ {
        off := 4 + n*rowSize; if off+rowSize > uint32(len(buf)) { break }; row := buf[off:off+rowSize]
        var localIP [16]byte; copy(localIP[:], row[0:16]); localPort := ntohs(uint16(binary.LittleEndian.Uint32(row[20:24])))
        pid := binary.LittleEndian.Uint32(row[24:28]); name := processName(pid); if name != "" { flows[IPv6UDPFlow{LocalIP: localIP, LocalPort: localPort}] = name }
    }
    ipv6UDP.mu.Lock(); ipv6UDP.m = flows; ipv6UDP.last = time.Now(); ipv6UDP.mu.Unlock()
}
