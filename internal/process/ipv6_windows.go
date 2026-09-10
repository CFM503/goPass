//go:build windows

package process

import (
    "encoding/binary"
    "net"
    "sync"
    "time"
    "unsafe"
)

type IPv6TCPFlow struct {
    LocalIP   [16]byte
    LocalPort uint16
    RemoteIP  [16]byte
    RemotePort uint16
}

type ipv6TCPEntry struct {
    Name      string
    checkedAt time.Time
}

type ipv6TCPResolver struct {
    mu     sync.RWMutex
    flows  map[IPv6TCPFlow]string
    last   time.Time
}

var ipv6TCP = &ipv6TCPResolver{flows: make(map[IPv6TCPFlow]string)}

func RefreshIPv6TCP() {
    ipv6TCP.refresh()
}

func LookupIPv6TCP(flow IPv6TCPFlow) (string, bool) {
    ipv6TCP.mu.RLock()
    name, ok := ipv6TCP.flows[flow]
    ipv6TCP.mu.RUnlock()
    return name, ok
}

func (r *ipv6TCPResolver) refresh() {
    r.mu.RLock()
    if time.Since(r.last) < 200*time.Millisecond {
        r.mu.RUnlock()
        return
    }
    r.mu.RUnlock()

    size := uint32(0)
    ret, _, _ := getExtendedTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, 23, tcpTableOwnerPidAll, 0)
    if size == 0 || (ret != 0 && ret != 122) {
        return
    }
    buf := make([]byte, size)
    ret, _, _ = getExtendedTCPTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, 23, tcpTableOwnerPidAll, 0)
    if ret != 0 {
        return
    }

    count := *(*uint32)(unsafe.Pointer(&buf[0]))
    const rowSize = 56
    flows := make(map[IPv6TCPFlow]string, count)
    now := time.Now()
    for n := uint32(0); n < count; n++ {
        off := 4 + n*rowSize
        if off+rowSize > uint32(len(buf)) {
            break
        }
        row := buf[off : off+rowSize]
        state := binary.LittleEndian.Uint32(row[0:4])
        if state == 1 {
            continue
        }
        var localIP, remoteIP [16]byte
        copy(localIP[:], row[4:20])
        localPort := ntohs(uint16(binary.LittleEndian.Uint32(row[24:28])))
        copy(remoteIP[:], row[28:44])
        remotePort := ntohs(uint16(binary.LittleEndian.Uint32(row[48:52])))
        pid := binary.LittleEndian.Uint32(row[52:56])
        name := processName(pid)
        if name == "" {
            continue
        }
        flows[IPv6TCPFlow{LocalIP: localIP, LocalPort: localPort, RemoteIP: remoteIP, RemotePort: remotePort}] = name
    }

    r.mu.Lock()
    r.flows = flows
    r.last = now
    r.mu.Unlock()
}

func IPv6FlowFromNet(localIP net.IP, localPort uint16, remoteIP net.IP, remotePort uint16) (IPv6TCPFlow, bool) {
    l := localIP.To16()
    rr := remoteIP.To16()
    if l == nil || rr == nil || l.To4() != nil || rr.To4() != nil {
        return IPv6TCPFlow{}, false
    }
    var f IPv6TCPFlow
    copy(f.LocalIP[:], l)
    copy(f.RemoteIP[:], rr)
    f.LocalPort = localPort
    f.RemotePort = remotePort
    return f, true
}
