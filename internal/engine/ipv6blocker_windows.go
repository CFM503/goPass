//go:build windows

package engine

import (
    "encoding/binary"
    "fmt"
    "log"
    "net"
    "strings"
    "sync"
    "time"

    "github.com/CFM503/goPass/internal/process"
)

// IPv6Blocker mirrors the successful v1.6.3 YouTube fallback behavior without
// globally disabling IPv6. Only IPv6 TCP/UDP packets owned by whitelisted
// processes are discarded; all other applications keep their normal path.
type IPv6Blocker struct {
    handle    *winDivertHandle
    mu        sync.RWMutex
    whitelist map[string]struct{}
    stopCh    chan struct{}
    closeOnce sync.Once
}

func NewIPv6Blocker(whitelist []string) *IPv6Blocker {
    b := &IPv6Blocker{whitelist: make(map[string]struct{}), stopCh: make(chan struct{})}
    b.SetWhitelist(whitelist)
    return b
}

func (b *IPv6Blocker) SetWhitelist(list []string) {
    m := make(map[string]struct{}, len(list))
    for _, name := range list {
        name = strings.TrimSpace(strings.ToLower(name))
        if name != "" {
            m[name] = struct{}{}
        }
    }
    b.mu.Lock()
    b.whitelist = m
    b.mu.Unlock()
}

func (b *IPv6Blocker) buildFilter() string {
    return "outbound and ipv6"
}

func (b *IPv6Blocker) preflight() error {
    h, err := wdOpen(b.buildFilter(), layerNetwork, priorityDefault, 0)
    if err != nil {
        return fmt.Errorf("WinDivert IPv6 blocker 初始化失败：%w", err)
    }
    h.Close()
    return nil
}

func (b *IPv6Blocker) Start() error {
    h, err := wdOpen(b.buildFilter(), layerNetwork, priorityDefault, 0)
    if err != nil {
        return fmt.Errorf("WinDivert IPv6 blocker 启动失败：%w", err)
    }
    b.mu.Lock()
    b.handle = h
    b.mu.Unlock()
    process.RefreshIPv6TCP()
    log.Println("[WinDivert] whitelist-aware IPv6 blocker ready")
    go b.refreshLoop()

    buf := make([]byte, 65535)
    for {
        select {
        case <-b.stopCh:
            return nil
        default:
        }
        b.mu.RLock()
        h = b.handle
        b.mu.RUnlock()
        if h == nil {
            return nil
        }
        n, addr, err := h.Recv(buf)
        if err != nil {
            select {
            case <-b.stopCh:
                return nil
            default:
                time.Sleep(5 * time.Millisecond)
                continue
            }
        }
        if n > 0 && n <= len(buf) {
            b.handlePacket(buf[:n], addr)
        }
    }
}

func (b *IPv6Blocker) refreshLoop() {
    ticker := time.NewTicker(250 * time.Millisecond)
    defer ticker.Stop()
    for {
        select {
        case <-b.stopCh:
            return
        case <-ticker.C:
            process.RefreshIPv6TCP()
        }
    }
}

func (b *IPv6Blocker) handlePacket(pkt []byte, addr *winDivertAddress) {
    if len(pkt) < 40 || (pkt[0]>>4) != 6 {
        b.sendPass(pkt, addr)
        return
    }
    next := pkt[6]
    if next != 6 && next != 17 {
        b.sendPass(pkt, addr)
        return
    }
    off := 40
    if next == 6 {
        if len(pkt) < off+20 {
            b.sendPass(pkt, addr)
            return
        }
        srcPort := binary.BigEndian.Uint16(pkt[off : off+2])
        dstPort := binary.BigEndian.Uint16(pkt[off+2 : off+4])
        if b.isWhitelistedTCP(pkt[8:24], srcPort, pkt[24:40], dstPort) {
            return
        }
        b.sendPass(pkt, addr)
        return
    }

    // UDP has no remote endpoint in the Windows UDP owner table, so use the
    // local port and only block IPv6/UDP 443 for a matching whitelisted PID.
    if len(pkt) < off+8 {
        b.sendPass(pkt, addr)
        return
    }
    srcPort := binary.BigEndian.Uint16(pkt[off : off+2])
    dstPort := binary.BigEndian.Uint16(pkt[off+2 : off+4])
    if dstPort != 443 {
        b.sendPass(pkt, addr)
        return
    }
    // IPv6 QUIC is covered by the TCP-oriented process snapshot when Chrome
    // has a TCP fallback. If ownership cannot be established, pass the packet
    // rather than risking interference with unrelated applications.
    _ = srcPort
    b.sendPass(pkt, addr)
}

func (b *IPv6Blocker) isWhitelistedTCP(src, dst []byte, srcPort, dstPort uint16) bool {
    if len(src) != 16 || len(dst) != 16 {
        return false
    }
    var srcIP, dstIP [16]byte
    copy(srcIP[:], src)
    copy(dstIP[:], dst)
    flow := process.IPv6TCPFlow{LocalIP: srcIP, LocalPort: srcPort, RemoteIP: dstIP, RemotePort: dstPort}
    name, ok := process.LookupIPv6TCP(flow)
    return ok && b.isWhitelisted(name)
}

func (b *IPv6Blocker) isWhitelisted(name string) bool {
    b.mu.RLock()
    _, ok := b.whitelist[strings.ToLower(name)]
    b.mu.RUnlock()
    return ok
}

func (b *IPv6Blocker) sendPass(pkt []byte, addr *winDivertAddress) {
    b.mu.RLock()
    h := b.handle
    b.mu.RUnlock()
    if h != nil {
        _ = h.Send(pkt, addr)
    }
}

func (b *IPv6Blocker) Close() {
    b.closeOnce.Do(func() {
        close(b.stopCh)
        b.mu.Lock()
        h := b.handle
        b.handle = nil
        b.mu.Unlock()
        if h != nil {
            h.Close()
        }
    })
}

var _ = net.IPv6len
