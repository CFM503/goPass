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

// UDPBlocker handles only outbound IPv4 UDP/443. GoPass does not proxy UDP.
// For a whitelisted process we discard QUIC packets so Chromium and other
// clients can quickly fall back to the existing TCP transparent-proxy path.
// Non-whitelisted UDP/443 traffic is passed through unchanged.
type UDPBlocker struct {
	handle    *winDivertHandle
	mu        sync.RWMutex
	resolver  *process.Resolver
	whitelist map[string]struct{}
	proxyIP   string
	stopCh    chan struct{}
	closeOnce sync.Once
}

func NewUDPBlocker(proxyIP string, whitelist []string) *UDPBlocker {
	u := &UDPBlocker{
		resolver:  process.NewResolver(),
		whitelist: make(map[string]struct{}),
		proxyIP:   proxyIP,
		stopCh:    make(chan struct{}),
	}
	u.SetWhitelist(whitelist)
	return u
}

func (u *UDPBlocker) SetWhitelist(list []string) {
	m := make(map[string]struct{}, len(list))
	for _, name := range list {
		name = strings.TrimSpace(strings.ToLower(name))
		if name != "" {
			m[name] = struct{}{}
		}
	}
	u.mu.Lock()
	u.whitelist = m
	u.mu.Unlock()
}

func (u *UDPBlocker) SetProxyIP(ip string) {
	u.mu.Lock()
	u.proxyIP = ip
	u.mu.Unlock()
}

func (u *UDPBlocker) buildFilter() string {
	u.mu.RLock()
	proxyIP := u.proxyIP
	u.mu.RUnlock()
	f := "outbound and ip and udp and udp.DstPort == 443 and ip.DstAddr != 127.0.0.1"
	if pip := net.ParseIP(proxyIP); pip != nil && pip.To4() != nil && !pip.IsLoopback() {
		f += fmt.Sprintf(" and ip.DstAddr != %s", pip.To4().String())
	}
	return f
}

func (u *UDPBlocker) preflight() error {
	h, err := wdOpen(u.buildFilter(), layerNetwork, priorityDefault, 0)
	if err != nil {
		return fmt.Errorf("WinDivert UDP/QUIC blocker 初始化失败：%w", err)
	}
	h.Close()
	return nil
}

func (u *UDPBlocker) Start() error {
	h, err := wdOpen(u.buildFilter(), layerNetwork, priorityDefault, 0)
	if err != nil {
		return fmt.Errorf("WinDivert UDP/QUIC blocker 启动失败：%w", err)
	}
	u.mu.Lock()
	u.handle = h
	u.mu.Unlock()
	_ = u.resolver.Refresh()
	log.Println("[WinDivert] whitelist-aware UDP/443 QUIC fallback blocker ready")
	go u.refreshLoop()

	buf := make([]byte, 2048)
	for {
		select {
		case <-u.stopCh:
			return nil
		default:
		}
		u.mu.RLock()
		h = u.handle
		u.mu.RUnlock()
		if h == nil {
			return nil
		}
		n, addr, err := h.Recv(buf)
		if err != nil {
			select {
			case <-u.stopCh:
				return nil
			default:
				time.Sleep(5 * time.Millisecond)
			}
			continue
		}
		if n > 0 && n <= len(buf) {
			u.handlePacket(buf[:n], addr)
		}
	}
}

func (u *UDPBlocker) refreshLoop() {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-u.stopCh:
			return
		case <-ticker.C:
			_ = u.resolver.Refresh()
		}
	}
}

func (u *UDPBlocker) handlePacket(pkt []byte, addr *winDivertAddress) {
	if len(pkt) < 28 || (pkt[0]>>4) != 4 || pkt[9] != 17 {
		u.sendPass(pkt, addr)
		return
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		u.sendPass(pkt, addr)
		return
	}
	dstPort := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	if dstPort != 443 {
		u.sendPass(pkt, addr)
		return
	}

	srcIP := binary.LittleEndian.Uint32(pkt[12:16])
	srcPort := binary.BigEndian.Uint16(pkt[ihl : ihl+2])
	entry, ok := u.resolver.LookupUDP(process.UDPFlow{LocalIP: srcIP, LocalPort: srcPort})
	if !ok || !u.isWhitelisted(entry.Name) {
		u.sendPass(pkt, addr)
		return
	}

	// Intentionally do not reinject the packet. This is a narrow, process-aware
	// QUIC block: only whitelisted applications lose UDP/443, while all other
	// applications retain their normal UDP path.
}

func (u *UDPBlocker) isWhitelisted(name string) bool {
	u.mu.RLock()
	_, ok := u.whitelist[strings.ToLower(name)]
	u.mu.RUnlock()
	return ok
}

func (u *UDPBlocker) sendPass(pkt []byte, addr *winDivertAddress) {
	u.mu.RLock()
	h := u.handle
	u.mu.RUnlock()
	if h != nil {
		_ = h.Send(pkt, addr)
	}
}

func (u *UDPBlocker) Close() {
	u.closeOnce.Do(func() {
		close(u.stopCh)
		u.mu.Lock()
		h := u.handle
		u.handle = nil
		u.mu.Unlock()
		if h != nil {
			h.Close()
		}
	})
}
