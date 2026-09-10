package engine

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type ConnKey struct { SrcIP string; SrcPort uint16 }
type OrigFlowKey struct { SrcIP string; SrcPort uint16; DstIP string; DstPort uint16 }
type ConnTarget struct { OrigSrcIP net.IP; OrigSrcPort uint16; OrigDstIP net.IP; OrigDstPort uint16; OrigIfIdx uint32; OrigSubIfIdx uint32; CreatedAt time.Time }
type ConnTracker struct { mu sync.RWMutex; entries map[ConnKey]ConnTarget; active map[ConnKey]struct{}; orig map[OrigFlowKey]ConnKey; stopCh chan struct{}; closeOnce sync.Once; gcInterval int; ttl int; nextPort uint16; reservedPort uint16 }

const (
	mappedPortMin = 32768
	mappedPortMax = 60999
)

func NewConnTracker(gcInterval, ttl int, reservedPort uint16) *ConnTracker {
	if gcInterval <= 0 { gcInterval = 15 }
	if ttl <= 0 { ttl = 30 }
	ct := &ConnTracker{entries: make(map[ConnKey]ConnTarget), active: make(map[ConnKey]struct{}), orig: make(map[OrigFlowKey]ConnKey), stopCh: make(chan struct{}), gcInterval: gcInterval, ttl: ttl, nextPort: mappedPortMin, reservedPort: reservedPort}
	go ct.startGC()
	return ct
}

// Set returns the same mapped port for every packet belonging to the same
// original TCP flow. This is essential: WinDivert sees every outbound packet,
// not only the SYN. Allocating a new port for each packet would create a new
// local TProxy connection for every segment and break the TCP stream.
func (ct *ConnTracker) Set(origSrcIP net.IP, origSrcPort uint16, origDstIP net.IP, origDstPort uint16, origIfIdx, origSubIfIdx uint32) (uint16, bool) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	origKey := OrigFlowKey{origSrcIP.String(), origSrcPort, origDstIP.String(), origDstPort}
	if mapped, exists := ct.orig[origKey]; exists {
		if _, ok := ct.entries[mapped]; ok {
			return mapped.SrcPort, true
		}
		delete(ct.orig, origKey)
	}

	for attempts := 0; attempts <= mappedPortMax-mappedPortMin; attempts++ {
		port := ct.nextPort
		ct.nextPort++
		if ct.nextPort > mappedPortMax { ct.nextPort = mappedPortMin }
		if port == ct.reservedPort { continue }
		key := ConnKey{"127.0.0.1", port}
		if _, exists := ct.entries[key]; exists { continue }
		ct.entries[key] = ConnTarget{
			OrigSrcIP: append(net.IP(nil), origSrcIP...), OrigSrcPort: origSrcPort,
			OrigDstIP: append(net.IP(nil), origDstIP...), OrigDstPort: origDstPort,
			OrigIfIdx: origIfIdx, OrigSubIfIdx: origSubIfIdx, CreatedAt: time.Now(),
		}
		ct.orig[origKey] = key
		return port, true
	}
	return 0, false
}

func (ct *ConnTracker) Activate(mappedIP string, mappedPort uint16) {
	ct.mu.Lock()
	key := ConnKey{mappedIP, mappedPort}
	if _, ok := ct.entries[key]; ok { ct.active[key] = struct{}{} }
	ct.mu.Unlock()
}

func (ct *ConnTracker) Get(srcIP string, srcPort uint16) (ConnTarget, bool) {
	ct.mu.RLock()
	v, ok := ct.entries[ConnKey{srcIP, srcPort}]
	ct.mu.RUnlock()
	return v, ok
}

func (ct *ConnTracker) Delete(srcIP string, srcPort uint16) {
	ct.mu.Lock()
	key := ConnKey{srcIP, srcPort}
	delete(ct.active, key)
	if entry, ok := ct.entries[key]; ok {
		origKey := OrigFlowKey{entry.OrigSrcIP.String(), entry.OrigSrcPort, entry.OrigDstIP.String(), entry.OrigDstPort}
		if mapped, exists := ct.orig[origKey]; exists && mapped == key { delete(ct.orig, origKey) }
	}
	delete(ct.entries, key)
	ct.mu.Unlock()
}

func (ct *ConnTracker) startGC() {
	ticker := time.NewTicker(time.Duration(ct.gcInterval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ct.stopCh: return
		case <-ticker.C:
			now := time.Now()
			ct.mu.Lock()
			for k, v := range ct.entries {
				if _, active := ct.active[k]; active { continue }
				if now.Sub(v.CreatedAt) > time.Duration(ct.ttl)*time.Second {
					origKey := OrigFlowKey{v.OrigSrcIP.String(), v.OrigSrcPort, v.OrigDstIP.String(), v.OrigDstPort}
					if mapped, exists := ct.orig[origKey]; exists && mapped == k { delete(ct.orig, origKey) }
					delete(ct.entries, k)
				}
			}
			ct.mu.Unlock()
		}
	}
}

func (ct *ConnTracker) Close() { ct.closeOnce.Do(func() { close(ct.stopCh) }) }
func (ct *ConnTarget) String() string { return fmt.Sprintf("%s:%d -> %s:%d", ct.OrigSrcIP.String(), ct.OrigSrcPort, ct.OrigDstIP.String(), ct.OrigDstPort) }
