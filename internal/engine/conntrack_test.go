package engine

import (
	"net"
	"testing"
	"time"
)

func TestConnTrackerAllocatesUniqueMappedPorts(t *testing.T) {
	ct := NewConnTracker(1, 1, 7893)
	defer ct.Close()

	p1, ok := ct.Set(net.ParseIP("192.168.1.10"), 50001, net.ParseIP("1.1.1.1"), 443, 1, 0)
	if !ok { t.Fatal("first mapped port allocation failed") }
	p2, ok := ct.Set(net.ParseIP("192.168.1.11"), 50001, net.ParseIP("2.2.2.2"), 443, 1, 0)
	if !ok { t.Fatal("second mapped port allocation failed") }
	if p1 == p2 { t.Fatalf("mapped ports collided: %d", p1) }
	if p1 == 7893 || p2 == 7893 { t.Fatal("mapped port used reserved TProxy port") }
}

func TestConnTrackerReusesMappedPortForSameFlow(t *testing.T) {
	ct := NewConnTracker(1, 1, 7893)
	defer ct.Close()

	ip1 := net.ParseIP("192.168.1.10")
	ip2 := net.ParseIP("1.1.1.1")
	p1, ok := ct.Set(ip1, 50001, ip2, 443, 1, 0)
	if !ok { t.Fatal("first mapped port allocation failed") }
	p2, ok := ct.Set(ip1, 50001, ip2, 443, 1, 0)
	if !ok { t.Fatal("second lookup/allocation failed") }
	if p1 != p2 { t.Fatalf("same flow received different mapped ports: %d != %d", p1, p2) }

	p3, ok := ct.Set(ip1, 50001, net.ParseIP("2.2.2.2"), 443, 1, 0)
	if !ok { t.Fatal("different flow allocation failed") }
	if p3 == p1 { t.Fatalf("different flow reused mapped port: %d", p3) }
}

func TestConnTrackerDeleteReleasesOriginalFlowIndex(t *testing.T) {
	ct := NewConnTracker(1, 1, 7893)
	defer ct.Close()

	ip1 := net.ParseIP("192.168.1.10")
	ip2 := net.ParseIP("1.1.1.1")
	p1, ok := ct.Set(ip1, 50001, ip2, 443, 1, 0)
	if !ok { t.Fatal("first mapped port allocation failed") }
	ct.Delete("127.0.0.1", p1)
	p2, ok := ct.Set(ip1, 50001, ip2, 443, 1, 0)
	if !ok { t.Fatal("reallocation after delete failed") }
	if p1 == p2 { t.Fatalf("deleted flow retained stale mapped port: %d", p1) }
}

func TestConnTrackerActiveEntrySurvivesTTL(t *testing.T) {
	ct := NewConnTracker(1, 1, 7893)
	defer ct.Close()

	p, ok := ct.Set(net.ParseIP("192.168.1.10"), 50001, net.ParseIP("1.1.1.1"), 443, 1, 0)
	if !ok { t.Fatal("mapped port allocation failed") }
	ct.Activate("127.0.0.1", p)

	ct.mu.Lock()
	key := ConnKey{"127.0.0.1", p}
	entry := ct.entries[key]
	entry.CreatedAt = time.Now().Add(-2 * time.Second)
	ct.entries[key] = entry
	ct.mu.Unlock()

	ct.startGCOnceForTest()
	if _, ok := ct.Get("127.0.0.1", p); !ok { t.Fatal("active conntrack entry was incorrectly garbage-collected") }
}

func (ct *ConnTracker) startGCOnceForTest() {
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
