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

func TestConnTrackerActiveEntrySurvivesTTL(t *testing.T) {
	ct := NewConnTracker(1, 1, 7893)
	defer ct.Close()

	p, ok := ct.Set(net.ParseIP("192.168.1.10"), 50001, net.ParseIP("1.1.1.1"), 443, 1, 0)
	if !ok { t.Fatal("mapped port allocation failed") }
	ct.Activate("127.0.0.1", p)

	// CreatedAt is intentionally old enough to be eligible for GC.
	ct.mu.Lock()
	key := ConnKey{"127.0.0.1", p}
	entry := ct.entries[key]
	entry.CreatedAt = time.Now().Add(-2 * time.Second)
	ct.entries[key] = entry
	ct.mu.Unlock()

	ct.startGCOnceForTest()
	if _, ok := ct.Get("127.0.0.1", p); !ok {
		t.Fatal("active conntrack entry was incorrectly garbage-collected")
	}
}

func (ct *ConnTracker) startGCOnceForTest() {
	now := time.Now()
	ct.mu.Lock()
	for k, v := range ct.entries {
		if _, active := ct.active[k]; active { continue }
		if now.Sub(v.CreatedAt) > time.Duration(ct.ttl)*time.Second { delete(ct.entries, k) }
	}
	ct.mu.Unlock()
}
