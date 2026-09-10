//go:build windows

package process

import "sync"

var udpRefreshFallbackMu sync.Mutex

// LookupUDPWithRefresh closes the startup race between a new UDP socket and the
// 250ms endpoint snapshot. The normal path remains an O(1) map lookup; only a
// cache miss performs one serialized Windows table refresh.
func (r *Resolver) LookupUDPWithRefresh(flow UDPFlow) (UDPEntry, bool) {
	if e, ok := r.LookupUDP(flow); ok {
		return e, true
	}
	udpRefreshFallbackMu.Lock()
	defer udpRefreshFallbackMu.Unlock()
	if e, ok := r.LookupUDP(flow); ok {
		return e, true
	}
	_ = r.Refresh()
	return r.LookupUDP(flow)
}
