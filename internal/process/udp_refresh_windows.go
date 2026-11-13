//go:build windows

package process

// LookupUDPWithRefresh closes the startup race between a new UDP socket and the
// periodic endpoint snapshot. The normal path remains an O(1) map lookup; only a
// cache miss performs one serialized Windows table refresh.
func (r *Resolver) LookupUDPWithRefresh(flow UDPFlow) (UDPEntry, bool) {
	if e, ok := r.LookupUDP(flow); ok {
		return e, true
	}
	r.fallbackMu.Lock()
	defer r.fallbackMu.Unlock()
	if e, ok := r.LookupUDP(flow); ok {
		return e, true
	}
	_ = r.Refresh()
	return r.LookupUDP(flow)
}
