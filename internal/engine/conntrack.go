package engine

import (
	"fmt"
	"net"
	"sync"
)

// ConnKey 唯一标识一条被劫持的连接（源 IP + 源端口）
type ConnKey struct {
	SrcIP   string
	SrcPort uint16
}

// ConnTarget 记录该连接的全套真实网络四元组，以及底层接口索引
type ConnTarget struct {
	OrigSrcIP    net.IP
	OrigSrcPort  uint16
	OrigDstIP    net.IP
	OrigDstPort  uint16
	OrigIfIdx    uint32
	OrigSubIfIdx uint32
	ProcessName  string
}

// ConnTracker 跟踪所有被透明劫持的连接源→目标
type ConnTracker struct {
	mu      sync.RWMutex
	entries map[ConnKey]ConnTarget
}

func NewConnTracker() *ConnTracker {
	return &ConnTracker{
		entries: make(map[ConnKey]ConnTarget),
	}
}

func (ct *ConnTracker) Set(mappedIP string, mappedPort uint16, origSrcIP net.IP, origSrcPort uint16, origDstIP net.IP, origDstPort uint16, origIfIdx uint32, origSubIfIdx uint32, processName string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.entries[ConnKey{mappedIP, mappedPort}] = ConnTarget{
		OrigSrcIP:    origSrcIP,
		OrigSrcPort:  origSrcPort,
		OrigDstIP:    origDstIP,
		OrigDstPort:  origDstPort,
		OrigIfIdx:    origIfIdx,
		OrigSubIfIdx: origSubIfIdx,
		ProcessName:  processName,
	}
}

func (ct *ConnTracker) Get(srcIP string, srcPort uint16) (ConnTarget, bool) {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	v, ok := ct.entries[ConnKey{srcIP, srcPort}]
	return v, ok
}

func (ct *ConnTracker) Delete(srcIP string, srcPort uint16) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	delete(ct.entries, ConnKey{srcIP, srcPort})
}

func (ct *ConnTarget) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d", ct.OrigSrcIP.String(), ct.OrigSrcPort, ct.OrigDstIP.String(), ct.OrigDstPort)
}
