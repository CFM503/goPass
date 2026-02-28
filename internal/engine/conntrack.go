package engine

import (
	"fmt"
	"net"
	"sync"
	"time"
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
	CreatedAt    time.Time
}

// ConnTracker 跟踪所有被透明劫持的连接源→目标
type ConnTracker struct {
	mu      sync.RWMutex
	entries map[ConnKey]ConnTarget
	stopCh  chan struct{}
	// [v1.2.6 Config] 抽取魔法清理调度参数
	gcInterval int
	ttl        int
}

func NewConnTracker(gcInterval, ttl int) *ConnTracker {
	if gcInterval <= 0 {
		gcInterval = 30
	}
	if ttl <= 0 {
		ttl = 60
	}
	ct := &ConnTracker{
		entries:    make(map[ConnKey]ConnTarget),
		stopCh:     make(chan struct{}),
		gcInterval: gcInterval,
		ttl:        ttl,
	}
	go ct.startGC()
	return ct
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
		CreatedAt:    time.Now(),
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

// startGC 定期清理超时的孤儿连接记录 (防御内存泄漏)
func (ct *ConnTracker) startGC() {
	ticker := time.NewTicker(time.Duration(ct.gcInterval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ct.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			ct.mu.Lock()
			for k, v := range ct.entries {
				// [v1.2.6 Config] 如果记录在 ttl 秒内没被 TProxy 接管使用(Delete掉)，就认为是死连接，将其清理
				if now.Sub(v.CreatedAt) > time.Duration(ct.ttl)*time.Second {
					delete(ct.entries, k)
				}
			}
			ct.mu.Unlock()
		}
	}
}

func (ct *ConnTracker) Close() {
	close(ct.stopCh)
}

func (ct *ConnTarget) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d", ct.OrigSrcIP.String(), ct.OrigSrcPort, ct.OrigDstIP.String(), ct.OrigDstPort)
}
