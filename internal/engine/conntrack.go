package engine

import (
	"fmt"
	"sync"
	"time"
)

// ConnKey 唯一标识一条被劫持的连接（源 IP + 源端口）
type ConnKey struct {
	SrcIP   [4]byte
	SrcPort uint16
}

// ConnTarget 记录该连接的全套真实网络四元组，以及底层接口索引
type ConnTarget struct {
	OrigSrcIP    [4]byte
	OrigSrcPort  uint16
	OrigDstIP    [4]byte
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

// parseIP4 将 "127.0.0.1" 解析为 [4]byte，零分配
func parseIP4(s string) [4]byte {
	var b [4]byte
	var n, val int
	for i := 0; i < 4 && n < len(s); i++ {
		val = 0
		for n < len(s) && s[n] >= '0' && s[n] <= '9' {
			val = val*10 + int(s[n]-'0')
			n++
		}
		b[i] = byte(val)
		n++
	}
	return b
}

// ip4ToBytes 将 net.IP 转为 [4]byte，零分配
func ip4ToBytes(ip []byte) [4]byte {
	var b [4]byte
	if len(ip) >= 4 {
		copy(b[:], ip[len(ip)-4:])
	}
	return b
}

func (ct *ConnTracker) Set(mappedIP [4]byte, mappedPort uint16, origSrcIP [4]byte, origSrcPort uint16, origDstIP [4]byte, origDstPort uint16, origIfIdx uint32, origSubIfIdx uint32, processName string) {
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

func (ct *ConnTracker) Get(srcIP [4]byte, srcPort uint16) (ConnTarget, bool) {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	v, ok := ct.entries[ConnKey{srcIP, srcPort}]
	return v, ok
}

func (ct *ConnTracker) Delete(srcIP [4]byte, srcPort uint16) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	delete(ct.entries, ConnKey{srcIP, srcPort})
}

// startGC 定期清理超时的孤儿连接记录
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
	return fmt.Sprintf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
		ct.OrigSrcIP[0], ct.OrigSrcIP[1], ct.OrigSrcIP[2], ct.OrigSrcIP[3], ct.OrigSrcPort,
		ct.OrigDstIP[0], ct.OrigDstIP[1], ct.OrigDstIP[2], ct.OrigDstIP[3], ct.OrigDstPort)
}
