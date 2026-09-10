package engine

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type ConnKey struct { SrcIP string; SrcPort uint16 }
type ConnTarget struct { OrigSrcIP net.IP; OrigSrcPort uint16; OrigDstIP net.IP; OrigDstPort uint16; OrigIfIdx uint32; OrigSubIfIdx uint32; CreatedAt time.Time }
type ConnTracker struct { mu sync.RWMutex; entries map[ConnKey]ConnTarget; stopCh chan struct{}; closeOnce sync.Once; gcInterval int; ttl int }

func NewConnTracker(gcInterval, ttl int)*ConnTracker{if gcInterval<=0{gcInterval=15};if ttl<=0{ttl=30};ct:=&ConnTracker{entries:make(map[ConnKey]ConnTarget),stopCh:make(chan struct{}),gcInterval:gcInterval,ttl:ttl};go ct.startGC();return ct}
func(ct *ConnTracker)Set(mappedIP string,mappedPort uint16,origSrcIP net.IP,origSrcPort uint16,origDstIP net.IP,origDstPort uint16,origIfIdx,origSubIfIdx uint32){ct.mu.Lock();ct.entries[ConnKey{mappedIP,mappedPort}]=ConnTarget{OrigSrcIP:append(net.IP(nil),origSrcIP...),OrigSrcPort:origSrcPort,OrigDstIP:append(net.IP(nil),origDstIP...),OrigDstPort:origDstPort,OrigIfIdx:origIfIdx,OrigSubIfIdx:origSubIfIdx,CreatedAt:time.Now()};ct.mu.Unlock()}
func(ct *ConnTracker)Get(srcIP string,srcPort uint16)(ConnTarget,bool){ct.mu.RLock();v,ok:=ct.entries[ConnKey{srcIP,srcPort}];ct.mu.RUnlock();return v,ok}
func(ct *ConnTracker)Delete(srcIP string,srcPort uint16){ct.mu.Lock();delete(ct.entries,ConnKey{srcIP,srcPort});ct.mu.Unlock()}
func(ct *ConnTracker)startGC(){ticker:=time.NewTicker(time.Duration(ct.gcInterval)*time.Second);defer ticker.Stop();for{select{case<-ct.stopCh:return;case<-ticker.C:now:=time.Now();ct.mu.Lock();for k,v:=range ct.entries{if now.Sub(v.CreatedAt)>time.Duration(ct.ttl)*time.Second{delete(ct.entries,k)}};ct.mu.Unlock()}}}
func(ct *ConnTracker)Close(){ct.closeOnce.Do(func(){close(ct.stopCh)})}
func(ct *ConnTarget)String()string{return fmt.Sprintf("%s:%d -> %s:%d",ct.OrigSrcIP.String(),ct.OrigSrcPort,ct.OrigDstIP.String(),ct.OrigDstPort)}
