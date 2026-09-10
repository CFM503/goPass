package engine

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CFM503/goPass/internal/config"
)

const defaultRelayBufferSize = 256 * 1024

var relayBufferPool = sync.Pool{New: func() any { return make([]byte, defaultRelayBufferSize) }}

func getRelayBuffer(size int) []byte {
	size = config.ClampBufferSize(size)
	if size <= defaultRelayBufferSize { return relayBufferPool.Get().([]byte)[:size] }
	return make([]byte, size)
}
func putRelayBuffer(buf []byte) { if cap(buf) == defaultRelayBufferSize { relayBufferPool.Put(buf[:defaultRelayBufferSize]) } }
func originalTarget(ip net.IP, port uint16) (string,error) { if ip==nil||ip.IsUnspecified(){return "",fmt.Errorf("invalid original destination IP")};if port==0{return "",fmt.Errorf("invalid original destination port")};return net.JoinHostPort(ip.String(),strconv.Itoa(int(port))),nil }

type TProxy struct{listener net.Listener;tracker *ConnTracker;upstream *UpstreamDialer;bufferSize int;tcpNoDelay bool;tcpKeepAlive bool;keepAlivePeriod int;tcpLinger int;perfMu sync.RWMutex;stats *Stats}
func NewTProxy(tracker *ConnTracker,proxyType,proxyAddr string,stats *Stats,perf config.PerformanceConfig,tproxyPort int)(*TProxy,error){ln,err:=net.Listen("tcp",fmt.Sprintf("0.0.0.0:%d",tproxyPort));if err!=nil{return nil,fmt.Errorf("TProxy listen failed: %w",err)};return &TProxy{listener:ln,tracker:tracker,upstream:NewUpstreamDialer(proxyType,proxyAddr),bufferSize:config.ClampBufferSize(perf.BufferSize),tcpNoDelay:perf.TCPNoDelay,tcpKeepAlive:perf.TCPKeepAlive,keepAlivePeriod:perf.KeepAlivePeriod,tcpLinger:perf.TCPLinger,stats:stats},nil}
func(tp *TProxy)UpdatePerformance(perf config.PerformanceConfig){tp.perfMu.Lock();tp.bufferSize=config.ClampBufferSize(perf.BufferSize);tp.tcpNoDelay=perf.TCPNoDelay;tp.tcpKeepAlive=perf.TCPKeepAlive;tp.keepAlivePeriod=perf.KeepAlivePeriod;tp.tcpLinger=perf.TCPLinger;tp.perfMu.Unlock()}
func(tp *TProxy)UpdateUpstream(pType,pAddr string){tp.upstream.Update(pType,pAddr);log.Printf("[TProxy] upstream proxy switched to %s -> %s",pType,pAddr)}
func(tp *TProxy)Accept(){var tempDelay time.Duration;for{conn,err:=tp.listener.Accept();if err!=nil{if ne,ok:=err.(net.Error);ok&&ne.Temporary(){if tempDelay==0{tempDelay=5*time.Millisecond}else{tempDelay*=2};if tempDelay>time.Second{tempDelay=time.Second};time.Sleep(tempDelay);continue};return};tempDelay=0;go tp.handleConn(conn)}}
func(tp *TProxy)handleConn(conn net.Conn){defer conn.Close();tp.perfMu.RLock();bufSize:=tp.bufferSize;noDelay:=tp.tcpNoDelay;keepAlive:=tp.tcpKeepAlive;keepAlivePeriod:=tp.keepAlivePeriod;tcpLinger:=tp.tcpLinger;tp.perfMu.RUnlock();tcpAddr,ok:=conn.RemoteAddr().(*net.TCPAddr);if !ok{return};srcIP,srcPort:=tcpAddr.IP.String(),uint16(tcpAddr.Port);target,found:=tp.tracker.Get(srcIP,srcPort);if !found{return};defer tp.tracker.Delete(srcIP,srcPort);targetAddr,err:=originalTarget(target.OrigDstIP,target.OrigDstPort);if err!=nil{return};remote,err:=tp.upstream.Dial("tcp",targetAddr);if err!=nil{log.Printf("[TProxy] upstream connect failed target=%s: %v",targetAddr,err);return};defer remote.Close();tune:=func(c net.Conn){if tc,ok:=c.(*net.TCPConn);ok{_=tc.SetNoDelay(noDelay);_=tc.SetKeepAlive(keepAlive);if keepAlivePeriod>0{_=tc.SetKeepAlivePeriod(time.Duration(keepAlivePeriod)*time.Second)};if tcpLinger>=0{_=tc.SetLinger(tcpLinger)}}};tune(conn);tune(remote);if tp.stats!=nil{id:=fmt.Sprintf("%s:%d",srcIP,srcPort);tp.stats.AddActiveConn(map[string]interface{}{"id":id,"target":targetAddr});defer tp.stats.RemoveActiveConn(id)};var wg sync.WaitGroup;wg.Add(2);result:=make(chan relayResult,2);go func(){defer wg.Done();result<-tp.relay(remote,conn,false,bufSize)}();go func(){defer wg.Done();result<-tp.relay(conn,remote,true,bufSize)}();first:=<-result;if first.err!=nil{_=conn.Close();_=remote.Close()};second:=<-result;if first.err==nil&&second.err!=nil{_=conn.Close();_=remote.Close()};wg.Wait()}
type relayResult struct{n int64;err error}
func(tp *TProxy)relay(src,dst net.Conn,tx bool,size int)relayResult{buf:=getRelayBuffer(size);defer putRelayBuffer(buf);n,err:=io.CopyBuffer(writerConn{Conn:dst,stats:tp.stats,tx:tx},src,buf);if err==nil||err==io.EOF{if tc,ok:=dst.(*net.TCPConn);ok{_=tc.CloseWrite()}};return relayResult{n:n,err:err}}
type writerConn struct{net.Conn;stats *Stats;tx bool}
func(w writerConn)Write(p []byte)(int,error){n,err:=w.Conn.Write(p);if n>0&&w.stats!=nil{if w.tx{atomic.AddInt64(&w.stats.TxBytes,int64(n))}else{atomic.AddInt64(&w.stats.RxBytes,int64(n))}};return n,err}
func(tp *TProxy)Close()error{return tp.listener.Close()}
