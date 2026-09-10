package engine

import (
	"net"
	"sync/atomic"
	"testing"
)

func runProxyBufferBenchmark(b *testing.B, bufSize int) {
	b.ReportAllocs()
	b.SetBytes(int64(bufSize))
	srcR, srcW := net.Pipe()
	dstR, dstW := net.Pipe()
	done := make(chan struct{})
	go func() {
		sink := make([]byte, 1024*1024)
		for { if _, err := dstR.Read(sink); err != nil { return } }
	}()
	data := make([]byte, bufSize)
	go func() { defer close(done); for i:=0;i<b.N;i++ { if _,err:=srcW.Write(data);err!=nil{return} };_=srcW.Close() }()
	b.ResetTimer()
	buf:=getRelayBuffer(bufSize);defer putRelayBuffer(buf)
	var transferred int64
	for { n,err:=srcR.Read(buf);if n>0{atomic.AddInt64(&transferred,int64(n));if _,werr:=dstW.Write(buf[:n]);werr!=nil{break}};if err!=nil{break} }
	b.StopTimer();_=srcR.Close();_=dstW.Close();_=dstR.Close();<-done
}

func BenchmarkProxyBuffer32K(b *testing.B){runProxyBufferBenchmark(b,32*1024)}
func BenchmarkProxyBuffer64K(b *testing.B){runProxyBufferBenchmark(b,64*1024)}
func BenchmarkProxyBuffer256K(b *testing.B){runProxyBufferBenchmark(b,256*1024)}
func BenchmarkProxyBuffer512K(b *testing.B){runProxyBufferBenchmark(b,512*1024)}
func BenchmarkProxyBuffer1M(b *testing.B){runProxyBufferBenchmark(b,1024*1024)}
