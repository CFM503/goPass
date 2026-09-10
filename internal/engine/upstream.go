package engine

import (
	"net"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

const upstreamConnectTimeout = 10 * time.Second

type UpstreamDialer struct {
	mu        sync.RWMutex
	pType     string
	pAddr     string
	cached    proxy.Dialer
	cachedKey string
}

func NewUpstreamDialer(pType, pAddr string) *UpstreamDialer { return &UpstreamDialer{pType:pType,pAddr:pAddr} }
func (u *UpstreamDialer) Update(pType,pAddr string){u.mu.Lock();u.pType=pType;u.pAddr=pAddr;u.cached=nil;u.cachedKey="";u.mu.Unlock()}
func (u *UpstreamDialer) Current()(string,string){u.mu.RLock();defer u.mu.RUnlock();return u.pType,u.pAddr}
func (u *UpstreamDialer) SetDialer(d proxy.Dialer){u.mu.Lock();u.cached=d;u.cachedKey="custom";u.mu.Unlock()}

func(u *UpstreamDialer)Dialer()(proxy.Dialer,error){u.mu.RLock();if u.cachedKey=="custom"&&u.cached!=nil{d:=u.cached;u.mu.RUnlock();return d,nil};key:=u.pType+"://"+u.pAddr;if u.cached!=nil&&u.cachedKey==key{d:=u.cached;u.mu.RUnlock();return d,nil};pType,pAddr:=u.pType,u.pAddr;u.mu.RUnlock();u.mu.Lock();defer u.mu.Unlock();if u.cachedKey=="custom"&&u.cached!=nil{return u.cached,nil};if u.cached!=nil&&u.cachedKey==key{return u.cached,nil};forward:=&net.Dialer{Timeout:upstreamConnectTimeout,KeepAlive:30*time.Second};var d proxy.Dialer;var err error;if pType=="http"{d,err=NewHTTPProxy(pAddr,"","",forward)}else{d,err=proxy.SOCKS5("tcp",pAddr,nil,forward)};if err==nil{u.cached,u.cachedKey=d,key};return d,err}
func(u *UpstreamDialer)Dial(network,addr string)(net.Conn,error){d,err:=u.Dialer();if err!=nil{return nil,err};return d.Dial(network,addr)}
