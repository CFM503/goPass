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
	username  string
	password  string
	cached    proxy.Dialer
	cachedKey string
}

func NewUpstreamDialer(pType, pAddr, username, password string) *UpstreamDialer { return &UpstreamDialer{pType:pType,pAddr:pAddr,username:username,password:password} }
func (u *UpstreamDialer) Update(pType,pAddr,username,password string){u.mu.Lock();u.pType=pType;u.pAddr=pAddr;u.username=username;u.password=password;u.cached=nil;u.cachedKey="";u.mu.Unlock()}
func (u *UpstreamDialer) Current()(string,string){u.mu.RLock();defer u.mu.RUnlock();return u.pType,u.pAddr}
func (u *UpstreamDialer) SetDialer(d proxy.Dialer){u.mu.Lock();u.cached=d;u.cachedKey="custom";u.mu.Unlock()}

// upstreamCacheKey 生成 dialer 缓存键。凭据必须参与：只按 "type://addr" 缓存的话，
// 改了密码仍会复用旧 dialer，新凭据永远不生效——表现出来就是"配了认证却没用"。
// 用 NUL 分隔而非直接拼接，否则地址与凭据会互相冒充（"h:1"+"u" 与 "h:1u"+"" 同键）。
func upstreamCacheKey(pType, pAddr, username, password string) string {
	return pType + "://" + pAddr + "\x00" + username + "\x00" + password
}

func(u *UpstreamDialer)Dialer()(proxy.Dialer,error){u.mu.RLock();if u.cachedKey=="custom"&&u.cached!=nil{d:=u.cached;u.mu.RUnlock();return d,nil};key:=upstreamCacheKey(u.pType,u.pAddr,u.username,u.password);if u.cached!=nil&&u.cachedKey==key{d:=u.cached;u.mu.RUnlock();return d,nil};pType,pAddr,username,password:=u.pType,u.pAddr,u.username,u.password;u.mu.RUnlock();u.mu.Lock();defer u.mu.Unlock();if u.cachedKey=="custom"&&u.cached!=nil{return u.cached,nil};if u.cached!=nil&&u.cachedKey==key{return u.cached,nil};forward:=&net.Dialer{Timeout:upstreamConnectTimeout,KeepAlive:30*time.Second};var d proxy.Dialer;var err error;if pType=="http"{d,err=NewHTTPProxy(pAddr,username,password,forward)}else if username!=""{d,err=proxy.SOCKS5("tcp",pAddr,&proxy.Auth{User:username,Password:password},forward)}else{d,err=proxy.SOCKS5("tcp",pAddr,nil,forward)};if err==nil{u.cached,u.cachedKey=d,key};return d,err}
func(u *UpstreamDialer)Dial(network,addr string)(net.Conn,error){d,err:=u.Dialer();if err!=nil{return nil,err};return d.Dial(network,addr)}
