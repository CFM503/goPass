package engine

// UpstreamDialer 上游代理拨号器缓存（SOCKS5 / HTTP CONNECT），
// 由 TProxy 与 DNSRelay 共享，支持热切换（原子替换缓存 Dialer）。

import (
	"net"
	"sync"

	"golang.org/x/net/proxy"
)

// UpstreamDialer 缓存并复用上游代理 Dialer。
type UpstreamDialer struct {
	mu        sync.RWMutex
	pType     string
	pAddr     string
	cached    proxy.Dialer
	cachedKey string
}

// NewUpstreamDialer 创建上游拨号器。
func NewUpstreamDialer(pType, pAddr string) *UpstreamDialer {
	return &UpstreamDialer{pType: pType, pAddr: pAddr}
}

// Update 热切换上游代理（清空缓存，下次 Dial 重建）。
func (u *UpstreamDialer) Update(pType, pAddr string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.pType = pType
	u.pAddr = pAddr
	u.cached = nil
	u.cachedKey = ""
}

// Current 返回当前上游代理类型与地址。
func (u *UpstreamDialer) Current() (string, string) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.pType, u.pAddr
}

// Dialer 返回（缓存的）proxy.Dialer。
func (u *UpstreamDialer) Dialer() (proxy.Dialer, error) {
	u.mu.RLock()
	key := u.pType + "://" + u.pAddr
	if u.cached != nil && u.cachedKey == key {
		d := u.cached
		u.mu.RUnlock()
		return d, nil
	}
	pType, pAddr := u.pType, u.pAddr
	u.mu.RUnlock()

	u.mu.Lock()
	defer u.mu.Unlock()
	if u.cached != nil && u.cachedKey == key {
		return u.cached, nil
	}

	var d proxy.Dialer
	var err error
	if pType == "http" {
		d, err = NewHTTPProxy(pAddr, "", "", proxy.Direct)
	} else {
		d, err = proxy.SOCKS5("tcp", pAddr, nil, proxy.Direct)
	}
	if err == nil {
		u.cached = d
		u.cachedKey = key
	}
	return d, err
}

// Dial 通过上游代理建立到 addr 的连接。
func (u *UpstreamDialer) Dial(network, addr string) (conn net.Conn, err error) {
	d, err := u.Dialer()
	if err != nil {
		return nil, err
	}
	return d.Dial(network, addr)
}
