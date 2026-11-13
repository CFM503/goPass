package engine

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// Dialer 抽象出站拨号器，签名与原 x/net/proxy.Dialer 一致。
type Dialer interface {
	Dial(network, addr string) (net.Conn, error)
}

// SOCKS5Dialer 实现基于 Go 标准库的 RFC 1928 / RFC 1929 SOCKS5 客户端。
type SOCKS5Dialer struct {
	network   string
	proxyAddr string
	username  string
	password  string
	forward   Dialer
}

func NewSOCKS5(network, proxyAddr, username, password string, forward Dialer) (Dialer, error) {
	if len(username) > 255 || len(password) > 255 {
		return nil, errors.New("socks5: username/password exceeds 255 bytes")
	}
	if forward == nil {
		forward = &net.Dialer{Timeout: upstreamConnectTimeout, KeepAlive: 30 * time.Second}
	}
	return &SOCKS5Dialer{
		network:   network,
		proxyAddr: proxyAddr,
		username:  username,
		password:  password,
		forward:   forward,
	}, nil
}

func (d *SOCKS5Dialer) Dial(network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("socks5: unsupported network %q", network)
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("socks5: invalid target %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("socks5: invalid port %q", portStr)
	}

	c, err := d.forward.Dial(d.network, d.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connect SOCKS5 proxy %s: %w", d.proxyAddr, err)
	}
	fail := func(e error) (net.Conn, error) {
		_ = c.Close()
		return nil, e
	}
	_ = c.SetDeadline(time.Now().Add(upstreamConnectTimeout))

	// 1. 方法协商（RFC 1928 Section 3）：仅在配置了用户名时通告 0x02（用户名/密码）。
	var greeting []byte
	if d.username != "" {
		greeting = []byte{0x05, 0x02, 0x00, 0x02}
	} else {
		greeting = []byte{0x05, 0x01, 0x00}
	}
	if _, err := c.Write(greeting); err != nil {
		return fail(fmt.Errorf("socks5 greeting write: %w", err))
	}

	var methodResp [2]byte
	if _, err := io.ReadFull(c, methodResp[:]); err != nil {
		return fail(fmt.Errorf("socks5 greeting read: %w", err))
	}
	if methodResp[0] != 0x05 {
		return fail(fmt.Errorf("socks5 unexpected version %d", methodResp[0]))
	}
	switch methodResp[1] {
	case 0x00:
	case 0x02:
		if d.username == "" {
			return fail(errors.New("socks5 server requested auth without configured username"))
		}
		authReq := make([]byte, 0, 3+len(d.username)+len(d.password))
		authReq = append(authReq, 0x01, byte(len(d.username)))
		authReq = append(authReq, d.username...)
		authReq = append(authReq, byte(len(d.password)))
		authReq = append(authReq, d.password...)
		if _, err := c.Write(authReq); err != nil {
			return fail(fmt.Errorf("socks5 auth write: %w", err))
		}
		var authResp [2]byte
		if _, err := io.ReadFull(c, authResp[:]); err != nil {
			return fail(fmt.Errorf("socks5 auth read: %w", err))
		}
		if authResp[0] != 0x01 || authResp[1] != 0x00 {
			return fail(fmt.Errorf("socks5 authentication failed (status=%d)", authResp[1]))
		}
	case 0xff:
		return fail(errors.New("socks5 no acceptable authentication method"))
	default:
		return fail(fmt.Errorf("socks5 unsupported authentication method %d", methodResp[1]))
	}

	// 2. CONNECT 请求（RFC 1928 Section 4）
	req := make([]byte, 0, 7+len(host))
	req = append(req, 0x05, 0x01, 0x00)
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return fail(fmt.Errorf("socks5 invalid domain length %d", len(host)))
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		return fail(fmt.Errorf("socks5 connect write: %w", err))
	}

	// 3. 读取服务端回复并消费绑定的 BND.ADDR + BND.PORT
	var replyHead [4]byte
	if _, err := io.ReadFull(c, replyHead[:]); err != nil {
		return fail(fmt.Errorf("socks5 connect reply read: %w", err))
	}
	if replyHead[0] != 0x05 {
		return fail(fmt.Errorf("socks5 unexpected reply version %d", replyHead[0]))
	}
	if replyHead[1] != 0x00 {
		return fail(fmt.Errorf("socks5 connect rejected (reply=%d)", replyHead[1]))
	}
	var discard [256]byte
	switch replyHead[3] {
	case 0x01:
		if _, err := io.ReadFull(c, discard[:4+2]); err != nil {
			return fail(fmt.Errorf("socks5 read IPv4 bind addr: %w", err))
		}
	case 0x04:
		if _, err := io.ReadFull(c, discard[:16+2]); err != nil {
			return fail(fmt.Errorf("socks5 read IPv6 bind addr: %w", err))
		}
	case 0x03:
		var dlen [1]byte
		if _, err := io.ReadFull(c, dlen[:]); err != nil {
			return fail(fmt.Errorf("socks5 read domain len: %w", err))
		}
		if _, err := io.ReadFull(c, discard[:int(dlen[0])+2]); err != nil {
			return fail(fmt.Errorf("socks5 read domain bind addr: %w", err))
		}
	default:
		return fail(fmt.Errorf("socks5 invalid reply address type %d", replyHead[3]))
	}

	_ = c.SetDeadline(time.Time{})
	return c, nil
}
