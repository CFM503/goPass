package engine

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// startMockEchoServer 启动本地回显服务
func startMockEchoServer(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 1024)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					resp := fmt.Sprintf("[Echo]%s", string(buf[:n]))
					if _, errWrite := conn.Write([]byte(resp)); errWrite != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln
}

// startMockSOCKS5Server 启动一个完全本地的轻量级 SOCKS5 Mock 代理服务器
func startMockSOCKS5Server(t *testing.T, tag string) (net.Listener, *int32) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var connCount int32

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&connCount, 1)
			go handleMockSOCKS5(c, tag)
		}
	}()
	return ln, &connCount
}

func handleMockSOCKS5(c net.Conn, tag string) {
	defer c.Close()
	// 1. SOCKS5 协商握手
	header := make([]byte, 2)
	if _, err := io.ReadFull(c, header); err != nil || header[0] != 0x05 {
		return
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	// 回复无需认证: [0x05, 0x00]
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. CONNECT 请求: [0x05, CMD=0x01, RSV=0x00, ATYP, ADDR, PORT]
	reqHead := make([]byte, 4)
	if _, err := io.ReadFull(c, reqHead); err != nil || reqHead[0] != 0x05 || reqHead[1] != 0x01 {
		return
	}
	var destAddr string
	switch reqHead[3] {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(c, ip); err != nil {
			return
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(c, portBytes); err != nil {
			return
		}
		port := int(portBytes[0])<<8 | int(portBytes[1])
		destAddr = net.JoinHostPort(net.IP(ip).String(), strconv.Itoa(port))
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(c, lenBuf); err != nil {
			return
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(c, domain); err != nil {
			return
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(c, portBytes); err != nil {
			return
		}
		port := int(portBytes[0])<<8 | int(portBytes[1])
		destAddr = net.JoinHostPort(string(domain), strconv.Itoa(port))
	default:
		return
	}

	targetConn, err := net.DialTimeout("tcp", destAddr, 2*time.Second)
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer targetConn.Close()

	// 回复成功: [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// 双向转发
	errCh := make(chan error, 2)
	go func() {
		_, errCopy := io.Copy(targetConn, c)
		errCh <- errCopy
	}()
	go func() {
		_, errCopy := io.Copy(c, targetConn)
		errCh <- errCopy
	}()
	<-errCh
}

// TestZeroDowntimeUpstreamSwitch 验证旧连接在线路热切时不中断，新连接走新线路
func TestZeroDowntimeUpstreamSwitch(t *testing.T) {
	echoLn := startMockEchoServer(t)
	defer echoLn.Close()
	echoAddr := echoLn.Addr().String()

	lnA, countA := startMockSOCKS5Server(t, "A")
	defer lnA.Close()
	addrA := lnA.Addr().String()

	lnB, countB := startMockSOCKS5Server(t, "B")
	defer lnB.Close()
	addrB := lnB.Addr().String()

	// 1. 初始化 UpstreamDialer 指向 SOCKS5 代理 A
	u := NewUpstreamDialer("socks5", addrA)

	// 2. 通过 UpstreamDialer 建立长连接 Connection 1 到目标回显服务器
	conn1, err := u.Dial("tcp", echoAddr)
	if err != nil {
		t.Fatalf("u.Dial via A failed: %v", err)
	}
	defer conn1.Close()

	// 验证 Connection 1 确实经过代理 A
	if atomic.LoadInt32(countA) != 1 {
		t.Fatalf("expected 1 connection on A, got %d", atomic.LoadInt32(countA))
	}

	// 验证 Connection 1 双向收发正常
	if _, err := conn1.Write([]byte("ping1")); err != nil {
		t.Fatalf("conn1 write failed: %v", err)
	}
	buf := make([]byte, 64)
	n, err := conn1.Read(buf)
	if err != nil || string(buf[:n]) != "[Echo]ping1" {
		t.Fatalf("conn1 expected [Echo]ping1, got %s (err: %v)", string(buf[:n]), err)
	}

	// 3. 执行热切换：UpstreamDialer 热更新为 SOCKS5 代理 B
	u.Update("socks5", addrB)
	_, currAddr := u.Current()
	if currAddr != addrB {
		t.Fatalf("expected current upstream %s, got %s", addrB, currAddr)
	}

	// 4. 【核心断言 1】：旧连接 Connection 1 必须完好无损，继续保持并能双向传输！
	if _, err := conn1.Write([]byte("ping_after_update")); err != nil {
		t.Fatalf("old connection 1 must not be interrupted by Update(): %v", err)
	}
	n, err = conn1.Read(buf)
	if err != nil || string(buf[:n]) != "[Echo]ping_after_update" {
		t.Fatalf("old connection 1 read error: got %s (err: %v)", string(buf[:n]), err)
	}
	// 确认代理 A 仍保持该连接，代理 B 尚未收到新连接
	if atomic.LoadInt32(countB) != 0 {
		t.Fatalf("proxy B should not have connections yet, got %d", atomic.LoadInt32(countB))
	}

	// 5. 【核心断言 2】：新建连接 Connection 2 必须无缝接入新上游代理 B
	conn2, err := u.Dial("tcp", echoAddr)
	if err != nil {
		t.Fatalf("u.Dial via B failed: %v", err)
	}
	defer conn2.Close()

	if atomic.LoadInt32(countB) != 1 {
		t.Fatalf("expected 1 connection on B, got %d", atomic.LoadInt32(countB))
	}

	if _, err := conn2.Write([]byte("ping2")); err != nil {
		t.Fatalf("conn2 write failed: %v", err)
	}
	n, err = conn2.Read(buf)
	if err != nil || string(buf[:n]) != "[Echo]ping2" {
		t.Fatalf("conn2 expected [Echo]ping2, got %s (err: %v)", string(buf[:n]), err)
	}

	// 6. 再次验证旧连接 Connection 1 依然持续工作正常 (多次持续传输)
	if _, err := conn1.Write([]byte("ping_third")); err != nil {
		t.Fatalf("old connection 1 continuous write failed: %v", err)
	}
	n, err = conn1.Read(buf)
	if err != nil || string(buf[:n]) != "[Echo]ping_third" {
		t.Fatalf("old connection 1 continuous read failed: got %s (err: %v)", string(buf[:n]), err)
	}
}
