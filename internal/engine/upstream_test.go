package engine

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// TestZeroDowntimeUpstreamSwitch 验证旧连接在线路热切时不中断，新连接走新线路
func TestZeroDowntimeUpstreamSwitch(t *testing.T) {
	// 启动模拟上游 A (Echo server A)
	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lnA.Close()
	addrA := lnA.Addr().String()

	go func() {
		for {
			c, err := lnA.Accept()
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
					// Echo with tag [A]
					resp := fmt.Sprintf("[A]%s", string(buf[:n]))
					if _, errWrite := conn.Write([]byte(resp)); errWrite != nil {
						return
					}
				}
			}(c)
		}
	}()

	// 启动模拟上游 B (Echo server B)
	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lnB.Close()
	addrB := lnB.Addr().String()

	go func() {
		for {
			c, err := lnB.Accept()
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
					// Echo with tag [B]
					resp := fmt.Sprintf("[B]%s", string(buf[:n]))
					if _, errWrite := conn.Write([]byte(resp)); errWrite != nil {
						return
					}
				}
			}(c)
		}
	}()

	// 创建 UpstreamDialer，初始指向上游 A
	u := NewUpstreamDialer("direct", addrA)

	// 建立旧连接 (直接拨号模拟底层长连接，如视频流)
	oldConn, err := net.DialTimeout("tcp", addrA, 2*time.Second)
	if err != nil {
		t.Fatalf("dial A failed: %v", err)
	}
	defer oldConn.Close()

	// 验证旧连接连通性
	_, _ = oldConn.Write([]byte("ping1"))
	buf := make([]byte, 64)
	n, _ := oldConn.Read(buf)
	if string(buf[:n]) != "[A]ping1" {
		t.Fatalf("expected [A]ping1, got %s", string(buf[:n]))
	}

	// 触发热切换：UpstreamDialer 切换为上游 B
	u.Update("direct", addrB)
	_, currAddr := u.Current()
	if currAddr != addrB {
		t.Fatalf("expected current addr %s, got %s", addrB, currAddr)
	}

	// 关键断言 1: 旧长连接 (如同正在播放的 YouTube 视频) 绝不能断，仍然可以继续正常双向收发！
	_, err = oldConn.Write([]byte("ping2"))
	if err != nil {
		t.Fatalf("old connection should remain alive: %v", err)
	}
	n, err = oldConn.Read(buf)
	if err != nil || string(buf[:n]) != "[A]ping2" {
		t.Fatalf("old connection should still read from A, got: %s, err: %v", string(buf[:n]), err)
	}

	// 关键断言 2: 新到达的请求连接将立即连到新上游 B
	newConn, err := net.DialTimeout("tcp", addrB, 2*time.Second)
	if err != nil {
		t.Fatalf("dial B failed: %v", err)
	}
	defer newConn.Close()

	_, _ = newConn.Write([]byte("pingNew"))
	n, _ = io.ReadAtLeast(newConn, buf, 1)
	if string(buf[:n]) != "[B]pingNew" {
		t.Fatalf("new connection should connect to B, got %s", string(buf[:n]))
	}
}
