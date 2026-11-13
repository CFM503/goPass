package engine

import (
	"io"
	"net"
	"testing"
)

func TestSOCKS5DialerDomainAndBindAddrTypes(t *testing.T) {
	cases := []struct {
		name     string
		target   string
		wantATYP byte
		bindResp []byte
	}{
		{
			name:     "domain target with domain bind addr",
			target:   "example.com:443",
			wantATYP: 0x03,
			bindResp: []byte{0x05, 0x00, 0x00, 0x03, 0x03, 'a', '.', 'b', 0x01, 0xbb},
		},
		{
			name:     "ipv6 target with ipv6 bind addr",
			target:   "[2001:db8::1]:443",
			wantATYP: 0x04,
			bindResp: append([]byte{0x05, 0x00, 0x00, 0x04}, make([]byte, 18)...),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			gotATYP := make(chan byte, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				// 1. greeting: [0x05, 0x01, 0x00]
				var g [3]byte
				if _, err := io.ReadFull(c, g[:]); err != nil {
					return
				}
				_, _ = c.Write([]byte{0x05, 0x00})
				// 2. CONNECT header: [0x05, 0x01, 0x00, atyp]
				var h [4]byte
				if _, err := io.ReadFull(c, h[:]); err != nil {
					return
				}
				gotATYP <- h[3]
				var drain int
				switch h[3] {
				case 0x01:
					drain = 4 + 2
				case 0x04:
					drain = 16 + 2
				case 0x03:
					var l [1]byte
					_, _ = io.ReadFull(c, l[:])
					drain = int(l[0]) + 2
				}
				_, _ = io.ReadFull(c, make([]byte, drain))
				_, _ = c.Write(tc.bindResp)
				_, _ = c.Write([]byte("hello"))
			}()

			d, err := NewSOCKS5("tcp", ln.Addr().String(), "", "", nil)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := d.Dial("tcp", tc.target)
			if err != nil {
				t.Fatalf("Dial(%q): %v", tc.target, err)
			}
			defer conn.Close()

			if atyp := <-gotATYP; atyp != tc.wantATYP {
				t.Fatalf("ATYP=%#x, want %#x", atyp, tc.wantATYP)
			}
			buf := make([]byte, 5)
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Fatalf("read payload after handshake: %v", err)
			}
			if string(buf) != "hello" {
				t.Fatalf("payload=%q, want hello", buf)
			}
		})
	}
}

func TestSOCKS5DialerRejectsServerErrorAndBadNetwork(t *testing.T) {
	d, err := NewSOCKS5("tcp", "127.0.0.1:1", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Dial("udp", "1.1.1.1:53"); err == nil {
		t.Fatal("unsupported network udp must fail")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var g [3]byte
		_, _ = io.ReadFull(c, g[:])
		_, _ = c.Write([]byte{0x05, 0x00})
		var h [10]byte
		_, _ = io.ReadFull(c, h[:])
		_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01}) // connection refused
	}()

	d2, _ := NewSOCKS5("tcp", ln.Addr().String(), "", "", nil)
	if _, err := d2.Dial("tcp", "1.1.1.1:443"); err == nil {
		t.Fatal("rejected SOCKS5 connect must fail")
	}
}
