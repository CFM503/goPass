package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
)

func main() {
	listen := "127.0.0.1:19080"
	if len(os.Args) > 1 {
		listen = os.Args[1]
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("SOCKS5 test proxy listening on %s", listen)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(c)
	}
}

func handle(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 262144)
	if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 5 {
		return
	}
	nmethods := int(buf[1])
	if nmethods > len(buf)-2 {
		return
	}
	if _, err := io.ReadFull(c, buf[:nmethods]); err != nil {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}

	if _, err := io.ReadFull(c, buf[:4]); err != nil || buf[0] != 5 || buf[1] != 1 {
		return
	}
	var host string
	switch buf[3] {
	case 1:
		if _, err := io.ReadFull(c, buf[:6]); err != nil {
			return
		}
		host = net.IPv4(buf[0], buf[1], buf[2], buf[3]).String()
		port := binary.BigEndian.Uint16(buf[4:6])
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	case 3:
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return
		}
		l := int(buf[0])
		if l > len(buf)-3 {
			return
		}
		if _, err := io.ReadFull(c, buf[:l+2]); err != nil {
			return
		}
		host = string(buf[:l])
		port := binary.BigEndian.Uint16(buf[l : l+2])
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	case 4:
		if _, err := io.ReadFull(c, buf[:18]); err != nil {
			return
		}
		if len(buf) < 18 {
			return
		}
		host = net.JoinHostPort(net.IP(buf[:16]).String(), strconv.Itoa(int(binary.BigEndian.Uint16(buf[16:18]))))
	default:
		return
	}

	remote, err := net.Dial("tcp", host)
	if err != nil {
		_ = writeReply(c, 5, 1)
		return
	}
	defer remote.Close()
	if err := writeReply(c, 5, 0); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.CopyBuffer(remote, c, buf) }()
	go func() { defer wg.Done(); _, _ = io.CopyBuffer(c, remote, buf) }()
	wg.Wait()
}

func writeReply(c net.Conn, ver, rep byte) error {
	return writeAll(c, []byte{ver, rep, 0, 1, 0, 0, 0, 0, 0, 0})
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

var _ = fmt.Sprintf
