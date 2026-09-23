package engine

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestRelayCopiesPayloadExactlyOnce(t *testing.T) {
	srcR, srcW := net.Pipe()
	dstR, dstW := net.Pipe()
	defer srcR.Close()
	defer dstR.Close()
	defer dstW.Close()

	payload := bytes.Repeat([]byte("GoPass-relay-"), 4096)
	resultCh := make(chan relayResult, 1)
	go func() { resultCh <- relay(srcR, dstW, 256*1024) }()

	writeDone := make(chan error, 1)
	go func() {
		_, err := srcW.Write(payload)
		_ = srcW.Close()
		writeDone <- err
	}()

	received := make([]byte, len(payload))
	if _, err := readExactly(dstR, received); err != nil { t.Fatal(err) }
	if !bytes.Equal(payload, received) { t.Fatal("relay payload was changed or duplicated") }
	if err := <-writeDone; err != nil { t.Fatal(err) }

	select {
	case result := <-resultCh:
		if result.err != nil { t.Fatalf("relay returned error: %v", result.err) }
	case <-time.After(time.Second):
		t.Fatal("relay did not terminate after source EOF")
	}
}

func TestRelayErrorTerminates(t *testing.T) {
	clientR, clientW := net.Pipe()
	upstreamR, upstreamW := net.Pipe()
	defer clientR.Close()
	defer clientW.Close()
	defer upstreamR.Close()
	defer upstreamW.Close()

	resultCh := make(chan relayResult, 1)
	go func() { resultCh <- relay(clientR, upstreamW, 64*1024) }()
	_ = clientW.Close()
	select {
	case <-resultCh:
	case <-time.After(time.Second):
		t.Fatal("relay remained blocked after source close")
	}
}

func readExactly(conn net.Conn, dst []byte) (int, error) {
	read := 0
	for read < len(dst) {
		n, err := conn.Read(dst[read:])
		read += n
		if err != nil { return read, err }
	}
	return read, nil
}
