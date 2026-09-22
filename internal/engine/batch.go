package engine

import (
	"encoding/binary"
	"fmt"
	"unsafe"
)

// 批量收发包参数。
//
// batchPackets: 单次收/发的包数上限。WinDivert 的 WINDIVERT_BATCH_MAX 是 255，
// 这里取 16 已经能把"每包两次内核上下文切换"摊薄掉，缓冲区也控制在 1MB 量级。
//
// maxPacketSize: WINDIVERT_MTU_MAX = 40 + 0xFFFF，单包最坏长度。
// 一批全是最长包时收包缓冲区也放得下，不会 ERROR_INSUFFICIENT_BUFFER。
const (
	batchPackets  = 16
	maxPacketSize = 40 + 0xFFFF
	recvBufSize   = batchPackets * maxPacketSize
)

// winDivertAddressSize == sizeof(WINDIVERT_ADDRESS)，WinDivert 2.2 下是 80。
// 批量收发都靠它把"字节数"换算成"包数"，与 C 结构差一个字节都会串位，
// 所以另有单测钉死这个值。
var winDivertAddressSize = int(unsafe.Sizeof(winDivertAddress{}))

// sendQueue 累积一个批次内要回注的包，批末用一次 WinDivertSendEx 发出。
// 容量按"一批最多 recvBufSize 字节"一次性预留，push 只做 memcpy，
// 稳态下整条回注路径零堆分配。
type sendQueue struct {
	buf   []byte
	addrs []winDivertAddress
	lens  []int
}

func newSendQueue() *sendQueue {
	return &sendQueue{
		buf:   make([]byte, 0, recvBufSize),
		addrs: make([]winDivertAddress, 0, batchPackets),
		lens:  make([]int, 0, batchPackets),
	}
}

// push 复制包体与地址。addr 会被解引用拷贝，调用方可复用同一对象。
func (q *sendQueue) push(pkt []byte, addr *winDivertAddress) {
	if q == nil || len(pkt) == 0 {
		return
	}
	q.buf = append(q.buf, pkt...)
	q.addrs = append(q.addrs, *addr)
	q.lens = append(q.lens, len(pkt))
}

// wouldOverflow 判断再入队 n 字节是否会触发扩容（扩容会带来分配）。
func (q *sendQueue) wouldOverflow(n int) bool {
	return cap(q.buf)-len(q.buf) < n
}

func (q *sendQueue) count() int { return len(q.lens) }

func (q *sendQueue) reset() {
	q.buf = q.buf[:0]
	q.addrs = q.addrs[:0]
	q.lens = q.lens[:0]
}

// packetLen 按 IP 头里的长度字段算出单个包的字节数。
// 批量收包把 N 个包无间隙拼进同一块缓冲区，WinDivert 不返回逐包长度，
// 只有靠头字段才能切分，所以这里必须严格校验，越界宁可报错也不能猜。
func packetLen(pkt []byte) (int, error) {
	if len(pkt) < 1 {
		return 0, fmt.Errorf("空包")
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return 0, fmt.Errorf("IPv4 头不完整(%d 字节)", len(pkt))
		}
		n := int(binary.BigEndian.Uint16(pkt[2:4]))
		if n < 20 || n > len(pkt) {
			return 0, fmt.Errorf("IPv4 TotalLength=%d 越界(缓冲区 %d)", n, len(pkt))
		}
		return n, nil
	case 6:
		if len(pkt) < 40 {
			return 0, fmt.Errorf("IPv6 头不完整(%d 字节)", len(pkt))
		}
		n := 40 + int(binary.BigEndian.Uint16(pkt[4:6]))
		if n < 40 || n > len(pkt) {
			return 0, fmt.Errorf("IPv6 长度=%d 越界(缓冲区 %d)", n, len(pkt))
		}
		return n, nil
	default:
		return 0, fmt.Errorf("未知 IP 版本 %d", pkt[0]>>4)
	}
}

// RecvBatch 一次最多收 len(addrs) 个包（WinDivert 2.x batched I/O）。
// 返回实际字节数与包数；DLL 不提供 RecvEx 或地址数组只有 1 格时，
// 自动退回单包 WinDivertRecv，行为与旧实现一致。
func (h *winDivertHandle) RecvBatch(buf []byte, addrs []winDivertAddress) (int, int, error) {
	if len(addrs) == 0 {
		return 0, 0, fmt.Errorf("empty address array")
	}
	if h.dll.procRecvEx == nil || len(addrs) < 2 {
		n, a, err := h.Recv(buf)
		if err != nil {
			return 0, 0, err
		}
		addrs[0] = *a
		return n, 1, nil
	}
	var n uint32
	// pAddrLen 进出都是"字节数"：进去是缓冲区总容量，出来是实际收到的地址总长。
	addrBytes := uint32(len(addrs) * winDivertAddressSize)
	ret, _, eno := h.dll.procRecvEx.Call(
		uintptr(h.handle),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&n)),
		0, // flags
		uintptr(unsafe.Pointer(&addrs[0])),
		uintptr(unsafe.Pointer(&addrBytes)),
		0, // lpOverlapped = NULL → 同步调用
	)
	if ret == 0 {
		return 0, 0, fmt.Errorf("WinDivertRecvEx: %w", eno)
	}
	if addrBytes == 0 || addrBytes%uint32(winDivertAddressSize) != 0 {
		return 0, 0, fmt.Errorf("WinDivertRecvEx 返回异常地址长度 %d", addrBytes)
	}
	pkts := int(addrBytes) / winDivertAddressSize
	if pkts > len(addrs) || int(n) > len(buf) {
		return 0, 0, fmt.Errorf("WinDivertRecvEx 返回异常规模: %d 包 %d 字节", pkts, n)
	}
	return int(n), pkts, nil
}

// SendBatch 把队列里的包按原顺序一次发出（WinDivert 2.x batched I/O）。
// 顺序 = 入队顺序 = 收包顺序，同一条流的包不会被重排；
// DLL 没有 SendEx 时按记录的逐包长度退回单包发送。
func (h *winDivertHandle) SendBatch(q *sendQueue) error {
	if q == nil || q.count() == 0 {
		return nil
	}
	if h.dll.procSendEx != nil {
		var sent uint32
		ret, _, eno := h.dll.procSendEx.Call(
			uintptr(h.handle),
			uintptr(unsafe.Pointer(&q.buf[0])),
			uintptr(len(q.buf)),
			uintptr(unsafe.Pointer(&sent)),
			0, // flags
			uintptr(unsafe.Pointer(&q.addrs[0])),
			uintptr(uint32(q.count()*winDivertAddressSize)),
			0, // lpOverlapped = NULL
		)
		if ret == 0 {
			return fmt.Errorf("WinDivertSendEx: %w", eno)
		}
		return nil
	}
	off := 0
	for idx, l := range q.lens {
		if err := h.Send(q.buf[off:off+l], &q.addrs[idx]); err != nil {
			return err
		}
		off += l
	}
	return nil
}
