package engine

// DNSRelay 本地 DNS 中继 —— 「零中国痕迹」的核心组件之一。
//
// 原理：拦截器把受控进程的出站 UDP 53 查询改写重定向到本中继（127.0.0.1:dnsPort），
// 中继按域名分流：
//   - 中国域名（geosite:cn / custom_direct） -> 系统 DNS 直连解析（原请求的 DNS 服务器）
//   - 国外域名（其余一切，fail-safe）        -> DoT（经上游代理出口）解析
//
// 从而保证：国外域名的 DNS 查询绝不经过中国境内任何 DNS 解析器，杜绝系统 DNS 泄漏；
// 国内域名走国内解析，速度与可用性不受影响。
//
// 失败策略：fail-closed —— 解析失败不返回结果（宁可超时，也不泄漏）。
//
// DoT 连接复用 + TTL 缓存，将经代理的 DNS 开销降到最低。

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CFM503/goPass/internal/config"
)

// =============================================================================
// DNS 报文解析（仅需提取查询名/类型 + 最小 TTL）
// =============================================================================

// parseDNSQuery 解析 DNS 查询，返回 (qname, qtype)。
func parseDNSQuery(q []byte) (string, uint16, bool) {
	if len(q) < 12 {
		return "", 0, false
	}
	qd := int(binary.BigEndian.Uint16(q[4:6]))
	if qd == 0 {
		return "", 0, false
	}
	off := 12
	var name strings.Builder
	for {
		if off >= len(q) {
			return "", 0, false
		}
		l := int(q[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 == 0xC0 {
			off += 2 // 压缩指针，域名结束
			break
		}
		if l > 63 || off+1+l > len(q) {
			return "", 0, false
		}
		if name.Len() > 0 {
			name.WriteByte('.')
		}
		name.Write(q[off+1 : off+1+l])
		off += 1 + l
	}
	if off+4 > len(q) {
		return "", 0, false
	}
	qtype := binary.BigEndian.Uint16(q[off : off+2])
	return strings.ToLower(name.String()), qtype, true
}

// skipDNSName 跳过 DNS 名称（支持压缩指针）。
func skipDNSName(b []byte, off int) (int, bool) {
	for {
		if off >= len(b) {
			return off, false
		}
		l := int(b[off])
		if l == 0 {
			return off + 1, true
		}
		if l&0xC0 == 0xC0 {
			return off + 2, true
		}
		if l > 63 || off+1+l > len(b) {
			return off, false
		}
		off += 1 + l
	}
}

// minAnswerTTL 提取响应中最小的答案 TTL（钳制在 [30, 3600] 秒）。
func minAnswerTTL(resp []byte) int {
	if len(resp) < 12 {
		return 300
	}
	qd := int(binary.BigEndian.Uint16(resp[4:6]))
	an := int(binary.BigEndian.Uint16(resp[6:8]))
	ns := int(binary.BigEndian.Uint16(resp[8:10]))
	ar := int(binary.BigEndian.Uint16(resp[10:12]))

	off := 12
	for i := 0; i < qd; i++ {
		var ok bool
		off, ok = skipDNSName(resp, off)
		if !ok || off+4 > len(resp) {
			return 300
		}
		off += 4
	}
	minTTL := 0
	total := an + ns + ar
	for i := 0; i < total; i++ {
		var ok bool
		off, ok = skipDNSName(resp, off)
		if !ok || off+10 > len(resp) {
			return 300
		}
		ttl := int(binary.BigEndian.Uint32(resp[off+4 : off+8]))
		rdlen := int(binary.BigEndian.Uint16(resp[off+8 : off+10]))
		if off+10+rdlen > len(resp) {
			return 300
		}
		if minTTL == 0 || (ttl > 0 && ttl < minTTL) {
			minTTL = ttl
		}
		off += 10 + rdlen
	}
	if minTTL < 30 {
		minTTL = 30
	}
	if minTTL > 3600 {
		minTTL = 3600
	}
	return minTTL
}

// =============================================================================
// TTL 缓存
// =============================================================================

type dnsCacheEntry struct {
	resp   []byte
	expiry time.Time
}

type dnsCache struct {
	mu sync.Mutex
	m  map[string]dnsCacheEntry
}

func newDNSCache() *dnsCache {
	return &dnsCache{m: make(map[string]dnsCacheEntry)}
}

func (c *dnsCache) Get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expiry) {
		delete(c.m, key)
		return nil, false
	}
	return e.resp, true
}

func (c *dnsCache) Set(key string, resp []byte, ttl int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = dnsCacheEntry{resp: append([]byte(nil), resp...), expiry: time.Now().Add(time.Duration(ttl) * time.Second)}
	if len(c.m) > 8192 {
		now := time.Now()
		for k, e := range c.m {
			if now.After(e.expiry) {
				delete(c.m, k)
			}
		}
	}
}

// =============================================================================
// DNSRelay
// =============================================================================

// DNSRelay 本地 DNS 中继。
type DNSRelay struct {
	router   *Router
	tracker  *ConnTracker
	upstream *UpstreamDialer
	resolved config.ResolvedSplit
	cache    *dnsCache

	connMu sync.Mutex
	conn   net.Conn // 复用的 DoT 连接（经上游代理）

	udpConn *net.UDPConn // 本地 UDP 监听（Close 时关闭）

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewDNSRelay 创建 DNS 中继。
func NewDNSRelay(router *Router, tracker *ConnTracker, upstream *UpstreamDialer, resolved config.ResolvedSplit) *DNSRelay {
	return &DNSRelay{
		router:   router,
		tracker:  tracker,
		upstream: upstream,
		resolved: resolved,
		cache:    newDNSCache(),
		stopCh:   make(chan struct{}),
	}
}

// Start 在 127.0.0.1:port 启动 UDP 监听（阻塞返回错误时说明端口被占用）。
func (d *DNSRelay) Start(port int) error {
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("DNS 中继监听 127.0.0.1:%d 失败: %w", port, err)
	}
	d.udpConn = conn
	log.Printf("[DNSRelay] ✅ 本地 DNS 中继已启动: 127.0.0.1:%d (国外域名经代理 DoT 解析，杜绝 DNS 泄漏)", port)
	go d.readLoop(conn)
	return nil
}

// Close 停止中继。
func (d *DNSRelay) Close() {
	select {
	case <-d.stopCh:
		return
	default:
		close(d.stopCh)
	}
	if d.udpConn != nil {
		d.udpConn.Close()
		d.udpConn = nil
	}
	d.connMu.Lock()
	if d.conn != nil {
		d.conn.Close()
		d.conn = nil
	}
	d.connMu.Unlock()
	d.wg.Wait()
}

func (d *DNSRelay) readLoop(conn *net.UDPConn) {
	buf := make([]byte, 8192)
	for {
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-d.stopCh:
				return
			default:
				continue
			}
		}
		query := append([]byte(nil), buf[:n]...)
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			d.handleQuery(query, client, conn)
		}()
	}
}

func (d *DNSRelay) handleQuery(query []byte, client *net.UDPAddr, conn *net.UDPConn) {
	qname, qtype, ok := parseDNSQuery(query)
	if !ok {
		log.Printf("[DNSRelay] 无法解析 DNS 查询（返回 SERVFAIL）")
		d.sendSERVFAIL(query, client, conn)
		return
	}

	var resp []byte
	var err error
	if d.isSystemDNS(qname) {
		resp, err = d.querySystemDNS(query, client)
	} else {
		resp, err = d.queryDoT(query, qname, qtype)
	}

	if err != nil {
		// fail-closed：不返回结果，宁让应用超时也绝不走有泄漏风险的路径
		log.Printf("[DNSRelay] 解析失败 %s (qtype=%d): %v（fail-closed）", qname, qtype, err)
		return
	}
	if _, err := conn.WriteToUDP(resp, client); err != nil {
		log.Printf("[DNSRelay] 回写响应失败: %v", err)
	}
}

// isSystemDNS 判断域名走系统 DNS（中国/自定义直连）还是 DoT（国外/自定义代理）。
func (d *DNSRelay) isSystemDNS(qname string) bool {
	m := d.router.Matcher()
	if m == nil {
		return false // 无规则时 fail-safe：一律按国外走 DoT
	}
	if m.MatchCustomDirect(qname, nil) {
		return true
	}
	return m.IsCNDomain(qname)
}

// querySystemDNS 将查询转发给原始 DNS 服务器（应用请求的那个）或配置的回退 DNS。
func (d *DNSRelay) querySystemDNS(query []byte, client *net.UDPAddr) ([]byte, error) {
	server := d.resolved.SystemDNS
	if server == "" {
		if t, ok := d.tracker.Get(client.IP.String(), uint16(client.Port)); ok && t.OrigDstIP != nil && !t.OrigDstIP.IsUnspecified() {
			server = t.OrigDstIP.String()
		}
	}
	if server == "" {
		server = "223.5.5.5" // AliDNS 兜底
	}
	target := ensurePort(server, 53)

	udpConn, err := net.DialTimeout("udp", target, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer udpConn.Close()
	udpConn.SetDeadline(time.Now().Add(4 * time.Second))

	if _, err := udpConn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 8192)
	n, err := udpConn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// queryDoT 经上游代理通过 DoT 解析国外域名（带 TTL 缓存）。
func (d *DNSRelay) queryDoT(query []byte, qname string, qtype uint16) ([]byte, error) {
	key := qname + "|" + strconv.Itoa(int(qtype))
	if resp, ok := d.cache.Get(key); ok {
		return resp, nil
	}

	resp, err := d.doRoundTrip(query)
	if err != nil {
		return nil, err
	}

	// 校验响应 ID 与查询一致，并缓存成功的答案
	if len(resp) >= 12 &&
		binary.BigEndian.Uint16(resp[0:2]) == binary.BigEndian.Uint16(query[0:2]) &&
		binary.BigEndian.Uint16(resp[6:8]) > 0 { // ANCOUNT > 0
		d.cache.Set(key, resp, minAnswerTTL(resp))
	}
	return resp, nil
}

// doRoundTrip 在复用的 DoT 连接上完成一次查询-应答（mutex 串行化）。
func (d *DNSRelay) doRoundTrip(query []byte) ([]byte, error) {
	d.connMu.Lock()
	defer d.connMu.Unlock()

	if d.conn == nil {
		c, err := d.dialDoT()
		if err != nil {
			return nil, err
		}
		d.conn = c
	}

	d.conn.SetDeadline(time.Now().Add(5 * time.Second))

	lp := make([]byte, 2)
	binary.BigEndian.PutUint16(lp, uint16(len(query)))
	msg := make([]byte, 0, 2+len(query))
	msg = append(msg, lp...)
	msg = append(msg, query...)
	if _, err := d.conn.Write(msg); err != nil {
		d.conn.Close()
		d.conn = nil
		return nil, err
	}

	if _, err := io.ReadFull(d.conn, lp); err != nil {
		d.conn.Close()
		d.conn = nil
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lp))
	if n <= 0 || n > 4096 {
		d.conn.Close()
		d.conn = nil
		return nil, fmt.Errorf("DoT 响应长度非法: %d", n)
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(d.conn, resp); err != nil {
		d.conn.Close()
		d.conn = nil
		return nil, err
	}
	return resp, nil
}

// dialDoT 经上游代理建立到 DoT 服务器的 TLS 连接。
func (d *DNSRelay) dialDoT() (net.Conn, error) {
	raw, err := d.upstream.Dial("tcp", d.resolved.DoTServer)
	if err != nil {
		return nil, fmt.Errorf("经上游代理连接 DoT %s 失败: %w", d.resolved.DoTServer, err)
	}
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName: d.resolved.DoTSNI,
		MinVersion: tls.VersionTLS12,
	})
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("DoT TLS 握手失败: %w", err)
	}
	tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// sendSERVFAIL 构造并发送最小 SERVFAIL 响应。
func (d *DNSRelay) sendSERVFAIL(query []byte, client *net.UDPAddr, conn *net.UDPConn) {
	resp := make([]byte, 12)
	copy(resp, query[:min(12, len(query))])
	flags := binary.BigEndian.Uint16(resp[2:4])
	flags |= 0x8000 // QR=1
	flags &^= 0x000F
	flags |= 0x0002 // RCODE=SERVFAIL
	binary.BigEndian.PutUint16(resp[2:4], flags)
	binary.BigEndian.PutUint16(resp[4:6], 0) // QDCOUNT=0
	if _, err := conn.WriteToUDP(resp, client); err != nil {
		log.Printf("[DNSRelay] 发送 SERVFAIL 失败: %v", err)
	}
}

// ensurePort 为不含端口的地址补上默认端口。
func ensurePort(host string, defaultPort int) string {
	if strings.Contains(host, ":") {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(defaultPort))
}
