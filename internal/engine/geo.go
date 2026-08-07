package engine

// GeoMatcher 地理分流规则匹配器。
//
// 数据源：
//   - geosite.dat / geoip.dat（v2ray/xray 生态，protobuf 封装格式 GeoIPList/GeoSiteList）
//   - 纯文本列表（.txt / .list）：每行一个域名或 CIDR
//   - MaxMind GeoLite2 Country CSV（blocks + locations 两个文件）
//
// 域名匹配语义与 v2ray-core v5 保持一致：
//   - Plain(0)     -> 子串匹配（Substr）
//   - Regex(1)     -> 正则
//   - RootDomain(2)-> 根域名匹配（域本身 + 任意子域）
//   - Full(3)      -> 完全匹配
//
// GeoMatcher 一经构建即为不可变（只读），通过整体替换实现热重载。

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/CFM503/goPass/internal/config"
)

// =============================================================================
// 最小 protobuf wire-format 读取器（仅用于解析 v2ray .dat 文件）
// =============================================================================

type pbReader struct {
	b   []byte
	off int
}

func (r *pbReader) varint() (uint64, error) {
	var v uint64
	var shift uint
	for {
		if r.off >= len(r.b) {
			return 0, fmt.Errorf("varint truncated")
		}
		b := r.b[r.off]
		r.off++
		if shift >= 64 {
			return 0, fmt.Errorf("varint overflow")
		}
		v |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			return v, nil
		}
		shift += 7
	}
}

func (r *pbReader) tag() (field int, wire int, err error) {
	v, err := r.varint()
	if err != nil {
		return 0, 0, err
	}
	field = int(v >> 3)
	wire = int(v & 7)
	if field <= 0 {
		return 0, 0, fmt.Errorf("invalid field number %d", field)
	}
	return field, wire, nil
}

func (r *pbReader) bytes() ([]byte, error) {
	n, err := r.varint()
	if err != nil {
		return nil, err
	}
	if r.off+int(n) > len(r.b) {
		return nil, fmt.Errorf("length-delimited field overruns buffer")
	}
	v := r.b[r.off : r.off+int(n)]
	r.off += int(n)
	return v, nil
}

// skip 跳过当前 wire type 字段。
func (r *pbReader) skip(wire int) error {
	switch wire {
	case 0:
		_, err := r.varint()
		return err
	case 1:
		if r.off+8 > len(r.b) {
			return fmt.Errorf("64-bit field truncated")
		}
		r.off += 8
		return nil
	case 2:
		_, err := r.bytes()
		return err
	case 5:
		if r.off+4 > len(r.b) {
			return fmt.Errorf("32-bit field truncated")
		}
		r.off += 4
		return nil
	default:
		return fmt.Errorf("unsupported wire type %d", wire)
	}
}

// =============================================================================
// .dat 解析
// =============================================================================

type cidrRecord struct {
	ip     net.IP
	prefix int
}

type geoipRecord struct {
	country string
	cidrs   []cidrRecord
}

type domainRecord struct {
	typ   int
	value string
}

type geositeRecord struct {
	country string
	domains []domainRecord
}

// parseCIDRMessage 解析 CIDR 内嵌消息 { ip=1, prefix=2 }。
func parseCIDRMessage(b []byte) (cidrRecord, bool) {
	r := &pbReader{b: b}
	var c cidrRecord
	hasIP := false
	for r.off < len(r.b) {
		f, w, err := r.tag()
		if err != nil {
			return c, false
		}
		switch {
		case f == 1 && w == 2:
			ipb, err := r.bytes()
			if err != nil {
				return c, false
			}
			if len(ipb) == 4 || len(ipb) == 16 {
				c.ip = net.IP(append([]byte(nil), ipb...))
				hasIP = true
			}
		case f == 2 && w == 0:
			v, err := r.varint()
			if err != nil {
				return c, false
			}
			c.prefix = int(v)
		default:
			if err := r.skip(w); err != nil {
				return c, false
			}
		}
	}
	return c, hasIP
}

// parseGeoIPMessage 解析 GeoIP 内嵌消息 { country_code=1, cidr=2, ... }。
func parseGeoIPMessage(b []byte) (geoipRecord, bool) {
	r := &pbReader{b: b}
	var rec geoipRecord
	for r.off < len(r.b) {
		f, w, err := r.tag()
		if err != nil {
			return rec, false
		}
		switch {
		case f == 1 && w == 2:
			v, err := r.bytes()
			if err != nil {
				return rec, false
			}
			rec.country = strings.ToUpper(string(v))
		case f == 2 && w == 2:
			v, err := r.bytes()
			if err != nil {
				return rec, false
			}
			if c, ok := parseCIDRMessage(v); ok {
				rec.cidrs = append(rec.cidrs, c)
			}
		default:
			if err := r.skip(w); err != nil {
				return rec, false
			}
		}
	}
	return rec, true
}

// parseGeoIPDat 解析 GeoIPList 封装格式（字段 1 = 重复的 GeoIP 内嵌消息）。
func parseGeoIPDat(data []byte) ([]geoipRecord, error) {
	r := &pbReader{b: data}
	var recs []geoipRecord
	for r.off < len(r.b) {
		f, w, err := r.tag()
		if err != nil {
			break
		}
		if f == 1 && w == 2 {
			v, err := r.bytes()
			if err != nil {
				break
			}
			if rec, ok := parseGeoIPMessage(v); ok {
				recs = append(recs, rec)
			}
			continue
		}
		if err := r.skip(w); err != nil {
			break
		}
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("无法从 geoip 文件中解析出任何条目（可能不是 GeoIPList 封装格式）")
	}
	return recs, nil
}

// parseDomainMessage 解析 Domain 内嵌消息 { type=1, value=2 }。
func parseDomainMessage(b []byte) (domainRecord, bool) {
	r := &pbReader{b: b}
	var d domainRecord
	for r.off < len(r.b) {
		f, w, err := r.tag()
		if err != nil {
			return d, false
		}
		switch {
		case f == 1 && w == 0:
			v, err := r.varint()
			if err != nil {
				return d, false
			}
			d.typ = int(v)
		case f == 2 && w == 2:
			v, err := r.bytes()
			if err != nil {
				return d, false
			}
			d.value = string(v)
		default:
			if err := r.skip(w); err != nil {
				return d, false
			}
		}
	}
	return d, d.value != ""
}

// parseGeoSiteMessage 解析 GeoSite 内嵌消息 { country_code=1, domain=2, ... }。
func parseGeoSiteMessage(b []byte) (geositeRecord, bool) {
	r := &pbReader{b: b}
	var rec geositeRecord
	for r.off < len(r.b) {
		f, w, err := r.tag()
		if err != nil {
			return rec, false
		}
		switch {
		case f == 1 && w == 2:
			v, err := r.bytes()
			if err != nil {
				return rec, false
			}
			rec.country = strings.ToUpper(string(v))
		case f == 2 && w == 2:
			v, err := r.bytes()
			if err != nil {
				return rec, false
			}
			if d, ok := parseDomainMessage(v); ok {
				rec.domains = append(rec.domains, d)
			}
		default:
			if err := r.skip(w); err != nil {
				return rec, false
			}
		}
	}
	return rec, true
}

// parseGeoSiteDat 解析 GeoSiteList 封装格式（字段 1 = 重复的 GeoSite 内嵌消息）。
func parseGeoSiteDat(data []byte) ([]geositeRecord, error) {
	r := &pbReader{b: data}
	var recs []geositeRecord
	for r.off < len(r.b) {
		f, w, err := r.tag()
		if err != nil {
			break
		}
		if f == 1 && w == 2 {
			v, err := r.bytes()
			if err != nil {
				break
			}
			if rec, ok := parseGeoSiteMessage(v); ok {
				recs = append(recs, rec)
			}
			continue
		}
		if err := r.skip(w); err != nil {
			break
		}
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("无法从 geosite 文件中解析出任何条目（可能不是 GeoSiteList 封装格式）")
	}
	return recs, nil
}

// =============================================================================
// 纯文本解析
// =============================================================================

// 自定义 IP 规则前缀
const (
	rulePrefixIP   = "ip:"
	rulePrefixCIDR = "cidr:"
)

// parseDomainLine 解析单行域名规则，返回 (kind, value)。
// kind: "suffix" | "full" | "keyword" | "regexp"
func parseDomainLine(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return "", "", false
	}
	if ip := net.ParseIP(line); ip != nil {
		return "", "", false // IP 由 parseIPLine 处理
	}
	if idx := strings.IndexByte(line, ':'); idx > 0 {
		pfx := strings.ToLower(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		switch pfx {
		case "full":
			return "full", normalizeDomain(val), true
		case "keyword":
			return "keyword", strings.ToLower(val), true
		case "regexp":
			return "regexp", val, true
		case "domain", "plain":
			return "suffix", normalizeDomain(val), true
		case "ip", "cidr":
			return "", "", false // IP 由 parseIPLine 处理
		}
	}
	// 裸域名 → 后缀匹配
	return "suffix", normalizeDomain(line), true
}

// parseIPLine 解析单行 IP 规则，返回 CIDR 字符串或 (nil,false)。
func parseIPLine(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return "", false
	}
	low := strings.ToLower(line)
	switch {
	case strings.HasPrefix(low, rulePrefixIP):
		return strings.TrimSpace(line[len(rulePrefixIP):]) + "/32", true
	case strings.HasPrefix(low, rulePrefixCIDR):
		return strings.TrimSpace(line[len(rulePrefixCIDR):]), true
	}
	// 裸 IP 或 CIDR
	if strings.Contains(line, "/") {
		return line, true
	}
	if ip := net.ParseIP(line); ip != nil {
		return line + "/32", true
	}
	return "", false
}

// parseDomainListFile 解析纯文本域名列表文件（每行一条规则）。
func parseDomainListFile(path string) ([]string, []string, []string, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer f.Close()

	var suffix, full, keyword, regexps []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		kind, value, ok := parseDomainLine(sc.Text())
		if !ok || value == "" {
			continue
		}
		switch kind {
		case "suffix":
			suffix = append(suffix, value)
		case "full":
			full = append(full, value)
		case "keyword":
			keyword = append(keyword, value)
		case "regexp":
			regexps = append(regexps, value)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, nil, nil, err
	}
	return suffix, full, keyword, regexps, nil
}

// parseGeoLite2BlocksCSV 解析 MaxMind GeoLite2 Country CSV。
// blocksPath: GeoLite2-Country-Blocks-IPv4.csv
// locationsPath: GeoLite2-Country-Locations-en.csv（用于 geoname_id -> ISO 映射）
// 返回 countryCode（如 "CN"）对应的网络段。
func parseGeoLite2BlocksCSV(blocksPath, locationsPath, countryCode string) ([]string, error) {
	// 1. 解析 locations：geoname_id -> country_iso_code
	locMap := make(map[string]string)
	lf, err := os.Open(locationsPath)
	if err != nil {
		return nil, fmt.Errorf("打开 GeoLite2 locations 文件失败: %w", err)
	}
	defer lf.Close()

	countryCode = strings.ToUpper(countryCode)
	sc := bufio.NewScanner(lf)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	header := true
	for sc.Scan() {
		line := sc.Text()
		if header {
			header = false
			continue
		}
		cols := strings.Split(line, ",")
		if len(cols) < 5 {
			continue
		}
		// geoname_id,locale_code,continent_code,continent_name,country_iso_code,...
		gid := strings.Trim(cols[0], `"`)
		iso := strings.ToUpper(strings.Trim(cols[4], `"`))
		if gid != "" && iso != "" {
			locMap[gid] = iso
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	// 2. 解析 blocks：network,geoname_id,registered_country_geoname_id,...
	bf, err := os.Open(blocksPath)
	if err != nil {
		return nil, fmt.Errorf("打开 GeoLite2 blocks 文件失败: %w", err)
	}
	defer bf.Close()

	var cidrs []string
	sc = bufio.NewScanner(bf)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	header = true
	for sc.Scan() {
		line := sc.Text()
		if header {
			header = false
			continue
		}
		cols := strings.Split(line, ",")
		if len(cols) < 3 {
			continue
		}
		network := strings.Trim(cols[0], `"`)
		geo := strings.Trim(cols[1], `"`)
		if geo == "" {
			geo = strings.Trim(cols[2], `"`) // registered_country_geoname_id
		}
		if locMap[geo] == countryCode {
			cidrs = append(cidrs, network)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("GeoLite2 数据中未找到 %s 网络段", countryCode)
	}
	return cidrs, nil
}

// =============================================================================
// 匹配器
// =============================================================================

// normalizeDomain 规范化域名：小写、去除首尾空白、去除尾部点、去除 *. 前缀。
func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimSuffix(d, ".")
	d = strings.TrimPrefix(d, "*.")
	d = strings.TrimPrefix(d, ".")
	return d
}

// domainMatcher 域名匹配器：后缀 / 完全 / 关键字 / 正则。
// 构建后只读，可被多 goroutine 并发匹配。
type domainMatcher struct {
	suffix  map[string]struct{}
	full    map[string]struct{}
	keyword []string
	regexps []*regexp.Regexp

	suffixCount  int
	keywordCount int
}

func newDomainMatcher() *domainMatcher {
	return &domainMatcher{
		suffix: make(map[string]struct{}),
		full:   make(map[string]struct{}),
	}
}

func (m *domainMatcher) addSuffix(d string) {
	if d == "" {
		return
	}
	m.suffix[d] = struct{}{}
	m.suffixCount++
}

func (m *domainMatcher) addFull(d string) {
	if d == "" {
		return
	}
	m.full[d] = struct{}{}
}

func (m *domainMatcher) addKeyword(k string) {
	if k == "" {
		return
	}
	m.keyword = append(m.keyword, k)
	m.keywordCount++
}

func (m *domainMatcher) addRegexp(pattern string) {
	if pattern == "" {
		return
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		log.Printf("[Geo] 忽略非法正则规则 %q: %v", pattern, err)
		return
	}
	m.regexps = append(m.regexps, re)
}

func (m *domainMatcher) Match(domain string) bool {
	if m == nil || domain == "" {
		return false
	}
	d := normalizeDomain(domain)
	if d == "" {
		return false
	}

	// 1. 后缀匹配（域本身 + 逐级父域）
	walk := d
	for {
		if _, ok := m.suffix[walk]; ok {
			return true
		}
		idx := strings.IndexByte(walk, '.')
		if idx < 0 {
			break
		}
		walk = walk[idx+1:]
	}

	// 2. 完全匹配
	if _, ok := m.full[d]; ok {
		return true
	}

	// 3. 关键字（子串）
	if len(m.keyword) > 0 {
		for _, k := range m.keyword {
			if strings.Contains(d, k) {
				return true
			}
		}
	}

	// 4. 正则
	if len(m.regexps) > 0 {
		for _, re := range m.regexps {
			if re.MatchString(d) {
				return true
			}
		}
	}
	return false
}

func (m *domainMatcher) Count() int {
	if m == nil {
		return 0
	}
	return m.suffixCount + len(m.full) + m.keywordCount + len(m.regexps)
}

// ipRange 闭区间 [start, end]。
type ipRange struct {
	start uint32
	end   uint32
}

// ipSet IPv4 网段集合（排序 + 二分查找）。
// IPv6 不参与匹配（IPv6 流量在拦截层被屏蔽，见 block_ipv6）。
type ipSet struct {
	ranges []ipRange
}

func (s *ipSet) addCIDR(cidr string) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		if ip := net.ParseIP(cidr); ip != nil {
			_, ipNet, err = net.ParseCIDR(cidr + "/32")
		}
		if err != nil {
			log.Printf("[Geo] 忽略非法 CIDR %q: %v", cidr, err)
			return
		}
	}
	v4 := ipNet.IP.To4()
	if v4 == nil {
		// IPv6 段：不支持，忽略（IPv6 在拦截层被屏蔽）
		return
	}
	ones, _ := ipNet.Mask.Size()
	base := binary.BigEndian.Uint32(v4)
	var mask uint32
	if ones > 0 {
		mask = ^uint32(0) << uint(32-ones)
	} else {
		mask = 0
	}
	start := base & mask
	end := start | ^mask
	s.ranges = append(s.ranges, ipRange{start: start, end: end})
}

func (s *ipSet) addIPBytes(ip net.IP, prefix int) {
	v4 := ip.To4()
	if v4 == nil {
		return
	}
	ones := prefix
	if ones < 0 || ones > 32 {
		ones = 32
	}
	base := binary.BigEndian.Uint32(v4)
	var mask uint32
	if ones > 0 {
		mask = ^uint32(0) << uint(32-ones)
	} else {
		mask = 0
	}
	start := base & mask
	end := start | ^mask
	s.ranges = append(s.ranges, ipRange{start: start, end: end})
}

// build 排序并合并重叠区间。
func (s *ipSet) build() {
	if len(s.ranges) < 2 {
		return
	}
	sort.Slice(s.ranges, func(i, j int) bool {
		if s.ranges[i].start != s.ranges[j].start {
			return s.ranges[i].start < s.ranges[j].start
		}
		return s.ranges[i].end < s.ranges[j].end
	})
	merged := s.ranges[:1]
	for _, r := range s.ranges[1:] {
		last := &merged[len(merged)-1]
		if r.start <= last.end+1 {
			if r.end > last.end {
				last.end = r.end
			}
		} else {
			merged = append(merged, r)
		}
	}
	s.ranges = merged
}

func (s *ipSet) Match(ip net.IP) bool {
	if s == nil || ip == nil || len(s.ranges) == 0 {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	x := binary.BigEndian.Uint32(v4)
	i := sort.Search(len(s.ranges), func(i int) bool { return s.ranges[i].end >= x })
	return i < len(s.ranges) && s.ranges[i].start <= x
}

func (s *ipSet) Count() int {
	if s == nil {
		return 0
	}
	return len(s.ranges)
}

// =============================================================================
// GeoMatcher
// =============================================================================

// GeoMatcherStats 规则加载统计（供 UI/API 展示）。
type GeoMatcherStats struct {
	GeoSiteFile      string `json:"geosite_file"`
	GeoIPFile        string `json:"geoip_file"`
	GeoSiteCNEntries int    `json:"geosite_cn_entries"`
	GeoIPCNCIDRs     int    `json:"geoip_cn_cidrs"`
	CustomDirectDom  int    `json:"custom_direct_domains"`
	CustomDirectIPs  int    `json:"custom_direct_ips"`
	CustomProxyDom   int    `json:"custom_proxy_domains"`
	CustomProxyIPs   int    `json:"custom_proxy_ips"`
	LoadedAt         string `json:"loaded_at"`
	Error            string `json:"error,omitempty"`
}

// GeoMatcher 分流规则集合（不可变）。
type GeoMatcher struct {
	cnDomains *domainMatcher // geosite:cn
	cnIPs     *ipSet         // geoip:cn

	customDirectDomains *domainMatcher
	customProxyDomains  *domainMatcher
	customDirectIPs     *ipSet
	customProxyIPs      *ipSet

	stats GeoMatcherStats
}

// LoadGeoMatcher 根据分流配置构建规则匹配器。
// baseDir 用于解析相对路径；为空则使用当前工作目录。
func LoadGeoMatcher(resolved config.ResolvedSplit, baseDir string) (*GeoMatcher, error) {
	m := &GeoMatcher{
		cnDomains:           newDomainMatcher(),
		cnIPs:               &ipSet{},
		customDirectDomains: newDomainMatcher(),
		customProxyDomains:  newDomainMatcher(),
		customDirectIPs:     &ipSet{},
		customProxyIPs:      &ipSet{},
	}
	var errs []string

	// ---- geosite（域名）----
	if resolved.GeoSiteFile != "" {
		path := resolvePath(resolved.GeoSiteFile, baseDir)
		if err := m.loadGeoSite(path); err != nil {
			errs = append(errs, fmt.Sprintf("geosite: %v", err))
		} else {
			m.stats.GeoSiteFile = resolved.GeoSiteFile
		}
	}

	// ---- geoip（IP 段）----
	if resolved.GeoIPFile != "" {
		path := resolvePath(resolved.GeoIPFile, baseDir)
		if err := m.loadGeoIP(path); err != nil {
			errs = append(errs, fmt.Sprintf("geoip: %v", err))
		} else {
			m.stats.GeoIPFile = resolved.GeoIPFile
		}
	}

	// ---- 自定义规则 ----
	directDoms, directIPs, err := parseCustomList(resolved.CustomDirect)
	if err != nil {
		errs = append(errs, fmt.Sprintf("custom_direct: %v", err))
	}
	proxyDoms, proxyIPs, err := parseCustomList(resolved.CustomProxy)
	if err != nil {
		errs = append(errs, fmt.Sprintf("custom_proxy: %v", err))
	}
	m.customDirectDomains = directDoms
	m.customDirectIPs = directIPs
	m.customProxyDomains = proxyDoms
	m.customProxyIPs = proxyIPs

	m.stats.CustomDirectDom = directDoms.Count()
	m.stats.CustomDirectIPs = directIPs.Count()
	m.stats.CustomProxyDom = proxyDoms.Count()
	m.stats.CustomProxyIPs = proxyIPs.Count()
	m.stats.GeoSiteCNEntries = m.cnDomains.Count()
	m.stats.GeoIPCNCIDRs = m.cnIPs.Count()
	m.stats.LoadedAt = nowStr()

	if len(errs) > 0 {
		m.stats.Error = strings.Join(errs, "; ")
	}
	return m, nil
}

func nowStr() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func resolvePath(p, baseDir string) string {
	if filepath.IsAbs(p) {
		return p
	}
	if baseDir != "" {
		return filepath.Join(baseDir, p)
	}
	return p
}

// loadGeoSite 按扩展名加载 geosite 数据源：
// .dat -> v2ray 封装格式；.txt/.list -> 纯文本域名列表；否则按内容嗅探。
// 磁盘文件缺失时自动回退到内置规则（编译进二进制，开箱即用）。
func (m *GeoMatcher) loadGeoSite(path string) error {
	// 磁盘规则文件缺失 -> 内置规则
	if _, err := os.Stat(path); err != nil && len(embeddedGeoSite) > 0 {
		log.Printf("[Geo] 磁盘规则文件 %s 不存在，使用内置 geosite 规则", path)
		return m.loadGeoSiteText(embeddedGeoSite)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".txt", ".list", ".conf":
		return m.loadGeoSiteText(data)
	default:
		return m.loadGeoSiteDat(data)
	}
}

func (m *GeoMatcher) loadGeoSiteDat(data []byte) error {
	recs, err := parseGeoSiteDat(data)
	if err != nil {
		return err
	}
	var matched bool
	for _, rec := range recs {
		if rec.country == "CN" {
			matched = true
			for _, d := range rec.domains {
				switch d.typ {
				case 0: // Plain -> 子串
					m.cnDomains.addKeyword(strings.ToLower(d.value))
				case 1: // Regex
					m.cnDomains.addRegexp(d.value)
				case 2: // RootDomain -> 后缀
					m.cnDomains.addSuffix(normalizeDomain(d.value))
				case 3: // Full -> 完全
					m.cnDomains.addFull(normalizeDomain(d.value))
				default:
					m.cnDomains.addSuffix(normalizeDomain(d.value))
				}
			}
		}
	}
	if !matched {
		return fmt.Errorf("geosite 数据中未找到 CN 分类")
	}
	return nil
}

func (m *GeoMatcher) loadGeoSiteText(data []byte) error {
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	count := 0
	for sc.Scan() {
		kind, value, ok := parseDomainLine(sc.Text())
		if !ok || value == "" {
			continue
		}
		count++
		switch kind {
		case "suffix":
			m.cnDomains.addSuffix(value)
		case "full":
			m.cnDomains.addFull(value)
		case "keyword":
			m.cnDomains.addKeyword(value)
		case "regexp":
			m.cnDomains.addRegexp(value)
		}
	}
	if count == 0 {
		return fmt.Errorf("geosite 文本文件中没有可用的域名规则")
	}
	return nil
}

// loadGeoIP 按扩展名加载 geoip 数据源。
// 磁盘文件缺失时自动回退到内置规则（编译进二进制，开箱即用）。
func (m *GeoMatcher) loadGeoIP(path string) error {
	// 磁盘规则文件缺失 -> 内置规则
	if _, err := os.Stat(path); err != nil && len(embeddedGeoIP) > 0 {
		log.Printf("[Geo] 磁盘规则文件 %s 不存在，使用内置 geoip 规则", path)
		return m.finishGeoIP(m.loadGeoIPText(embeddedGeoIP))
	}

	switch strings.ToLower(filepath.Ext(path)) {
	case ".csv":
		// MaxMind GeoLite2：需要同目录的 locations 文件
		loc := filepath.Join(filepath.Dir(path), "GeoLite2-Country-Locations-en.csv")
		cidrs, err := parseGeoLite2BlocksCSV(path, loc, "CN")
		if err != nil {
			return err
		}
		for _, c := range cidrs {
			m.cnIPs.addCIDR(c)
		}
	case ".txt", ".list":
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return m.finishGeoIP(m.loadGeoIPText(data))
	default:
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return m.finishGeoIP(m.loadGeoIPDat(data))
	}
	return m.finishGeoIP(nil)
}

// finishGeoIP 统一收尾：构建索引并校验非空。
func (m *GeoMatcher) finishGeoIP(err error) error {
	if err != nil {
		return err
	}
	m.cnIPs.build()
	if m.cnIPs.Count() == 0 {
		return fmt.Errorf("geoip 数据中 CN 网段为空")
	}
	return nil
}

// loadGeoIPDat 从 v2ray geoip.dat 封装格式解析 CN 网段。
func (m *GeoMatcher) loadGeoIPDat(data []byte) error {
	recs, err := parseGeoIPDat(data)
	if err != nil {
		return err
	}
	var matched bool
	for _, rec := range recs {
		if rec.country == "CN" {
			matched = true
			for _, c := range rec.cidrs {
				m.cnIPs.addIPBytes(c.ip, c.prefix)
			}
		}
	}
	if !matched {
		return fmt.Errorf("geoip 数据中未找到 CN 网段")
	}
	return nil
}

// loadGeoIPText 从纯文本（每行一个 IP 或 CIDR）加载网段。
func (m *GeoMatcher) loadGeoIPText(data []byte) error {
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	count := 0
	for sc.Scan() {
		if c, ok := parseIPLine(sc.Text()); ok {
			m.cnIPs.addCIDR(c)
			count++
		}
	}
	if count == 0 {
		return fmt.Errorf("geoip 文本文件中没有可用的网段")
	}
	return nil
}

// parseCustomList 将自定义规则条目拆分为域名规则与 IP 规则。
func parseCustomList(items []string) (*domainMatcher, *ipSet, error) {
	dm := newDomainMatcher()
	is := &ipSet{}
	for _, item := range items {
		if c, ok := parseIPLine(item); ok {
			is.addCIDR(c)
			continue
		}
		if kind, value, ok := parseDomainLine(item); ok && value != "" {
			switch kind {
			case "suffix":
				dm.addSuffix(value)
			case "full":
				dm.addFull(value)
			case "keyword":
				dm.addKeyword(value)
			case "regexp":
				dm.addRegexp(value)
			}
		}
	}
	is.build()
	return dm, is, nil
}

// =============================================================================
// 查询接口
// =============================================================================

// IsCNDomain 域名是否命中 geosite:cn。
func (m *GeoMatcher) IsCNDomain(domain string) bool {
	return m != nil && m.cnDomains != nil && m.cnDomains.Match(domain)
}

// IsCNIP IP 是否命中 geoip:cn。
func (m *GeoMatcher) IsCNIP(ip net.IP) bool {
	return m != nil && m.cnIPs != nil && m.cnIPs.Match(ip)
}

// MatchCustomDirect 命中自定义直连规则（先域名后 IP）。
func (m *GeoMatcher) MatchCustomDirect(domain string, ip net.IP) bool {
	if m == nil {
		return false
	}
	if domain != "" && m.customDirectDomains != nil && m.customDirectDomains.Match(domain) {
		return true
	}
	return ip != nil && m.customDirectIPs != nil && m.customDirectIPs.Match(ip)
}

// MatchCustomProxy 命中自定义强制代理规则（先域名后 IP）。
func (m *GeoMatcher) MatchCustomProxy(domain string, ip net.IP) bool {
	if m == nil {
		return false
	}
	if domain != "" && m.customProxyDomains != nil && m.customProxyDomains.Match(domain) {
		return true
	}
	return ip != nil && m.customProxyIPs != nil && m.customProxyIPs.Match(ip)
}

// IsForeignIP 判定 IP 是否为国外（未命中 CN 或自定义直连即为国外，fail-safe）。
func (m *GeoMatcher) IsForeignIP(ip net.IP) bool {
	if m == nil || ip == nil {
		return true
	}
	if m.customDirectIPs != nil && m.customDirectIPs.Match(ip) {
		return false
	}
	if m.cnIPs != nil && m.cnIPs.Match(ip) {
		return false
	}
	return true
}

// Stats 返回加载统计。
func (m *GeoMatcher) Stats() GeoMatcherStats {
	if m == nil {
		return GeoMatcherStats{}
	}
	return m.stats
}
