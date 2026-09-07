package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	API         APIConfig         `json:"api"`
	DNS         DNSConfig         `json:"dns"`
	Routing     RoutingConfig     `json:"routing"`
	Outbounds   OutboundConfig    `json:"outbounds"`
	Performance PerformanceConfig `json:"performance"`
	System      SystemConfig         `json:"system"`
	Split       SplitConfig          `json:"split"`
	AutomaticRoute AutomaticRouteConfig `json:"automatic_route"`
}

// SplitConfig 「绝对分流」配置。
// 语义与任务要求的 YAML 字段一一对应（本项目配置为 JSON，字段名保持一致）。
// 布尔字段使用指针以区分「未配置」与「显式 false」，从而能安全地填入面向
// 「零中国痕迹」的安全默认值。
type SplitConfig struct {
	// Enabled 总开关。关闭后完全保持原有进程白名单行为。
	Enabled *bool `json:"enabled"`
	// Mode 分流模式: "geo"（纯地理分流）| "process"（纯进程白名单）| "both"（两者同时启用）
	Mode string `json:"mode"`
	// GeoPriority 仅在 Mode=="both" 时有效：true=地理分流优先于进程白名单（绝对分流）；
	// false=进程白名单优先（仅白名单进程参与地理分流，其余进程完全放行）。
	GeoPriority *bool `json:"geo_priority"`
	// CNDirect 中国站直连（默认 true）。false 时中国流量也走代理。
	CNDirect *bool `json:"cn_direct"`
	// ForeignProxy 国外站强制走代理（默认 true）。false 时国外流量直连（不推荐，会泄露）。
	ForeignProxy *bool `json:"foreign_proxy"`
	// BlockIPv6 屏蔽全部出站 IPv6，杜绝 IPv6 泄漏（默认 true，零中国痕迹必需）。
	BlockIPv6 *bool `json:"block_ipv6"`
	// RuleFiles 规则文件路径（geosite.dat / geoip.dat，v2ray/xray 生态格式）。
	RuleFiles SplitRuleFiles `json:"rule_files"`
	// CustomDirect 自定义强制直连的域名/IP（优先级最高）。
	CustomDirect []string `json:"custom_direct"`
	// CustomProxy 自定义强制走代理的域名/IP（优先级最高）。
	CustomProxy []string `json:"custom_proxy"`

	// ---- 以下为「零中国痕迹」附加配置（任务 YAML 之外的扩展项）----

	// DNSRelayPort 本地 DNS 中继端口。启用分流后默认 5300；0 表示关闭 DNS 劫持（不推荐）。
	DNSRelayPort int `json:"dns_relay_port"`
	// SystemDNS 中国域名使用的系统 DNS（默认空=使用应用原始请求的 DNS 服务器）。
	SystemDNS string `json:"system_dns"`
	// DoTServer 国外域名使用的 DoT 服务器（经上游代理出口），默认 1.1.1.1:853。
	DoTServer string `json:"dot_server"`
	// DoTSNI DoT TLS 握手的 SNI，默认 cloudflare-dns.com。
	DoTSNI string `json:"dot_sni"`
	// BlockForeignUDP 拦截全部国外目标 UDP（QUIC/STUN/TURN/游戏等），杜绝 UDP 泄漏（默认 true）。
	BlockForeignUDP *bool `json:"block_foreign_udp"`
	// UpdateURLs 规则文件在线更新地址（留空则使用官方默认地址）。
	UpdateURLs SplitUpdateURLs `json:"update_urls"`
	// AutoUpdateHours 规则文件自动更新间隔（小时），0=关闭。默认 0。
	AutoUpdateHours int `json:"auto_update_hours"`
}

type SplitRuleFiles struct {
	GeoSite string `json:"geosite"`
	GeoIP   string `json:"geoip"`
}

type SplitUpdateURLs struct {
	GeoSite string `json:"geosite"`
	GeoIP   string `json:"geoip"`
}

// ResolvedSplit 是应用了默认值后的只读分流配置快照。
type ResolvedSplit struct {
	Enabled         bool
	Mode            string
	GeoPriority     bool
	CNDirect        bool
	ForeignProxy    bool
	BlockIPv6       bool
	GeoSiteFile     string
	GeoIPFile       string
	CustomDirect    []string
	CustomProxy     []string
	DNSRelayPort    int
	SystemDNS       string
	DoTServer       string
	DoTSNI          string
	BlockForeignUDP bool
	AutoUpdateHours int
}

// Resolve 将指针布尔字段与零值字段解析为带安全默认值的快照。
func (s *SplitConfig) Resolve() ResolvedSplit {
	def := DefaultConfig().Split
	b := func(p *bool, fallback bool) bool {
		if p != nil {
			return *p
		}
		return fallback
	}
	mode := s.Mode
	if mode != "geo" && mode != "process" && mode != "both" {
		mode = def.Mode
	}
	dnsPort := s.DNSRelayPort
	if dnsPort == 0 {
		dnsPort = def.DNSRelayPort
	}
	dotServer := s.DoTServer
	if dotServer == "" {
		dotServer = def.DoTServer
	}
	dotSNI := s.DoTSNI
	if dotSNI == "" {
		dotSNI = def.DoTSNI
	}
	return ResolvedSplit{
		Enabled:         b(s.Enabled, false),
		Mode:            mode,
		GeoPriority:     b(s.GeoPriority, true),
		CNDirect:        b(s.CNDirect, true),
		ForeignProxy:    b(s.ForeignProxy, true),
		BlockIPv6:       b(s.BlockIPv6, true),
		GeoSiteFile:     s.RuleFiles.GeoSite,
		GeoIPFile:       s.RuleFiles.GeoIP,
		CustomDirect:    append([]string(nil), s.CustomDirect...),
		CustomProxy:     append([]string(nil), s.CustomProxy...),
		DNSRelayPort:    dnsPort,
		SystemDNS:       s.SystemDNS,
		DoTServer:       dotServer,
		DoTSNI:          dotSNI,
		BlockForeignUDP: b(s.BlockForeignUDP, true),
		AutoUpdateHours: s.AutoUpdateHours,
	}
}

type PerformanceConfig struct {
	BufferSize      int  `json:"buffer_size"`
	TCPNoDelay      bool `json:"tcp_nodelay"`
	TCPSocketBuffer int  `json:"tcp_socket_buffer"`
	BidirectWait    bool `json:"bidirectional_wait"`
	TCPKeepAlive    bool `json:"tcp_keep_alive"`
	KeepAlivePeriod int  `json:"keep_alive_period"`
	TCPLinger       int  `json:"tcp_linger"`
}

type APIConfig struct {
	ListenAddr        string `json:"listen_addr"`
	WSRefreshInterval int    `json:"ws_refresh_interval"`
	UIConnLimit       int    `json:"ui_conn_limit"`

	// [v1.2.6 Config] UI 直连显示开关 (默认关闭)
	ShowDirectConns bool `json:"show_direct_conns"`
	// [v1.2.6 Config] 直连显示最大条数限制 (默认 20)
	DirectConnsLimit int `json:"direct_conns_limit"`
}

// [v1.2.6 Config] 系统核心重构：剥离所有底层魔法数字
type SystemConfig struct {
	// [v1.2.6 Config] 透明代理内核监听端口 (默认 7893)
	TProxyPort int `json:"tproxy_port"`
	// [v1.2.6 Config] 进程探测缓存刷新频率 (默认 10s)
	ProcessCacheRefreshInterval int `json:"process_cache_refresh_interval"`
	// [v1.2.6 Config] TCP状态探测刷新频率 (默认 2s)
	NetstatCacheRefreshInterval int `json:"netstat_cache_refresh_interval"`
	// [v1.2.6 Config] 直连流量防内存溢出超时时间 (默认 5s)
	DirectConnsTTL int `json:"direct_conns_ttl"`
	// [v1.2.6 Config] 流量追踪垃圾回收频率 (默认 30s)
	ConnTrackGCInterval int `json:"conn_track_gc_interval"`
	// [v1.2.6 Config] 流量追踪超时时间 (默认 60s)
	ConnTrackTTL int `json:"conn_track_ttl"`
}

type DNSConfig struct {
	ListenAddr  string `json:"listen_addr"`
	FakeIPRange string `json:"fake_ip_range"`
}

type RoutingConfig struct {
	Mode  string `json:"mode"` // "whitelist" or "global"
	Rules []Rule `json:"rules"`
}

type Rule struct {
	Type     string `json:"type"` // "process", "domain", "ip"
	Payload  string `json:"payload"`
	Outbound string `json:"outbound"`
}

type OutboundConfig struct {
	Servers []Server `json:"servers"`
}

type Server struct {
	Tag      string `json:"tag"`
	Type     string `json:"type"` // "socks5", "http", "direct"
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// AutomaticRouteConfig 动态线路调度器配置
type AutomaticRouteConfig struct {
	Enabled              bool          `json:"enabled"`
	CheckInterval        int           `json:"check_interval"`          // 秒，Active 线路检测周期 (默认 5)
	StandbyCheckInterval int           `json:"standby_check_interval"`  // 秒，Standby 线路检测周期 (默认 30)
	RecoverCheckInterval int           `json:"recover_check_interval"`  // 秒，Failed 线路恢复检测周期 (默认 120)
	SwitchThreshold      float64       `json:"switch_threshold"`        // 切换分值门槛 (默认 5.0)
	SwitchCooldown       int           `json:"switch_cooldown"`         // 切换冷却时间/秒 (默认 60)
	MinimumStableTime    int           `json:"minimum_stable_time"`     // 候选线路需持续稳定的最小秒数 (默认 30)
	FailureThreshold     int           `json:"failure_threshold"`       // 判定故障的连续失败次数 (默认 3)
	RecoveryThreshold    int           `json:"recovery_threshold"`      // 判定恢复的连续成功次数 (默认 3)
	PeakMode             string        `json:"peak_mode"`               // "auto" | "scheduled" | "always" | "never" (默认 "auto")
	PeakStartHour        int           `json:"peak_start_hour"`         // 默认 18
	PeakEndHour          int           `json:"peak_end_hour"`           // 默认 23
	HistoryWindow        int           `json:"history_window"`          // 历史平滑窗口/分钟 (默认 60)
	StandbyCount         int           `json:"standby_count"`           // 备用线路数量 (默认 3)
	MaxProbeConcurrency  int           `json:"max_probe_concurrency"`   // 最大探测并发数 (默认 4)
	HistoryFile          string        `json:"history_file"`            // 历史数据保存路径 (默认 "routes_history.json")
	HistorySaveInterval  int           `json:"history_save_interval"`   // 历史保存周期/秒 (默认 300)
	Routes               []RouteConfig `json:"routes"`                  // 预配置线路列表
}

type RouteConfig struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "socks5" | "http"
	Type     string `json:"type"`     // "goway" | "external"
}

func DefaultAutomaticRouteConfig() AutomaticRouteConfig {
	return AutomaticRouteConfig{
		Enabled:              false,
		CheckInterval:        5,
		StandbyCheckInterval: 30,
		RecoverCheckInterval: 120,
		SwitchThreshold:      5.0,
		SwitchCooldown:       60,
		MinimumStableTime:    30,
		FailureThreshold:     3,
		RecoveryThreshold:    3,
		PeakMode:             "auto",
		PeakStartHour:        18,
		PeakEndHour:          23,
		HistoryWindow:        60,
		StandbyCount:         3,
		MaxProbeConcurrency:  4,
		HistoryFile:          "routes_history.json",
		HistorySaveInterval:  300,
		Routes: []RouteConfig{
			{
				ID:       "goway-default",
				Name:     "GOWAY Default",
				Address:  "127.0.0.1",
				Port:     9192,
				Protocol: "socks5",
				Type:     "goway",
			},
		},
	}
}

// NormalizeAutomaticRoute 填充安全默认值
func NormalizeAutomaticRoute(a AutomaticRouteConfig) AutomaticRouteConfig {
	def := DefaultAutomaticRouteConfig()
	if a.CheckInterval <= 0 {
		a.CheckInterval = def.CheckInterval
	}
	if a.StandbyCheckInterval <= 0 {
		a.StandbyCheckInterval = def.StandbyCheckInterval
	}
	if a.RecoverCheckInterval <= 0 {
		a.RecoverCheckInterval = def.RecoverCheckInterval
	}
	if a.SwitchThreshold <= 0 {
		a.SwitchThreshold = def.SwitchThreshold
	}
	if a.SwitchCooldown == 0 {
		a.SwitchCooldown = def.SwitchCooldown
	} else if a.SwitchCooldown < 0 {
		a.SwitchCooldown = 0
	}
	if a.MinimumStableTime == 0 {
		a.MinimumStableTime = def.MinimumStableTime
	} else if a.MinimumStableTime < 0 {
		a.MinimumStableTime = 0
	}
	if a.FailureThreshold <= 0 {
		a.FailureThreshold = def.FailureThreshold
	}
	if a.RecoveryThreshold <= 0 {
		a.RecoveryThreshold = def.RecoveryThreshold
	}
	if a.PeakMode == "" {
		a.PeakMode = def.PeakMode
	}
	if a.PeakStartHour == 0 && a.PeakEndHour == 0 {
		a.PeakStartHour = def.PeakStartHour
		a.PeakEndHour = def.PeakEndHour
	}
	if a.HistoryWindow <= 0 {
		a.HistoryWindow = def.HistoryWindow
	}
	if a.StandbyCount <= 0 {
		a.StandbyCount = def.StandbyCount
	}
	if a.MaxProbeConcurrency <= 0 {
		a.MaxProbeConcurrency = def.MaxProbeConcurrency
	}
	if a.HistoryFile == "" {
		a.HistoryFile = def.HistoryFile
	}
	if a.HistorySaveInterval <= 0 {
		a.HistorySaveInterval = def.HistorySaveInterval
	}
	if len(a.Routes) == 0 {
		a.Routes = def.Routes
	}
	return a
}

func DefaultConfig() *Config {
	return &Config{
		API: APIConfig{
			ListenAddr:        "127.0.0.1:8080",
			WSRefreshInterval: 5,
			UIConnLimit:       10,
			ShowDirectConns:   false,
			DirectConnsLimit:  20,
		},
		DNS: DNSConfig{
			ListenAddr:  "127.0.0.1:53",
			FakeIPRange: "198.18.0.0/16",
		},
		Routing: RoutingConfig{
			Mode: "whitelist",
			Rules: []Rule{
				{Type: "process", Payload: "chrome.exe", Outbound: "proxy"},
			},
		},
		Outbounds: OutboundConfig{
			Servers: []Server{
				{Tag: "proxy", Type: "socks5", Address: "127.0.0.1", Port: 9192},
				{Tag: "direct", Type: "direct"},
			},
		},
		Performance: PerformanceConfig{
			BufferSize:      32768,
			TCPNoDelay:      true,
			TCPSocketBuffer: 0,
			BidirectWait:    true,
			TCPKeepAlive:    true,
			KeepAlivePeriod: 15,
			TCPLinger:       -1,
		},
		System: SystemConfig{
			TProxyPort:                  7893,
			ProcessCacheRefreshInterval: 10,
			NetstatCacheRefreshInterval: 2,
			DirectConnsTTL:              5,
			ConnTrackGCInterval:         30,
			ConnTrackTTL:                60,
		},
		Split: SplitConfig{
			Enabled:      boolPtr(true),
			Mode:         "both",
			GeoPriority:  boolPtr(true),
			CNDirect:     boolPtr(true),
			ForeignProxy: boolPtr(true),
			BlockIPv6:    boolPtr(true),
			RuleFiles: SplitRuleFiles{
				GeoSite: "geosite.dat",
				GeoIP:   "geoip.dat",
			},
			CustomDirect:    []string{},
			CustomProxy:     []string{},
			DNSRelayPort:    5300,
			SystemDNS:       "",
			DoTServer:       "1.1.1.1:853",
			DoTSNI:          "cloudflare-dns.com",
			BlockForeignUDP: boolPtr(true),
			UpdateURLs: SplitUpdateURLs{
				GeoSite: "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat",
				GeoIP:   "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
			},
			AutoUpdateHours: 0,
		},
		AutomaticRoute: DefaultAutomaticRouteConfig(),
	}
}

func boolPtr(b bool) *bool { return &b }

// UnmarshalJSON implements custom JSON decoding for backward compatibility.
// [v1.2.6 Config] 兼容旧版 config.json 中 outbounds 拼写为 outbound 的情况，以及初始化 SystemConfig。
func (c *Config) UnmarshalJSON(data []byte) error {
	type Alias Config
	aux := &struct {
		*Alias
		OldOutbound *OutboundConfig `json:"outbound"`
	}{
		Alias: (*Alias)(c),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.OldOutbound != nil && len(c.Outbounds.Servers) == 0 {
		c.Outbounds = *aux.OldOutbound
	}

	// [v1.2.6 Config] 填充新增项的默认零值防止挂掉
	if c.System.TProxyPort == 0 {
		def := DefaultConfig()
		c.System = def.System
	}
	if c.API.UIConnLimit == 0 {
		c.API.UIConnLimit = 10
	}
	if c.API.DirectConnsLimit == 0 {
		c.API.DirectConnsLimit = 20
	}
	// [split] 合并分流配置的默认值：旧配置无 split 块时 Enabled 保持关闭（不改变原行为），
	// 其余字段填入面向「零中国痕迹」的安全默认值。
	c.Split = NormalizeSplit(c.Split)

	// [route] 合并动态线路调度器默认值
	c.AutomaticRoute = NormalizeAutomaticRoute(c.AutomaticRoute)
	return nil
}

// NormalizeSplit 为 SplitConfig 填充安全默认值（加载与热更新共用）。
// 注意：整个 split 块缺失时 Enabled 默认 false（保持旧版行为），用户显式开启后其余字段即生效。
func NormalizeSplit(s SplitConfig) SplitConfig {
	def := DefaultConfig().Split
	if s.Enabled == nil {
		s.Enabled = boolPtr(false)
	}
	if s.GeoPriority == nil {
		s.GeoPriority = def.GeoPriority
	}
	if s.CNDirect == nil {
		s.CNDirect = def.CNDirect
	}
	if s.ForeignProxy == nil {
		s.ForeignProxy = def.ForeignProxy
	}
	if s.BlockIPv6 == nil {
		s.BlockIPv6 = def.BlockIPv6
	}
	if s.BlockForeignUDP == nil {
		s.BlockForeignUDP = def.BlockForeignUDP
	}
	if s.Mode == "" {
		s.Mode = def.Mode
	}
	if s.DNSRelayPort == 0 {
		s.DNSRelayPort = def.DNSRelayPort
	}
	if s.DoTServer == "" {
		s.DoTServer = def.DoTServer
	}
	if s.DoTSNI == "" {
		s.DoTSNI = def.DoTSNI
	}
	if s.RuleFiles.GeoSite == "" {
		s.RuleFiles.GeoSite = def.RuleFiles.GeoSite
	}
	if s.RuleFiles.GeoIP == "" {
		s.RuleFiles.GeoIP = def.RuleFiles.GeoIP
	}
	if s.UpdateURLs.GeoSite == "" {
		s.UpdateURLs.GeoSite = def.UpdateURLs.GeoSite
	}
	if s.UpdateURLs.GeoIP == "" {
		s.UpdateURLs.GeoIP = def.UpdateURLs.GeoIP
	}
	if s.CustomDirect == nil {
		s.CustomDirect = []string{}
	}
	if s.CustomProxy == nil {
		s.CustomProxy = []string{}
	}
	return s
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
