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
	System      SystemConfig      `json:"system"`
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
			BufferSize:      262144,
			TCPNoDelay:      true,
			TCPSocketBuffer: 4194304,
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
	}
}

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
		c.System.TProxyPort = 7893
		c.System.ProcessCacheRefreshInterval = 10
		c.System.NetstatCacheRefreshInterval = 2
		c.System.DirectConnsTTL = 5
		c.System.ConnTrackGCInterval = 30
		c.System.ConnTrackTTL = 60
	}
	if c.API.UIConnLimit == 0 {
		c.API.UIConnLimit = 10
	}
	if c.API.DirectConnsLimit == 0 {
		c.API.DirectConnsLimit = 20
	}
	return nil
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
