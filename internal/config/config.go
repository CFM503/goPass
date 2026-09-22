package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	API              APIConfig         `json:"api"`
	Outbounds        OutboundConfig    `json:"outbounds"`
	Performance      PerformanceConfig `json:"performance"`
	System           SystemConfig      `json:"system"`
	ProcessWhitelist []string          `json:"process_whitelist"`
}

type PerformanceConfig struct {
	BufferSize int `json:"buffer_size"`
}

func ClampBufferSize(size int) int {
	const min = 32 * 1024
	const max = 1024 * 1024
	if size < min {
		return min
	}
	if size > max {
		return max
	}
	return size
}

type APIConfig struct {
	ListenAddr        string `json:"listen_addr"`
	WSRefreshInterval int    `json:"ws_refresh_interval"`
	UIConnLimit       int    `json:"ui_conn_limit"`
}

type SystemConfig struct {
	TProxyPort          int `json:"tproxy_port"`
	ConnTrackGCInterval int `json:"conn_track_gc_interval"`
	ConnTrackTTL        int `json:"conn_track_ttl"`
}

type OutboundConfig struct {
	Servers []Server `json:"servers"`
}

type Server struct {
	Tag      string `json:"tag"`
	Type     string `json:"type"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

func DefaultConfig() *Config {
	return &Config{
		API: APIConfig{ListenAddr: "127.0.0.1:8080", WSRefreshInterval: 2, UIConnLimit: 50},
		Outbounds: OutboundConfig{Servers: []Server{{Tag: "proxy", Type: "socks5", Address: "127.0.0.1", Port: 9192}}},
		Performance: PerformanceConfig{BufferSize: 64 * 1024},
		System: SystemConfig{TProxyPort: 7893, ConnTrackGCInterval: 15, ConnTrackTTL: 30},
		ProcessWhitelist: []string{},
	}
}

func (c *Config) UnmarshalJSON(data []byte) error {
	type current Config
	var raw struct {
		*current
		Performance *struct {
			BufferSize int `json:"buffer_size"`
		} `json:"performance"`
	}
	raw.current = (*current)(c)
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	d := DefaultConfig()
	if c.API.ListenAddr == "" {
		c.API.ListenAddr = d.API.ListenAddr
	}
	if c.API.WSRefreshInterval <= 0 {
		c.API.WSRefreshInterval = d.API.WSRefreshInterval
	}
	if c.API.UIConnLimit <= 0 {
		c.API.UIConnLimit = d.API.UIConnLimit
	}
	if c.System.TProxyPort == 0 {
		c.System = d.System
	} else {
		if c.System.ConnTrackGCInterval <= 0 {
			c.System.ConnTrackGCInterval = d.System.ConnTrackGCInterval
		}
		if c.System.ConnTrackTTL <= 0 {
			c.System.ConnTrackTTL = d.System.ConnTrackTTL
		}
	}
	if len(c.Outbounds.Servers) == 0 {
		c.Outbounds = d.Outbounds
	}
	if c.Performance.BufferSize == 0 {
		c.Performance.BufferSize = d.Performance.BufferSize
	} else {
		c.Performance.BufferSize = ClampBufferSize(c.Performance.BufferSize)
	}
	if c.ProcessWhitelist == nil {
		c.ProcessWhitelist = []string{}
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

// Save 先写临时文件再原子替换，避免进程被杀/断电时留下半个 config.json
// （半截 JSON 会在下次启动被当成"损坏配置"）。
func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
