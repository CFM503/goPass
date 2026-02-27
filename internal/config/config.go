package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	API      APIConfig      `json:"api"`
	DNS      DNSConfig      `json:"dns"`
	Routing  RoutingConfig  `json:"routing"`
	Outbound OutboundConfig `json:"outbound"`
}

type APIConfig struct {
	ListenAddr        string `json:"listen_addr"`
	WSRefreshInterval int    `json:"ws_refresh_interval"`
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
			WSRefreshInterval: 1,
		},
		DNS: DNSConfig{
			ListenAddr:  "127.0.0.1:53",
			FakeIPRange: "198.18.0.0/16",
		},
		Routing: RoutingConfig{
			Mode: "whitelist",
			Rules: []Rule{
				{
					Type:     "process",
					Payload:  "curl.exe",
					Outbound: "proxy",
				},
			},
		},
		Outbound: OutboundConfig{
			Servers: []Server{
				{Tag: "proxy", Type: "socks5", Address: "127.0.0.1", Port: 9192},
				{Tag: "direct", Type: "direct"},
			},
		},
	}
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
