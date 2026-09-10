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
	BufferSize      int  `json:"buffer_size"`
	TCPNoDelay      bool `json:"tcp_nodelay"`
	TCPKeepAlive    bool `json:"tcp_keep_alive"`
	KeepAlivePeriod int  `json:"keep_alive_period"`
	TCPLinger       int  `json:"tcp_linger"`
}

func ClampBufferSize(size int) int {
	const minBufferSize = 32 * 1024
	const maxBufferSize = 1024 * 1024
	if size < minBufferSize { return minBufferSize }
	if size > maxBufferSize { return maxBufferSize }
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

type OutboundConfig struct { Servers []Server `json:"servers"` }
type Server struct { Tag string `json:"tag"`; Type string `json:"type"`; Address string `json:"address"`; Port int `json:"port"`; Username string `json:"username"`; Password string `json:"password"` }

func DefaultConfig() *Config {
	return &Config{
		API: APIConfig{ListenAddr:"127.0.0.1:8080",WSRefreshInterval:5,UIConnLimit:20},
		Outbounds: OutboundConfig{Servers:[]Server{{Tag:"proxy",Type:"socks5",Address:"127.0.0.1",Port:9192}}},
		Performance: PerformanceConfig{BufferSize:256*1024,TCPNoDelay:true,TCPKeepAlive:true,KeepAlivePeriod:15,TCPLinger:-1},
		System: SystemConfig{TProxyPort:7893,ConnTrackGCInterval:15,ConnTrackTTL:30},
		ProcessWhitelist: []string{},
	}
}

func (c *Config) UnmarshalJSON(data []byte) error {
	type Alias Config
	aux := (*Alias)(c)
	if err := json.Unmarshal(data, aux); err != nil { return err }
	def := DefaultConfig()
	if c.API.ListenAddr=="" { c.API.ListenAddr=def.API.ListenAddr }
	if c.API.WSRefreshInterval<=0 { c.API.WSRefreshInterval=def.API.WSRefreshInterval }
	if c.API.UIConnLimit<=0 { c.API.UIConnLimit=def.API.UIConnLimit }
	if c.System.TProxyPort==0 { c.System=def.System } else {
		if c.System.ConnTrackGCInterval<=0 { c.System.ConnTrackGCInterval=def.System.ConnTrackGCInterval }
		if c.System.ConnTrackTTL<=0 { c.System.ConnTrackTTL=def.System.ConnTrackTTL }
	}
	if c.Performance.BufferSize==0 { c.Performance=def.Performance } else { c.Performance.BufferSize=ClampBufferSize(c.Performance.BufferSize) }
	return nil
}

func Load(path string) (*Config,error) { data,err:=os.ReadFile(path); if err!=nil{return nil,err}; var c Config; if err:=json.Unmarshal(data,&c);err!=nil{return nil,err};return &c,nil }
func (c *Config) Save(path string) error { data,err:=json.MarshalIndent(c,"","  ");if err!=nil{return err};return os.WriteFile(path,data,0644) }
