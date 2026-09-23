package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// saveMu 串行化整个 Save 过程（建临时文件 → 写入 → 替换）。
//
// 只把临时文件名做成随机还不够：Windows 的 MoveFileEx 在两个调用同时替换同一个
// 目标时会有一方拿到 ERROR_ACCESS_DENIED，那一方的保存就丢了——而调用方
// （engine.SaveConfig）是 `_ =` 吞掉错误的，表现成"界面提示保存成功、其实没存上"。
// 串行之后替换永不重叠，后一个照常覆盖前一个，两边都成功。
// 锁序恒为 cfgMu → saveMu（Save 不取 cfgMu），不会反向。
var saveMu sync.Mutex

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
	ListenAddr string `json:"listen_addr"`
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
		API: APIConfig{ListenAddr: "127.0.0.1:8080"},
		Outbounds: OutboundConfig{Servers: []Server{{Tag: "proxy", Type: "socks5", Address: "127.0.0.1", Port: 9192}}},
		Performance: PerformanceConfig{BufferSize: 64 * 1024},
		System: SystemConfig{TProxyPort: 7893, ConnTrackGCInterval: 15, ConnTrackTTL: 30},
		ProcessWhitelist: []string{},
	}
}

func (c *Config) UnmarshalJSON(data []byte) error {
	type current Config
	// raw 只能内嵌 *current：一旦再声明一个显式 performance 字段，它会因"字段深度更浅"
	// 而遮蔽内嵌的 current.Performance——JSON 值落进显式字段，下面却读 c.Performance，
	// 结果 config.json 里的 buffer_size 被静默丢弃、永远回落到默认 64KB。
	var raw struct {
		*current
	}
	raw.current = (*current)(c)
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	d := DefaultConfig()
	if c.API.ListenAddr == "" {
		c.API.ListenAddr = d.API.ListenAddr
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
//
// 临时文件名必须每次不同。固定用 path+".tmp" 时，两个并发保存会往同一个文件里
// WriteFile：一方截断、另一方按自己的偏移写，长度不一致就拼出杂交内容；而且前一个
// rename 把 .tmp 移走之后，后到的那个 rename 源文件已不存在，直接报错。两条路径的
// 结果都是"界面上保存成功、config.json 却坏了"，下次启动按损坏处理、白名单被清空。
// CreateTemp 给出随机后缀，各方写完各自原子替换，后写者赢，两边看到的都是完整内容。
func (c *Config) Save(path string) error {
	saveMu.Lock()
	defer saveMu.Unlock()
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	dir, base := filepath.Split(path)
	f, err := os.CreateTemp(dir, base+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	// CreateTemp 默认 0600，这里显式还原成原先 WriteFile 用的 0644，免得行为跟着变。
	_ = os.Chmod(tmp, 0644)
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
