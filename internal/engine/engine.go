package engine

import (
	"fmt"
	"log"
	"os"

	"github.com/yourusername/gopass/internal/config"
)

// Engine 是 GoPass 透明代理的核心
type Engine struct {
	cfg         *config.Config
	tracker     *ConnTracker
	tproxy      *TProxy
	interceptor *Interceptor

	// 运行时统计（供 API 层读取）
	Stats *Stats
}

// Stats 保存引擎运行状态
type Stats struct {
	PID         int
	Connections int
	RxBytes     int64
	TxBytes     int64
	Active      []map[string]interface{}
}

// New 创建引擎实例
func New(cfg *config.Config) (*Engine, error) {
	return &Engine{
		cfg:     cfg,
		tracker: NewConnTracker(),
		Stats: &Stats{
			PID: os.Getpid(),
		},
	}, nil
}

// Start 启动透明代理内核
func (e *Engine) Start() error {
	log.Printf("[Engine] GoPass 启动，PID=%d", e.Stats.PID)

	// 找到第一个 socks5 代理服务器地址
	socks5Addr := ""
	for _, srv := range e.cfg.Outbound.Servers {
		if srv.Type == "socks5" {
			socks5Addr = fmt.Sprintf("%s:%d", srv.Address, srv.Port)
			break
		}
	}
	if socks5Addr == "" {
		return fmt.Errorf("配置中没有找到 socks5 类型的代理服务器")
	}
	log.Printf("[Engine] 上游 SOCKS5 代理: %s", socks5Addr)

	// 收集进程白名单
	var whitelist []string
	for _, rule := range e.cfg.Routing.Rules {
		if rule.Type == "process" {
			whitelist = append(whitelist, rule.Payload)
		}
	}
	if len(whitelist) == 0 {
		log.Println("[Engine] 警告：配置中没有进程白名单规则，将不拦截任何流量")
	} else {
		log.Printf("[Engine] 进程白名单: %v", whitelist)
	}

	// 解析代理 IP 和端口（用于排除回环）
	proxyHost, proxyPort, err := parseAddr(socks5Addr)
	if err != nil {
		return fmt.Errorf("解析代理地址失败: %w", err)
	}

	// 启动本地透明代理监听器
	tproxy, err := NewTProxy(e.tracker, socks5Addr, e.Stats)
	if err != nil {
		return fmt.Errorf("TProxy 启动失败: %w", err)
	}
	e.tproxy = tproxy
	go tproxy.Accept()

	// 启动 WinDivert 拦截器（纯 Go syscall，无 CGo）
	interceptor := NewInterceptor(e.cfg.Routing.Mode, whitelist, e.tracker, proxyHost, uint16(proxyPort))
	e.interceptor = interceptor
	go interceptor.Start()

	log.Println("[Engine] 所有组件启动完毕，开始透明代理...")
	return nil
}

// Stop 停止引擎
func (e *Engine) Stop() {
	if e.interceptor != nil {
		e.interceptor.Close()
	}
	if e.tproxy != nil {
		e.tproxy.Close()
	}
}

// UpdateMode 更新代理模式并保存配置
func (e *Engine) UpdateMode(mode string, configPath string) error {
	e.cfg.Routing.Mode = mode
	if e.interceptor != nil {
		e.interceptor.SetMode(mode)
	}
	if configPath != "" {
		return e.cfg.Save(configPath)
	}
	return nil
}

// UpdateRules 更新白名单规则并保存配置
func (e *Engine) UpdateRules(rules []config.Rule, configPath string) error {
	e.cfg.Routing.Rules = rules

	// 重新收集进程白名单
	var whitelist []string
	for _, rule := range rules {
		if rule.Type == "process" {
			whitelist = append(whitelist, rule.Payload)
		}
	}

	if e.interceptor != nil {
		e.interceptor.SetWhitelist(whitelist)
	}

	if configPath != "" {
		return e.cfg.Save(configPath)
	}
	return nil
}

// GetConfig 返回当前配置
func (e *Engine) GetConfig() *config.Config {
	return e.cfg
}

func parseAddr(addr string) (string, int, error) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			host := addr[:i]
			var port int
			fmt.Sscanf(addr[i+1:], "%d", &port)
			return host, port, nil
		}
	}
	return "", 0, fmt.Errorf("invalid address: %s", addr)
}
