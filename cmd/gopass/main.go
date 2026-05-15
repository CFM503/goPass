package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/yourusername/gopass/internal/api"
	"github.com/yourusername/gopass/internal/config"
	"github.com/yourusername/gopass/internal/engine"
	"github.com/yourusername/gopass/internal/process"
	"github.com/yourusername/gopass/internal/tray"
)

func main() {
	configFile := flag.String("config", "config.json", "path to config file")
	flag.Parse()

	fmt.Println("=== GoPass 透明代理 ===")
	fmt.Println("Version: v1.3.5")
	fmt.Printf("PID: %d\n\n", os.Getpid())

	// Load Configuration
	cfg, err := config.Load(*configFile)
	if err != nil {
		log.Printf("配置文件 '%s' 不存在，自动生成默认配置...", *configFile)
		cfg = config.DefaultConfig()
		if saveErr := cfg.Save(*configFile); saveErr != nil {
			log.Printf("保存默认配置失败: %v", saveErr)
		} else {
			log.Printf("已保存默认配置到 %s", *configFile)
		}
	}

	// [v1.3.1 Config] 根据配置启动进程缓存与网络连接缓存守护
	process.InitProcessCache(cfg.System.ProcessCacheRefreshInterval)
	process.InitNetstatCache(cfg.System.NetstatCacheRefreshInterval)

	// Init Engine
	eng, err := engine.New(cfg)
	if err != nil {
		log.Fatalf("引擎初始化失败: %v", err)
	}

	// Start API & Web UI server (in background)
	go func() {
		log.Printf("Web 控制台: http://%s", cfg.API.ListenAddr)
		if err := api.StartServer(cfg.API.ListenAddr, eng); err != nil {
			log.Printf("API 服务器错误: %v", err)
		}
	}()

	// Start transparent proxy engine
	if err := eng.Start(); err != nil {
		log.Fatalf("引擎启动失败: %v", err)
	}

	// Start system tray icon in background
	trayQuit := make(chan struct{})
	go func() {
		go tray.Setup(cfg.API.ListenAddr)
		<-trayQuit
		tray.RemoveTray()
	}()

	// 阻塞直到 Ctrl+C / SIGTERM
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	log.Println("\n正在停止 GoPass...")
	tray.RemoveTray()
	close(trayQuit)
	eng.Stop()
	log.Println("已退出。")
}
