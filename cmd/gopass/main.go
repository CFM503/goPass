package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/CFM503/goPass/internal/api"
	"github.com/CFM503/goPass/internal/config"
	"github.com/CFM503/goPass/internal/engine"
	"github.com/CFM503/goPass/internal/version"
)

func main() {
	configFile := flag.String("config", "config.json", "path to config file")
	flag.Parse()

	fmt.Println("=== GoPass 透明代理 ===")
	fmt.Printf("Version: %s\n", version.Version)
	fmt.Printf("PID: %d\n\n", os.Getpid())

	engine.CleanUpDependencies()

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

	eng, err := engine.New(cfg)
	if err != nil { log.Fatalf("引擎初始化失败: %v", err) }

	if err := eng.Start(); err != nil {
		log.Printf("启动检查失败：%v", err)
		fmt.Println()
		fmt.Println("GoPass 未启动透明代理，也未启动 Web 控制台。")
		fmt.Println("请根据上面的错误信息修复环境后重新运行。")
		fmt.Println("按 Enter 退出；输入 q 后按 Enter 立即退出。")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(line) == "q" { os.Exit(1) }
		os.Exit(1)
	}

	go func() {
		log.Printf("Web 控制台: http://%s", cfg.API.ListenAddr)
		if err := api.StartServer(cfg.API.ListenAddr, eng); err != nil { log.Printf("API 服务器错误: %v", err) }
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	log.Println("\n正在停止 GoPass...")
	eng.Stop()
	log.Println("已退出。")
}
