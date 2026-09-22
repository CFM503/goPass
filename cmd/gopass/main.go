package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/CFM503/goPass/internal/api"
	"github.com/CFM503/goPass/internal/config"
	"github.com/CFM503/goPass/internal/engine"
	"github.com/CFM503/goPass/internal/singleton"
	"github.com/CFM503/goPass/internal/version"
)

func main() {
	configFile := flag.String("config", "config.json", "path to config file")
	flag.Parse()

	// 必须在 CleanUpDependencies 之前：单实例锁保证第二个实例不会
	// 停掉/删掉第一个实例正在使用的 WinDivert 驱动服务。
	if err := singleton.Acquire(); err != nil {
		if errors.Is(err, singleton.ErrAlreadyRunning) {
			fmt.Println("检测到 GoPass 已在运行，本实例退出。")
			fmt.Println("（重复启动会打断正在代理的连接，请勿多开。）")
			fmt.Println()
			fmt.Println("按 Enter 退出...")
			_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
			os.Exit(1)
		}
		log.Printf("单实例检查失败（继续启动）: %v", err)
	}

	fmt.Println("=== GoPass 透明代理 ===")
	fmt.Printf("Version: %s\n", version.Version)
	fmt.Printf("PID: %d\n\n", os.Getpid())

	engine.CleanUpDependencies()

	cfg, err := config.Load(*configFile)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		log.Printf("配置文件 '%s' 不存在，自动生成默认配置...", *configFile)
		cfg = config.DefaultConfig()
		if saveErr := cfg.Save(*configFile); saveErr != nil {
			log.Printf("保存默认配置失败: %v", saveErr)
		} else {
			log.Printf("已保存默认配置到 %s", *configFile)
		}
	default:
		// 旧版本把这里当成"文件不存在"直接覆盖，会静默丢掉白名单。
		cfg = config.DefaultConfig()
		log.Printf("配置文件 '%s' 无法解析: %v", *configFile, err)
		if fi, statErr := os.Stat(*configFile); statErr == nil && fi.IsDir() {
			log.Fatalf("配置路径 '%s' 是一个目录", *configFile)
		}
		backup := *configFile + ".corrupt"
		if renErr := os.Rename(*configFile, backup); renErr != nil {
			log.Printf("备份失败(%v)：不会覆盖原文件，本次以内存中的默认配置运行。", renErr)
		} else {
			log.Printf("已把损坏的配置备份到 %s", backup)
			if saveErr := cfg.Save(*configFile); saveErr != nil {
				log.Printf("保存默认配置失败: %v", saveErr)
			} else {
				log.Printf("已保存默认配置到 %s（白名单已清空，请重新添加）", *configFile)
			}
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
		if err := api.StartServer(cfg.API.ListenAddr, eng, *configFile); err != nil { log.Printf("API 服务器错误: %v", err) }
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	log.Println("\n正在停止 GoPass...")
	eng.Stop()
	log.Println("已退出。")
}
