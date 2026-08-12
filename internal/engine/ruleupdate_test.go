package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CFM503/goPass/internal/config"
)

func TestUpdateTracker(t *testing.T) {
	tr := NewUpdateTracker()

	// 初始 idle
	s := tr.Snapshot()
	if s.Status != "idle" {
		t.Fatalf("初始状态 = %s, want idle", s.Status)
	}

	// Begin
	if !tr.Begin() {
		t.Fatal("首次 Begin 应成功")
	}
	if tr.Begin() {
		t.Fatal("重复 Begin 应失败（已在更新中）")
	}

	// 进度上报
	tr.Progress("geosite", 1024, 2048)
	tr.Progress("geoip", 512, -1)
	s = tr.Snapshot()
	if s.Status != "running" {
		t.Fatalf("状态 = %s, want running", s.Status)
	}
	if s.GeoSite.Done != 1024 || s.GeoSite.Total != 2048 {
		t.Errorf("geosite 进度错误: %+v", s.GeoSite)
	}
	if s.GeoIP.Done != 512 || s.GeoIP.Total != -1 {
		t.Errorf("geoip 进度错误: %+v", s.GeoIP)
	}

	// 完成
	tr.FileDone("geosite", "http://x/geosite", true, "")
	tr.FileDone("geoip", "http://x/geoip", false, "connection refused")
	tr.Finish(false)
	s = tr.Snapshot()
	if s.Status != "error" {
		t.Fatalf("状态 = %s, want error", s.Status)
	}
	if !s.GeoSite.OK || s.GeoIP.OK {
		t.Errorf("FileDone 标记错误: geosite ok=%v geoip ok=%v", s.GeoSite.OK, s.GeoIP.OK)
	}
	if s.GeoIP.Error == "" {
		t.Error("geoip 错误信息未保留")
	}

	// 完成后可再次 Begin
	if !tr.Begin() {
		t.Fatal("完成后再 Begin 应成功")
	}
	tr.Finish(true)
	if s := tr.Snapshot(); s.Status != "done" {
		t.Fatalf("状态 = %s, want done", s.Status)
	}
}

func TestResetConfigSavesDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	// 构造一个“脏”配置
	eng := &Engine{
		updateTracker: NewUpdateTracker(),
	}
	router, err := NewRouter(config.ResolvedSplit{}, dir)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	eng.router = router

	// 复位（tproxy/interceptor 为 nil 时只保存配置，不应 panic）
	if err := eng.ResetConfig(cfgPath); err != nil {
		t.Fatalf("ResetConfig: %v", err)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("读取复位后的配置失败: %v", err)
	}
	content := string(data)
	// 默认配置的特征
	for _, want := range []string{
		`"split"`,
		`"enabled": true`,
		`"mode": "both"`,
		`"socks5"`,
		`"chrome.exe"`,
		`"geo_priority": true`,
	} {
		if !containsStr(content, want) {
			t.Errorf("复位后的配置缺少 %s", want)
		}
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
