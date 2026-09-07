package config

import (
	"encoding/json"
	"testing"
)

func TestDefaultConfigSplit(t *testing.T) {
	c := DefaultConfig()
	r := c.Split.Resolve()
	if !r.Enabled {
		t.Error("默认配置应开启分流")
	}
	if r.Mode != "both" {
		t.Errorf("默认模式 = %s, want both", r.Mode)
	}
	if !r.BlockIPv6 {
		t.Error("默认应屏蔽 IPv6")
	}
	if !r.ForeignProxy {
		t.Error("默认应强制国外走代理")
	}
	if r.DNSRelayPort != 5300 {
		t.Errorf("默认 DNS 中继端口 = %d, want 5300", r.DNSRelayPort)
	}
	if r.DoTServer != "1.1.1.1:853" {
		t.Errorf("默认 DoT 服务器 = %s", r.DoTServer)
	}
}

func TestSplitResolveDefaults(t *testing.T) {
	// 旧版 config.json（无 split 块）-> 分流保持关闭（不改变旧行为）
	old := `{"api":{},"system":{}}`
	var c Config
	if err := json.Unmarshal([]byte(old), &c); err != nil {
		t.Fatal(err)
	}
	r := c.Split.Resolve()
	if r.Enabled {
		t.Error("旧配置无 split 块时 Enabled 应为 false")
	}
	if !r.BlockIPv6 {
		t.Error("旧配置下 BlockIPv6 应默认 true（保持原有 IPv6 拦截）")
	}

	// 显式开启 + 显式关闭 block_ipv6
	withSplit := `{"split":{"enabled":true,"mode":"geo","block_ipv6":false}}`
	var c2 Config
	if err := json.Unmarshal([]byte(withSplit), &c2); err != nil {
		t.Fatal(err)
	}
	r2 := c2.Split.Resolve()
	if !r2.Enabled || r2.Mode != "geo" {
		t.Errorf("解析失败: %+v", r2)
	}
	if r2.BlockIPv6 {
		t.Error("显式 block_ipv6=false 应被保留")
	}
	if r2.CNDirect != true || r2.ForeignProxy != true {
		t.Error("未显式配置的 cn_direct/foreign_proxy 应默认 true")
	}
	if r2.GeoPriority != true {
		t.Error("geo_priority 应默认 true")
	}
	if r2.DNSRelayPort != 5300 {
		t.Errorf("DNSRelayPort 应默认 5300, got %d", r2.DNSRelayPort)
	}
}

func TestSplitSaveRoundTrip(t *testing.T) {
	c := DefaultConfig()
	c.Split.Enabled = boolPtr(false)
	c.Split.CustomDirect = []string{"example.com", "1.2.3.0/24"}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var c2 Config
	if err := json.Unmarshal(data, &c2); err != nil {
		t.Fatal(err)
	}
	if c2.Split.Enabled == nil || *c2.Split.Enabled != false {
		t.Error("enabled=false 应保留")
	}
	if len(c2.Split.CustomDirect) != 2 {
		t.Errorf("custom_direct 未保留: %v", c2.Split.CustomDirect)
	}
}

func TestNormalizeSplitPartial(t *testing.T) {
	// 模拟 Web UI 仅提交部分字段（无 update_urls / dns 配置）
	partial := SplitConfig{Enabled: boolPtr(true), Mode: "geo", BlockIPv6: boolPtr(false)}
	n := NormalizeSplit(partial)
	if n.UpdateURLs.GeoSite == "" || n.UpdateURLs.GeoIP == "" {
		t.Error("update_urls 应填充默认值")
	}
	if n.DNSRelayPort != 5300 {
		t.Errorf("dns_relay_port 应默认 5300, got %d", n.DNSRelayPort)
	}
	if n.DoTServer != "1.1.1.1:853" {
		t.Errorf("dot_server 应默认 1.1.1.1:853, got %q", n.DoTServer)
	}
	if n.BlockForeignUDP == nil || !*n.BlockForeignUDP {
		t.Error("block_foreign_udp 应默认 true")
	}
	if n.RuleFiles.GeoSite != "geosite.dat" || n.RuleFiles.GeoIP != "geoip.dat" {
		t.Errorf("rule_files 应默认 geosite.dat/geoip.dat, got %+v", n.RuleFiles)
	}
}

func TestAutomaticRouteConfigDefaults(t *testing.T) {
	c := DefaultConfig()
	if c.AutomaticRoute.CheckInterval != 5 {
		t.Errorf("CheckInterval = %d, want 5", c.AutomaticRoute.CheckInterval)
	}
	if c.AutomaticRoute.SwitchThreshold != 5.0 {
		t.Errorf("SwitchThreshold = %f, want 5.0", c.AutomaticRoute.SwitchThreshold)
	}
	if c.AutomaticRoute.FailureThreshold != 3 {
		t.Errorf("FailureThreshold = %d, want 3", c.AutomaticRoute.FailureThreshold)
	}
	if c.AutomaticRoute.RecoveryThreshold != 3 {
		t.Errorf("RecoveryThreshold = %d, want 3", c.AutomaticRoute.RecoveryThreshold)
	}
	if len(c.AutomaticRoute.Routes) == 0 {
		t.Error("默认应该包含至少 1 条初始线路")
	}

	// 测试旧版配置反序列化（无 automatic_route 块时自动填充默认值）
	old := `{"api":{},"system":{}}`
	var c2 Config
	if err := json.Unmarshal([]byte(old), &c2); err != nil {
		t.Fatal(err)
	}
	if c2.AutomaticRoute.CheckInterval != 5 {
		t.Errorf("c2.AutomaticRoute.CheckInterval = %d, want 5", c2.AutomaticRoute.CheckInterval)
	}
	if c2.AutomaticRoute.StandbyCount != 3 {
		t.Errorf("c2.AutomaticRoute.StandbyCount = %d, want 3", c2.AutomaticRoute.StandbyCount)
	}
}

