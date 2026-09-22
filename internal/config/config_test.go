package config

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	c := DefaultConfig()
	if c.Performance.BufferSize != 64*1024 {
		t.Fatalf("default BufferSize=%d", c.Performance.BufferSize)
	}
	if len(c.Outbounds.Servers) != 1 || c.Outbounds.Servers[0].Type != "socks5" || c.Outbounds.Servers[0].Port != 9192 {
		t.Fatalf("upstream defaults=%+v", c.Outbounds.Servers)
	}
	if c.System.TProxyPort != 7893 {
		t.Fatalf("tproxy port=%d", c.System.TProxyPort)
	}
	if len(c.ProcessWhitelist) != 0 {
		t.Fatal("default process whitelist must be empty")
	}
}

func TestClampBufferSize(t *testing.T) {
	tests := []struct{ in, want int }{
		{0, 32768}, {-1, 32768}, {32767, 32768}, {32768, 32768},
		{64 * 1024, 64 * 1024}, {256 * 1024, 256 * 1024}, {512 * 1024, 512 * 1024},
		{1024 * 1024, 1024 * 1024}, {1024*1024 + 1, 1024 * 1024},
		{2 * 1024 * 1024, 1024 * 1024},
	}
	for _, tt := range tests {
		if got := ClampBufferSize(tt.in); got != tt.want {
			t.Errorf("ClampBufferSize(%d)=%d want %d", tt.in, got, tt.want)
		}
	}
}

func TestRemovedRoutingConfigIsNotSerialized(t *testing.T) {
	legacy := `{"split":{"enabled":true},"routing":{"mode":"global"},"automatic_route":{"enabled":true},"api":{},"system":{}}`
	var c Config
	if err := json.Unmarshal([]byte(legacy), &c); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"split", "routing", "automatic_route"} {
		if _, ok := out[key]; ok {
			t.Fatalf("%s must not be serialized", key)
		}
	}
}

// Save 必须原子替换：不留 .tmp 残留，且覆盖后内容完整。
func TestSaveIsAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c := DefaultConfig()
	c.ProcessWhitelist = []string{"chrome.exe"}
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("temp file left behind: %v", err)
	}
	// 再存一次（覆盖已存在文件）也必须成功
	c.ProcessWhitelist = []string{"chrome.exe", "a.exe"}
	if err := c.Save(path); err != nil {
		t.Fatalf("overwrite save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.ProcessWhitelist) != 2 {
		t.Fatalf("whitelist=%v", got.ProcessWhitelist)
	}
}

// 区分"文件不存在"与"JSON 损坏"：前者自动创建，后者必须报错（由上层备份）。
func TestLoadErrorKinds(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "nope.json")
	if _, err := Load(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing file err=%v, want fs.ErrNotExist", err)
	}

	corrupt := filepath.Join(dir, "config.json")
	if err := os.WriteFile(corrupt, []byte(`{"api": {`), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(corrupt)
	if err == nil {
		t.Fatal("corrupt config should fail")
	}
	if errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("corrupt config must NOT be reported as not-exist: %v", err)
	}
}

func TestProcessWhitelistRoundTrip(t *testing.T) {
	c := DefaultConfig()
	c.ProcessWhitelist = []string{"chrome.exe", "BigEyesTV.exe"}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var c2 Config
	if err := json.Unmarshal(data, &c2); err != nil {
		t.Fatal(err)
	}
	if len(c2.ProcessWhitelist) != 2 || c2.ProcessWhitelist[0] != "chrome.exe" {
		t.Fatalf("whitelist roundtrip failed: %v", c2.ProcessWhitelist)
	}
}
