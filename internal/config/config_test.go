package config

import (
	"encoding/json"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	c := DefaultConfig()
	if c.Performance.BufferSize != 256*1024 {
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
		{256 * 1024, 256 * 1024}, {512 * 1024, 512 * 1024},
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
