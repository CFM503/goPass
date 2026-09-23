package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
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

// v1.8.3 删除 api.ws_refresh_interval 与 api.ui_conn_limit 的回归守卫。
//
// 这两个字段从来没有读者：设置页拉取的 /api/settings 路由从来不存在，写入它们的
// UpdateUIConfig 零调用方，状态页轮询间隔实为 JS 里写死的 3 秒。把它们留在 schema
// 里只会让用户以为改这两项有效。要求是：旧配置文件带同名键必须照常加载
// （encoding/json 忽略未知键，所以无需迁移），重新保存时不再写回去，
// 同段的 listen_addr 则必须毫发无损地保留下来。
func TestRemovedAPISettingsAreNotSerialized(t *testing.T) {
	legacy := `{"api":{"listen_addr":"127.0.0.1:9999","ws_refresh_interval":7,"ui_conn_limit":123}}`
	var c Config
	if err := json.Unmarshal([]byte(legacy), &c); err != nil {
		t.Fatal(err)
	}
	// 对照：同段里仍然存在的字段不能被误伤
	if c.API.ListenAddr != "127.0.0.1:9999" {
		t.Fatalf("api.listen_addr must still load, got %q", c.API.ListenAddr)
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	api, ok := out["api"].(map[string]interface{})
	if !ok {
		t.Fatalf("api section missing from %s", data)
	}
	if _, ok := api["listen_addr"]; !ok {
		t.Fatalf("api.listen_addr must still be serialized, got %v", api)
	}
	for _, key := range []string{"ws_refresh_interval", "ui_conn_limit"} {
		if _, ok := api[key]; ok {
			t.Fatalf("api.%s must not be serialized", key)
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
	// 临时文件名带随机后缀，残留要按通配符查——固定名 path+".tmp" 已经查不到了
	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(path), "*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("temp file left behind: %v", leftovers)
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

// Save 的失败路径必须把错误如实返回，并且绝不留下 .tmp 残留。
// 调用方（engine.SaveConfig）是 `_ =` 吞掉错误的，这里再不返回就彻底没救了——
// 表现成"界面提示保存成功、其实没存上"，正是 B4 要消除的那类静默失败。
func TestSaveFailuresSurfaceAndCleanUp(t *testing.T) {
	c := DefaultConfig()
	c.ProcessWhitelist = []string{"chrome.exe"}

	// 目录不存在 → 建临时文件那一步就失败
	if err := c.Save(filepath.Join(t.TempDir(), "missing-dir", "config.json")); err == nil {
		t.Fatal("saving into a missing directory must fail")
	}

	// 目标已被一个目录占住 → 替换那一步失败，此时必须把刚建的临时文件清掉
	dir := t.TempDir()
	target := filepath.Join(dir, "occupied")
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatal(err)
	}
	if err := c.Save(target); err == nil {
		t.Fatal("renaming a file over a directory must fail")
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("failed Save left temp file behind: %v", leftovers)
	}
}

// 并发保存不能共用同一个 .tmp（B4 回归）。
//
// 固定用 path+".tmp" 时，N 个并发 Save 会往同一个文件里 WriteFile：一方截断、
// 另一方按自己的偏移写，长度不一致就拼出杂交内容；而且前一个 rename 把 .tmp 移走
// 之后，后到的那个 rename 源文件已不存在，直接报错。两条路径的结果都是"界面提示
// 保存成功、config.json 却坏了"，下次启动按损坏配置处理、白名单被清空。
//
// 每个写入者的白名单长度都不同：只有长度不同才可能拼出杂交内容，
// 这样"内容必须完整等于某个写入者的版本"这条断言才真的有判别力。
func TestConcurrentSavesDoNotCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	const writers = 16

	errs := make([]error, writers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			c := DefaultConfig()
			for j := 0; j <= i; j++ {
				c.ProcessWhitelist = append(c.ProcessWhitelist, fmt.Sprintf("proc%02d.exe", j))
			}
			errs[i] = c.Save(path)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("save #%d failed: %v", i, err)
		}
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("config corrupted by concurrent saves: %v", err)
	}
	// 内容必须是某个写入者的完整版本：proc00..procNN 且长度落在 1..writers 之内。
	if n := len(got.ProcessWhitelist); n < 1 || n > writers {
		t.Fatalf("whitelist length %d outside 1..%d: %v", n, writers, got.ProcessWhitelist)
	}
	for j, name := range got.ProcessWhitelist {
		if want := fmt.Sprintf("proc%02d.exe", j); name != want {
			t.Fatalf("config corrupted: entry %d=%q, want %q (full list %v)", j, name, want, got.ProcessWhitelist)
		}
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

// B1 回归：raw 里若声明一个同名 performance 字段，它会因深度更浅而遮蔽内嵌的
// current.Performance，JSON 值落进显式字段、UnmarshalJSON 却读 c.Performance，
// 导致 config.json 里的 buffer_size 被静默丢弃并回落到默认 64KB（用户看到的现象
// 是“设置页保存成功、重启后失效”）。
func TestPerformanceBufferSizeSurvivesLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"performance":{"buffer_size":123456}}`), 0644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Performance.BufferSize != 123456 {
		t.Fatalf("buffer_size=%d, want 123456 (config.json 的值被丢弃)", c.Performance.BufferSize)
	}
}

func TestPerformanceBufferSizeDefaultAndClamp(t *testing.T) {
	// 缺省时才回落默认值。
	absent := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(absent, []byte(`{"api":{}}`), 0644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(absent)
	if err != nil {
		t.Fatal(err)
	}
	if c.Performance.BufferSize != 64*1024 {
		t.Fatalf("absent buffer_size=%d, want 65536", c.Performance.BufferSize)
	}

	// 有值时必须 clamp，而不是被当成 0 走“取默认”分支。
	for _, tc := range []struct {
		json string
		want int
	}{
		{`{"performance":{"buffer_size":1024}}`, 32 * 1024},
		{`{"performance":{"buffer_size":2097152}}`, 1024 * 1024},
	} {
		path := filepath.Join(t.TempDir(), "config.json") // 每次都是新的唯一目录
		if err := os.WriteFile(path, []byte(tc.json), 0644); err != nil {
			t.Fatal(err)
		}
		got, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if got.Performance.BufferSize != tc.want {
			t.Errorf("%s -> buffer_size=%d, want %d", tc.json, got.Performance.BufferSize, tc.want)
		}
	}
}
