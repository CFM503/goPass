package engine

// 规则文件在线更新：从配置的 URL 下载 geosite/geoip 规则文件并热重载。
// 支持进度跟踪（供前端轮询进度条）。

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// RuleUpdateResult 更新结果（供 API POST 返回）。
type RuleUpdateResult struct {
	GeoSite   string `json:"geosite"`
	GeoIP     string `json:"geoip"`
	GeoSiteOK bool   `json:"geosite_ok"`
	GeoIPOK   bool   `json:"geoip_ok"`
	UpdatedAt string `json:"updated_at"`
	Error     string `json:"error,omitempty"`
}

// DownloadState 单个规则文件的下载进度。
type DownloadState struct {
	URL   string `json:"url"`
	Total int64  `json:"total"` // -1 = 未知（无法获取 Content-Length）
	Done  int64  `json:"done"`
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

// UpdateTracker 规则文件在线更新的进度跟踪器（线程安全，供 API GET 轮询）。
type UpdateTracker struct {
	mu        sync.Mutex
	Status    string        `json:"status"` // idle | running | done | error
	GeoSite   DownloadState `json:"geosite"`
	GeoIP     DownloadState `json:"geoip"`
	UpdatedAt string        `json:"updated_at"`
}

// NewUpdateTracker 创建进度跟踪器。
func NewUpdateTracker() *UpdateTracker {
	return &UpdateTracker{Status: "idle"}
}

// Begin 尝试开始一次更新；已在更新中则返回 false。
func (t *UpdateTracker) Begin() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Status == "running" {
		return false
	}
	t.Status = "running"
	t.GeoSite = DownloadState{Total: -1}
	t.GeoIP = DownloadState{Total: -1}
	t.UpdatedAt = nowStr()
	return true
}

// Progress 更新单个文件的下载进度。
func (t *UpdateTracker) Progress(name string, done, total int64) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	st := &t.GeoSite
	if name == "geoip" {
		st = &t.GeoIP
	}
	st.Done = done
	st.Total = total
}

// FileDone 标记单个文件下载完成/失败。
func (t *UpdateTracker) FileDone(name, url string, ok bool, errStr string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	st := &t.GeoSite
	if name == "geoip" {
		st = &t.GeoIP
	}
	st.URL = url
	st.OK = ok
	st.Error = errStr
}

// Finish 结束一次更新。
func (t *UpdateTracker) Finish(ok bool) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if ok {
		t.Status = "done"
	} else {
		t.Status = "error"
	}
}

// Snapshot 返回当前进度的线程安全快照。
func (t *UpdateTracker) Snapshot() UpdateTracker {
	if t == nil {
		return UpdateTracker{Status: "idle"}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return UpdateTracker{
		Status:    t.Status,
		GeoSite:   t.GeoSite,
		GeoIP:     t.GeoIP,
		UpdatedAt: t.UpdatedAt,
	}
}

// UpdateRuleFiles 下载 geosite/geoip 规则文件到本地路径。
// 任一 URL 为空则跳过对应文件。tracker 可为 nil（无进度上报）。
func UpdateRuleFiles(geositeURL, geositePath, geoipURL, geoipPath string, tracker *UpdateTracker) *RuleUpdateResult {
	res := &RuleUpdateResult{UpdatedAt: nowStr()}
	client := &http.Client{Timeout: 180 * time.Second}
	var errs []string

	if geositeURL != "" && geositePath != "" {
		res.GeoSite = geositePath
		if err := downloadFile(client, geositeURL, geositePath, "geosite", tracker); err != nil {
			errs = append(errs, fmt.Sprintf("geosite %s: %v", geositeURL, err))
			if tracker != nil {
				tracker.FileDone("geosite", geositeURL, false, err.Error())
			}
		} else {
			res.GeoSiteOK = true
			if tracker != nil {
				tracker.FileDone("geosite", geositeURL, true, "")
			}
			log.Printf("[RuleUpdate] ✅ 已更新 geosite 规则: %s -> %s", geositeURL, geositePath)
		}
	}

	if geoipURL != "" && geoipPath != "" {
		res.GeoIP = geoipPath
		if err := downloadFile(client, geoipURL, geoipPath, "geoip", tracker); err != nil {
			errs = append(errs, fmt.Sprintf("geoip %s: %v", geoipURL, err))
			if tracker != nil {
				tracker.FileDone("geoip", geoipURL, false, err.Error())
			}
		} else {
			res.GeoIPOK = true
			if tracker != nil {
				tracker.FileDone("geoip", geoipURL, true, "")
			}
			log.Printf("[RuleUpdate] ✅ 已更新 geoip 规则: %s -> %s", geoipURL, geoipPath)
		}
	}

	if tracker != nil {
		tracker.Finish(len(errs) == 0)
	}

	if len(errs) > 0 {
		res.Error = strings.Join(errs, "; ")
	}
	return res
}

// downloadFile 下载文件（先写临时文件再原子替换），带进度上报。
func downloadFile(client *http.Client, url, path, name string, tracker *UpdateTracker) error {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	total := int64(-1)
	if resp.ContentLength > 0 {
		total = resp.ContentLength
	}
	if tracker != nil {
		tracker.Progress(name, 0, total)
	}

	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}

	buf := make([]byte, 64*1024)
	var done int64
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				f.Close()
				os.Remove(tmp)
				return werr
			}
			done += int64(n)
			if tracker != nil {
				tracker.Progress(name, done, total)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			os.Remove(tmp)
			return rerr
		}
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
