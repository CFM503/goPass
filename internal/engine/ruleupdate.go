package engine

// 规则文件在线更新：从配置的 URL 下载 geosite/geoip 规则文件并热重载。

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RuleUpdateResult 更新结果（供 API 返回）。
type RuleUpdateResult struct {
	GeoSite   string `json:"geosite"`
	GeoIP     string `json:"geoip"`
	GeoSiteOK bool   `json:"geosite_ok"`
	GeoIPOK   bool   `json:"geoip_ok"`
	UpdatedAt string `json:"updated_at"`
	Error     string `json:"error,omitempty"`
}

// UpdateRuleFiles 下载 geosite/geoip 规则文件到本地路径。
// 任一 URL 为空则跳过对应文件。
func UpdateRuleFiles(geositeURL, geositePath, geoipURL, geoipPath string) *RuleUpdateResult {
	res := &RuleUpdateResult{UpdatedAt: nowStr()}
	client := &http.Client{Timeout: 180 * time.Second}
	var errs []string

	if geositeURL != "" && geositePath != "" {
		res.GeoSite = geositePath
		if err := downloadFile(client, geositeURL, geositePath); err != nil {
			errs = append(errs, fmt.Sprintf("geosite %s: %v", geositeURL, err))
		} else {
			res.GeoSiteOK = true
			log.Printf("[RuleUpdate] ✅ 已更新 geosite 规则: %s -> %s", geositeURL, geositePath)
		}
	}

	if geoipURL != "" && geoipPath != "" {
		res.GeoIP = geoipPath
		if err := downloadFile(client, geoipURL, geoipPath); err != nil {
			errs = append(errs, fmt.Sprintf("geoip %s: %v", geoipURL, err))
		} else {
			res.GeoIPOK = true
			log.Printf("[RuleUpdate] ✅ 已更新 geoip 规则: %s -> %s", geoipURL, geoipPath)
		}
	}

	if len(errs) > 0 {
		res.Error = strings.Join(errs, "; ")
	}
	return res
}

// downloadFile 下载文件（先写临时文件再原子替换）。
func downloadFile(client *http.Client, url, path string) error {
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

	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, resp.Body)
	f.Close()
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
