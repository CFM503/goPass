//go:build genrules

package engine

// 内置规则生成器（仅在显式指定 -tags genrules 时编译）：
//
//	go test -tags genrules -run TestGenEmbeddedRules ./internal/engine/
//
// 从项目根目录 .tools/ 下的 v2fly geosite.dat / geoip.dat 提取 CN 分类，
// 生成紧凑的纯文本规则文件到 internal/engine/rules/（由 //go:embed 编译进二进制）。
// 生成前请先运行 .tools\download.ps1 获取最新 .dat 文件。

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenEmbeddedRules(t *testing.T) {
	base := filepath.Clean(filepath.Join("..", ".."))
	geositePath := filepath.Join(base, ".tools", "geosite.dat")
	geoipPath := filepath.Join(base, ".tools", "geoip.dat")
	outDir := "rules"

	if _, err := os.Stat(geositePath); err != nil {
		t.Fatalf("缺少 %s，请先运行 .tools\\download.ps1", geositePath)
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatal(err)
	}

	// ---- geosite:cn ----
	data, err := os.ReadFile(geositePath)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := parseGeoSiteDat(data)
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	count := 0
	for _, rec := range recs {
		if rec.country != "CN" {
			continue
		}
		for _, d := range rec.domains {
			v := strings.TrimSpace(d.value)
			if v == "" {
				continue
			}
			switch d.typ {
			case 0: // Plain -> 子串
				sb.WriteString("keyword:" + strings.ToLower(v) + "\n")
			case 1: // Regex
				sb.WriteString("regexp:" + v + "\n")
			case 2: // RootDomain -> 后缀
				sb.WriteString(normalizeDomain(v) + "\n")
			case 3: // Full -> 完全
				sb.WriteString("full:" + normalizeDomain(v) + "\n")
			default:
				sb.WriteString(normalizeDomain(v) + "\n")
			}
			count++
		}
	}
	geositeOut := filepath.Join(outDir, "geosite-cn.txt")
	if err := os.WriteFile(geositeOut, []byte(sb.String()), 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("✅ 生成 %s：%d 条域名规则", geositeOut, count)

	// ---- geoip:cn ----
	data2, err := os.ReadFile(geoipPath)
	if err != nil {
		t.Fatal(err)
	}
	recs2, err := parseGeoIPDat(data2)
	if err != nil {
		t.Fatal(err)
	}
	var sb2 strings.Builder
	count2 := 0
	for _, rec := range recs2 {
		if rec.country != "CN" {
			continue
		}
		for _, c := range rec.cidrs {
			v4 := c.ip.To4()
			if v4 == nil {
				continue // 忽略 IPv6 段（拦截层已屏蔽 IPv6）
			}
			sb2.WriteString(fmt.Sprintf("%s/%d\n", v4.String(), c.prefix))
			count2++
		}
	}
	geoipOut := filepath.Join(outDir, "geoip-cn.txt")
	if err := os.WriteFile(geoipOut, []byte(sb2.String()), 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("✅ 生成 %s：%d 条 IPv4 网段", geoipOut, count2)

	if count == 0 || count2 == 0 {
		t.Fatal("生成结果为空")
	}
}
