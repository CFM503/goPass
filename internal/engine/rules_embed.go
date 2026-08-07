package engine

// 内置分流规则（编译进二进制，开箱即用，无需手动下载规则文件）。
//
// 生成自 v2fly 官方 geosite.dat / geoip.dat 的 CN 分类，转为紧凑纯文本格式：
//   - geosite-cn.txt：geosite:cn 域名规则（suffix / full: / keyword: / regexp:）
//   - geoip-cn.txt：geoip:cn IPv4 网段（每行一个 CIDR）
//
// 加载优先级：磁盘上的 rule_files 存在时优先使用磁盘文件（可在线更新 / 自定义），
// 磁盘文件缺失时自动回退到内置规则。删除磁盘文件即恢复内置版本。
//
// 重新生成：先运行 .tools\download.ps1 获取最新 .dat，再执行
//
//	go test -tags genrules -run TestGenEmbeddedRules ./internal/engine/

import _ "embed"

//go:embed rules/geosite-cn.txt
var embeddedGeoSite []byte

//go:embed rules/geoip-cn.txt
var embeddedGeoIP []byte
