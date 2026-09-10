# GoPass Changelog

## v1.6.8

- **定位收敛**：GoPass 只负责 Windows 进程白名单 IPv4 TCP 透明劫持与上游代理转发。
- **白名单模式**：只有名单中的程序通过配置的 SOCKS5 / HTTP CONNECT 上游代理。
- **非白名单直连**：其他程序保持 Windows 正常网络路径，不经过 GoPass 上游代理。
- **Web UI 重构**：固定为“状态 / 进程白名单 / 设置”三个页面。
- **实时状态面板**：显示代理程序、直连程序、代理连接、直连连接，以及程序 PID、连接数和目标 IP:端口。
- **TProxy Buffer Size 保留**：设置页提供 32 KB、64 KB、128 KB、256 KB、512 KB、1 MB，默认 256 KB，运行时硬限制 1 MB。
- **其他 TCP 参数固定**：不再向用户开放 TCP NoDelay、Keep-Alive 等高级调优项。
- **删除无关能力**：不提供 GeoIP/GeoSite、域名/IP 分流、DNS Relay/Fake-IP、SNI 路由、UDP/QUIC、自动选路、测速探测、路线评分、多线路或复杂规则。
- **WinDivert 范围**：限定为 IPv4 TCP 网络层透明拦截。
- **版本**：v1.6.8。
