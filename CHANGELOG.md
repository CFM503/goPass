# GoPass Changelog

## v1.7.1

- **恢复新连接启动检查**：恢复 v1.6.3 的 TCP 进程实时回查机制。后台 TCP 表缓存未命中新连接时，会串行执行一次即时 `GetExtendedTcpTable` 刷新并重试，避免 Chrome 等刚启动/刚建立连接的程序因 250ms 刷新窗口而被误判为直连。
- **保持高性能**：正常命中缓存仍为 O(1) 查找；只有缓存未命中时才触发实时回查，并通过互斥避免并发刷新风暴。
- **进程名缓存**：继续使用 2 秒 PID→进程名缓存，避免恢复实时检查后重新产生高频 `OpenProcess` 调用。

## v1.7.0

- **版本重新编号**：基于 1.6.8 的功能收敛版本重新编号为 v1.7.0，避免继续复用历史版本标签。
- **依赖清理**：彻底移除已删除的 gorilla/websocket 依赖记录，并同步 vendor/modules.txt。
- **构建一致性**：修复 Go vendor 模式下 `inconsistent vendoring` 导致 Windows CI 无法进入测试和构建阶段的问题。
- **定位保持收敛**：GoPass 只负责 Windows 进程白名单 IPv4 TCP 透明劫持与上游代理转发。
- **白名单模式**：只有名单中的程序通过配置的 SOCKS5 / HTTP CONNECT 上游代理。
- **非白名单直连**：其他程序保持 Windows 正常网络路径，不经过 GoPass 上游代理。
- **Web UI**：保持“状态 / 进程白名单 / 设置”三个页面和 HTTP 状态轮询。
- **实时状态面板**：显示代理程序、直连程序、代理连接、直连连接，以及程序 PID、连接数和目标 IP:端口。
- **TProxy Buffer Size**：设置页提供 32 KB、64 KB、128 KB、256 KB、512 KB、1 MB，默认 **64 KB**，运行时硬限制 1 MB。
- **连接跟踪稳定性**：透明劫持不再复用原始本地端口，而是为每条映射分配独立端口，并避开 TProxy 监听端口，降低并发连接串流风险。
- **长连接保护**：已建立并接入 TProxy 的连接不会被短 TTL GC 删除，视频/长连接不会因连接跟踪过期而失去 NAT 映射。
- **进程查询优化**：Windows PID 到进程名增加 2 秒短期缓存，并仅使用 `PROCESS_QUERY_LIMITED_INFORMATION`，降低高连接数下的系统调用压力。
- **内存控制**：默认 64 KB 转发缓冲区，且大于默认值的缓冲区不进入长期 `sync.Pool`，避免高并发配置大缓冲后持续占用大量内存。
- **其他 TCP 参数固定**：不向用户开放 TCP NoDelay、Keep-Alive 等高级调优项。
- **删除无关能力**：不提供 GeoIP/GeoSite、域名/IP 分流、DNS Relay/Fake-IP、SNI 路由、UDP/QUIC、自动选路、测速探测、路线评分、多线路或复杂规则。
- **WinDivert 范围**：限定为 IPv4 TCP 网络层透明拦截。
