# GoPass Changelog

## v1.6.6

- **TProxy Buffer 默认值**：512 KB。
- **TProxy Buffer 安全范围**：32 KB–2 MB。
- **Web UI 预设**：32 KB、256 KB、512 KB（推荐）、1 MB、2 MB，并支持自定义输入。
- **自定义值校验**：前端与 API/运行时统一限制为 32 KB–2 MB，防止异常大值造成不必要的内存占用。
- **Socket Buffer**：固定为 `0`，继续使用 Windows TCP Auto-Tuning，不再向用户开放设置。
- **TCP 高级参数收敛**：TCP NoDelay、Bidirectional Wait、TCP Keep-Alive、Keep-Alive Period、TCP Linger 使用稳定默认值，普通 Web UI 不再允许随意修改。
- **保持 v1.6.5 核心能力**：保留 OrigDstIP 优先、Fake-IP 恢复、SNI fallback 与既有透明代理逻辑。
