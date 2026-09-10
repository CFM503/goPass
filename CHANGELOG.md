# GoPass Changelog

## v1.6.7

- **Core relay rewrite**: GoPass is now a proxy-only IPv4 TCP transparent relay.
- **Split routing removed**: GeoIP/GeoSite, process whitelist routing, custom direct/proxy rules, CN/foreign routing, Fake-IP DNS relay, IPv6 blocking and foreign UDP/QUIC routing were removed from the core.
- **2 MB buffer option removed**: relay buffer is now **32 KB–1 MB**, with a hard runtime maximum of 1 MB.
- **Default relay buffer**: 256 KB.
- **Relay lifecycle rewritten**: removed the Bidirectional Wait setting; relay errors close both sides so blocked I/O can terminate.
- **Payload path simplified**: removed SNI inspection/replay from the core, so normal application payload is not buffered and resent for routing decisions.
- **ConnTracker simplified**: it only transfers Original Destination metadata from WinDivert to TProxy.
- **WinDivert scope simplified**: IPv4 TCP interception only.
- **Dashboard simplified**: removed Rules/Split UI; upstream and relay performance settings remain.
- **Regression coverage added**: relay payload integrity and shutdown tests, plus 32KB–1MB buffer benchmarks.
- **Version**: v1.6.7.

## v1.6.6

- **TProxy Buffer 默认值**：512 KB。
- **TProxy Buffer 安全范围**：32 KB–2 MB。
- **Web UI 预设**：32 KB、256 KB、512 KB（推荐）、1 MB、2 MB，并支持自定义输入。
- **自定义值校验**：前端与 API/运行时统一限制为 32 KB–2 MB，防止异常大值造成不必要的内存占用。
- **Socket Buffer**：固定为 `0`，继续使用 Windows TCP Auto-Tuning，不再向用户开放设置。
- **TCP 高级参数收敛**：TCP NoDelay、Bidirectional Wait、TCP Keep-Alive、Keep-Alive Period、TCP Linger 使用稳定默认值，普通 Web UI 不再允许随意修改。
