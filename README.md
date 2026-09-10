# GoPass 1.6.8

GoPass is a Windows **process-whitelist transparent TCP proxy**. Its job is intentionally narrow: detect TCP connections belonging to whitelisted processes, transparently intercept IPv4 TCP traffic, and forward those connections through one configured upstream SOCKS5 or HTTP CONNECT proxy.

## 核心功能

- **进程白名单透明劫持**：只有白名单中的程序会被 GoPass 劫持。
- **非白名单程序直连**：其他程序保持 Windows 原有网络路径，不经过 GoPass 的上游代理。
- **IPv4 TCP**：当前透明拦截范围限定为 IPv4 TCP。
- **上游 SOCKS5 / HTTP CONNECT**：白名单程序统一使用设置页配置的上游代理。
- **本地 Web UI**：`http://127.0.0.1:8080`，只有三个页面：状态、进程白名单、设置。
- **实时进程状态**：状态页显示当前有 TCP 网络连接的程序、PID、代理/直连状态、连接数和目标 IP:端口。
- **固定内部转发缓冲**：内部使用 256 KB relay buffer，不提供用户性能调节项，运行时不允许超过 1 MB。

## Web UI

### 状态

查看：

- GoPass 运行状态和 PID
- 代理程序数量
- 直连程序数量
- 代理连接数量
- 直连连接数量
- 当前有网络连接的程序
- 每个程序的 PID、代理/直连状态、连接数、目标 IP:端口

### 进程白名单

添加或删除程序，例如：

```text
chrome.exe
BigEyesTV.exe
```

只有加入名单的程序会通过 GoPass 上游代理。

### 设置

仅提供 GoPass 必需设置：

- 上游协议：SOCKS5 / HTTP CONNECT
- 上游地址
- 上游端口
- TProxy 端口（当前默认 7893）
- Web UI 地址（当前默认 127.0.0.1:8080）

## 明确不做

GoPass 不提供：

- GeoIP / GeoSite
- 域名/IP 分流
- DNS Relay / Fake-IP
- SNI 路由判断
- UDP / QUIC
- 自动选路、测速、探测、路线评分
- 多线路和复杂规则系统
- 用户可调的 TCP 性能参数或 Buffer 参数

## 工作方式

```text
Windows TCP connection
        |
        v
进程 PID / 程序名关联
        |
   ┌────┴────┐
   │ 白名单？ │
   └────┬────┘
      是 │ 否
         │
         v
   WinDivert IPv4 TCP
         |
         v
       TProxy
         |
         v
 SOCKS5 / HTTP CONNECT
         |
         v
      Internet

未在白名单：保持原连接，直接访问 Internet
```

GoPass 需要管理员权限运行，因为 WinDivert 需要提升权限。
