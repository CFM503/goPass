# GoPass - Transparent Proxy Engine

GoPass is a modern, high-performance Windows transparent proxy engine written purely in Go. It serves as an open-source alternative to Proxifier/SSTap, allowing you to seamlessly route traffic from specific applications (or all applications) through a downstream SOCKS5 proxy.

Unlike traditional proxy clients that require applications to natively support proxy settings, GoPass intercepts network packets at the Windows kernel level using **WinDivert** and transparently forwards them.

## ✨ Key Features

- **Pure Go Implementation**: No CGo required! GoPass talks directly to the WinDivert driver via raw syscalls, making compilation and deployment incredibly simple.
- **Two Routing Modes**:
  - **Whitelist Mode (Default)**: Proxies *only* the specific processes you configure (e.g., `brave.exe`, `curl.exe`).
  - **Global Mode**: Proxies all traffic on the machine.
- **Smart Global Bypass**: When in Global Mode, GoPass will *automatically* detect the PID of your upstream proxy software (based on your configured SOCKS5 port) and bypass its traffic. This completely eliminates the infamous "infinite proxy loop" problem without requiring any manual process configuration!
- **Modern Web UI Dashboard**: Built-in HTTP and WebSocket server provides a beautiful, real-time dashboard at `http://127.0.0.1:8080`.
  - View live connection counts, TX/RX network speeds, and a table of active connections with their corresponding process names.
  - Dynamically switch between Global and Whitelist modes.
  - Add or delete whitelist rules on the fly.
- **Hot-Reloading**: Changes to rules and bypass modes made via the Web UI are instantly applied to the running WinDivert engine. No restarts required.

## 🚀 Getting Started

### Prerequisites
1. Download the latest `WinDivert.dll` and `WinDivert64.sys` (version 2.2.x) from the [official WinDivert releases](https://github.com/basil00/Divert/releases).
2. Place both files in the exact same directory as the compiled `gopass.exe`.

### Compilation
Because GoPass now utilizes pure Go syscalls for WinDivert, you **do not** need a C compiler (MinGW). Simply build it like any normal Go project:

```powershell
$env:GOOS="windows"
$env:GOARCH="amd64"
go build -o gopass.exe ./cmd/gopass
```

*(Alternatively, you can just use `go run ./cmd/gopass` for quick testing, provided you run it in a directory with the WinDivert DLLs).*

### Execution
> [!WARNING]
> **Administrator Privileges Required!**
> Because GoPass interacts with the Windows networking stack at the kernel level via WinDivert, you MUST run it from an **Administrator** command prompt or PowerShell.

```powershell
.\gopass.exe
```

By default, GoPass connects to a local SOCKS5 proxy at `127.0.0.1:9192`. You can modify this in the auto-generated `config.json` file.

## 💻 Web Control Panel

Once GoPass is running, open your browser and navigate to:
**http://127.0.0.1:8080**

- **Dashboard**: Monitor real-time traffic statistics and see exactly which processes are establishing connections through the proxy.
- **Rules**: Add application names (e.g., `chrome.exe`) to the proxy whitelist without restarting the software.
- **Settings**: Instantly switch the entire system between Whitelist routing and Global routing.

## 🛠️ Configuration (config.json)

The `config.json` is automatically generated on the first run. 
- `mode`: Controls the routing mode (`whitelist` or `global`).
- `rules`: A list of process payloads specifying which `.exe` workflows should be proxied.
- `outbounds`: Defines your upstream proxy services (currently supports `socks5`).

## 🤝 Contributing
Issues and Pull Requests are welcome. If you find a bug or have a feature request, please feel free to open an issue!

## 📜 License
MIT License.
