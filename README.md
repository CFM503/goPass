# GoPass

GoPass is a Windows-based transparent proxy program written in Golang, designed as an open-source alternative to Proxifier.

It leverages `WinDivert` to perform process-based transparent packet filtering and `gVisor netstack` to parse IP packets and route connections to upper-level proxies (SOCKS5, Direct, etc.).

## Prerequisites for Windows

Because WinDivert operates at the Windows kernel network stack, this project requires **CGo** and the **WinDivert Native Drivers**.

1. **Install MinGW-w64 (GCC for Windows)**
   - Download and install [MSYS2](https://www.msys2.org/).
   - Open MSYS2 terminal and run: `pacman -S mingw-w64-x86_64-gcc`
   - Add `C:\msys64\mingw64\bin` to your System Environment `PATH`.
   - Verify: `gcc --version`

2. **Download WinDivert DLL and SYS**
   - Download the latest compiled binaries from [WinDivert releases](https://github.com/basil00/Divert/releases).
   - Extract the files. You MUST place `WinDivert.dll` and `WinDivert64.sys` in the same directory as the compiled `gopass.exe`.

3. **Enable CGo**
   - In PowerShell: `$env:CGO_ENABLED="1"`

## Build Instructions

```powershell
# Set CGo Flag
$env:CGO_ENABLED="1"
$env:GOOS="windows"
$env:GOARCH="amd64"

# Build the executable
go build -o gopass.exe ./cmd/gopass
```

## Running GoPass

> [!WARNING]
> **Administrator Privileges Required!**
> WinDivert must load a kernel driver. You MUST run `gopass.exe` from an **Administrator** command prompt or PowerShell.

```powershell
# Launch the proxy engine
.\gopass.exe -config .\config.json
```

Then open your browser and go to `http://127.0.0.1:8080` to access the modern Dashboard and see active real-time connections!
