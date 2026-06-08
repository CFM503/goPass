# GoPass v1.4.5 Release Plan

## Context
GoPass is a Windows transparent proxy (Go). The project has: an outdated module path placeholder (`github.com/yourusername/gopass`), version strings out of sync across 3 files, a duplicate `WinDivert64.sys` at root, a broken `.gitignore` exception path, and no vendor directory. The user wants to clean up, update to v1.4.5, vendor dependencies, build a Windows binary, and push to GitHub.

## Step 1: Download Dependencies to Vendor Folder
- Set proxy: `export https_proxy=http://127.0.0.1:9192 http_proxy=http://127.0.0.1:9192`
- Run `go mod vendor` to create `vendor/` directory with all 3 dependencies
- Verify `vendor/` contains the expected packages

## Step 2: Fix Module Path (go.mod + all imports)
- **`go.mod`**: Change `github.com/yourusername/gopass` → `github.com/CFM503/goPass`
- **10 files** with imports to update (all `github.com/yourusername/gopass/...` → `github.com/CFM503/goPass/...`):
  - `cmd/gopass/main.go` (4 imports)
  - `internal/api/api.go` (3 imports)
  - `internal/api/ws.go` (1 import)
  - `internal/engine/engine.go` (1 import)
  - `internal/engine/tproxy.go` (1 import)
  - `internal/engine/windivert.go` (1 import)

## Step 3: Update Version to v1.4.5 (3 files)
- `cmd/gopass/main.go:22`: `v1.4.4` → `v1.4.5`
- `web/index.html:14`: `v1.4.2` → `v1.4.5`
- `internal/engine/httpproxy.go:70`: `GoPass/1.1.2` → `GoPass/1.4.5`

## Step 4: Clean Up Unused Files
- Delete root-level `WinDivert64.sys` (duplicate of `internal/engine/windivert/WinDivert64.sys`)
- Fix `.gitignore:9`: `!internal/engine/embed/WinDivert.dll` → `!internal/engine/windivert/WinDivert.dll`

## Step 5: Update go.sum & Re-vendor
- Run `go mod tidy` to regenerate `go.sum` with new module path
- Re-run `go mod vendor` to refresh vendor with correct paths

## Step 6: Git Commit, Tag, and Push
- `git add -A`
- `git commit -m "chore: bump version to v1.4.5, fix module path, clean up duplicates"`
- `git tag v1.4.5`
- `git push origin main --tags`

## Step 7: Build Windows Binary
- `go build -o release/gopass.exe ./cmd/gopass`
- Output to `release/` directory (already in `.gitignore`)

## Critical Files
- `D:/SOFT/AI/github/gopass/go.mod`
- `D:/SOFT/AI/github/gopass/cmd/gopass/main.go`
- `D:/SOFT/AI/github/gopass/web/index.html`
- `D:/SOFT/AI/github/gopass/internal/engine/httpproxy.go`
- `D:/SOFT/AI/github/gopass/.gitignore`
- `D:/SOFT/AI/github/gopass/internal/api/api.go`
- `D:/SOFT/AI/github/gopass/internal/api/ws.go`
- `D:/SOFT/AI/github/gopass/internal/engine/engine.go`
- `D:/SOFT/AI/github/gopass/internal/engine/tproxy.go`
- `D:/SOFT/AI/github/gopass/internal/engine/windivert.go`

## Verification
1. `go build ./...` succeeds after all changes
2. `vendor/` directory exists with all dependencies
3. Root-level `WinDivert64.sys` is gone
4. All version strings show `v1.4.5`
5. Git tag `v1.4.5` exists and is pushed
6. `release/gopass.exe` binary is built
