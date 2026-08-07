# Download the latest v2fly geosite.dat / geoip.dat rule files to the GoPass root.
#
# GoPass now embeds geosite:cn / geoip:cn rules directly in the binary (out of the box,
# no download needed). This script is OPTIONAL — use it to refresh the DISK copies, which
# take precedence over the embedded rules when present. Delete the disk files to revert
# to the embedded rules.
#
# To re-embed the latest rules into the binary after downloading:
#   go test -tags genrules -run TestGenEmbeddedRules ./internal/engine/
#
# Run from the GoPass root directory:
#   powershell -ExecutionPolicy Bypass -File .tools\download.ps1
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $dir

$targets = @(
    @{ Url = 'https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat'; Out = Join-Path $root 'geosite.dat' },
    @{ Url = 'https://github.com/v2fly/geoip/releases/latest/download/geoip.dat'; Out = Join-Path $root 'geoip.dat' }
)

foreach ($t in $targets) {
    Write-Host "Downloading $($t.Url) -> $($t.Out) ..."
    Invoke-WebRequest -Uri $t.Url -OutFile $t.Out -UseBasicParsing
    $len = (Get-Item $t.Out).Length
    Write-Host "  OK ($([math]::Round($len / 1MB, 2)) MB)"
}

Write-Host "`nDone. Disk rule files now take precedence over the embedded rules."
Write-Host "Delete geosite.dat / geoip.dat to revert to the built-in embedded rules."
Write-Host "To re-embed the latest rules: go test -tags genrules -run TestGenEmbeddedRules ./internal/engine/"
