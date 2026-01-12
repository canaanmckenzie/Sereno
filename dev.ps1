# Sereno Development Helper
# Usage: .\dev.ps1 -Build    # Rebuild
#        .\dev.ps1 -Run      # Run TUI
#        .\dev.ps1           # Build and Run

param(
    [switch]$Build,
    [switch]$Run,
    [switch]$Driver,
    [switch]$Stop
)

$ErrorActionPreference = "Stop"
$exe = ".\target\x86_64-pc-windows-msvc\release\sereno.exe"

if ($Stop) {
    Write-Host "Stopping driver..." -ForegroundColor Yellow
    sc.exe stop SerenoFilter 2>$null
    exit
}

if ($Driver) {
    Write-Host "Starting driver..." -ForegroundColor Cyan
    sc.exe start SerenoFilter
    exit
}

if ($Build -or (-not $Run)) {
    Write-Host "Building..." -ForegroundColor Cyan
    cargo build --release -p sereno-cli
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Build failed!" -ForegroundColor Red
        exit 1
    }
    Write-Host "Build complete." -ForegroundColor Green
}

if ($Run -or (-not $Build)) {
    if (-not (Test-Path $exe)) {
        Write-Host "Binary not found. Run with -Build first." -ForegroundColor Red
        exit 1
    }
    Write-Host "Starting TUI..." -ForegroundColor Cyan
    & $exe
}
