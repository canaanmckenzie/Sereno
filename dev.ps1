# Sereno Development Helper
#
# ARCHITECTURE: Async Pending Model (FwpsPendOperation0/FwpsCompleteOperation0)
# - Driver intercepts connections, pends them WITHOUT blocking kernel threads
# - User-mode TUI receives pending connections, evaluates rules, sends verdict
# - Driver completes the pended operation with ALLOW or BLOCK
# - This allows unlimited concurrent connections with zero kernel thread blocking
#
# Usage: .\dev.ps1              # Build CLI and Run TUI
#        .\dev.ps1 -Build       # Rebuild CLI only
#        .\dev.ps1 -Run         # Run TUI only (assumes already built)
#        .\dev.ps1 -BuildDriver # Build, sign, and install driver (requires admin)
#        .\dev.ps1 -Driver      # Start driver only
#        .\dev.ps1 -Stop        # Stop driver
#        .\dev.ps1 -All         # Full rebuild: driver + CLI, install, and start TUI
#
# Typical development workflow:
#   1. .\dev.ps1 -BuildDriver   # First time: build and install driver (admin required)
#   2. .\dev.ps1               # Edit code, rebuild CLI, test in TUI
#   3. .\dev.ps1 -Run          # Just run TUI (no rebuild)
#
# If driver crashes VM (shouldn't with async model):
#   1. Restart VM
#   2. .\dev.ps1 -Stop         # Stop driver
#   3. Fix code
#   4. .\dev.ps1 -BuildDriver  # Rebuild and reinstall

param(
    [switch]$Build,
    [switch]$Run,
    [switch]$BuildDriver,
    [switch]$Driver,
    [switch]$Stop,
    [switch]$All
)

$ErrorActionPreference = "Stop"
$exe = ".\target\x86_64-pc-windows-msvc\release\sereno.exe"
$driverSrc = ".\sereno-driver\bin\x64\Release\SerenoFilter.sys"
$driverDst = "C:\Windows\System32\drivers\SerenoFilter.sys"
$certThumbprint = "1DC360B0502EDDBF7424ADF0D18EEDB70904523F"
$signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
$serviceName = "SerenoFilter"

# Helper: Check if running as admin
function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Helper: Ensure service exists
function Ensure-ServiceExists {
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Host "Creating driver service..." -ForegroundColor Yellow
        sc.exe create $serviceName type= kernel binPath= $driverDst start= demand | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Failed to create service!" -ForegroundColor Red
            exit 1
        }
        Write-Host "Service created." -ForegroundColor Green
    }
}

if ($Stop) {
    Write-Host "Stopping driver..." -ForegroundColor Yellow
    sc.exe stop $serviceName 2>$null
    exit
}

if ($Driver) {
    Write-Host "Starting driver..." -ForegroundColor Cyan
    Ensure-ServiceExists
    sc.exe start $serviceName
    exit
}

if ($BuildDriver -or $All) {
    if (-not (Test-Admin)) {
        Write-Host "ERROR: BuildDriver requires Administrator privileges!" -ForegroundColor Red
        Write-Host "Right-click PowerShell and 'Run as Administrator'" -ForegroundColor Yellow
        exit 1
    }

    Write-Host "=== Building Driver ===" -ForegroundColor Cyan

    # Stop driver if running
    Write-Host "Stopping driver if running..." -ForegroundColor Yellow
    sc.exe stop $serviceName 2>$null
    Start-Sleep -Seconds 1

    # Build driver (Release configuration)
    Write-Host "Building driver (Release x64)..." -ForegroundColor Cyan
    Push-Location ".\sereno-driver"
    & ".\scripts\build.ps1" -Configuration Release -Platform x64
    if ($LASTEXITCODE -ne 0) {
        Pop-Location
        Write-Host "Driver build failed!" -ForegroundColor Red
        exit 1
    }
    Pop-Location
    Write-Host "Driver build complete." -ForegroundColor Green

    # Check driver exists
    if (-not (Test-Path $driverSrc)) {
        Write-Host "ERROR: Driver not found at $driverSrc" -ForegroundColor Red
        exit 1
    }

    # Sign driver
    Write-Host "Signing driver..." -ForegroundColor Cyan
    if (-not (Test-Path $signtool)) {
        Write-Host "signtool.exe not found at: $signtool" -ForegroundColor Red
        exit 1
    }
    & $signtool sign /v /sha1 $certThumbprint /fd sha256 $driverSrc
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Driver signing failed!" -ForegroundColor Red
        Write-Host "Make sure your test certificate exists. Check with:" -ForegroundColor Yellow
        Write-Host "  Get-ChildItem Cert:\CurrentUser\My | Format-Table Subject, Thumbprint" -ForegroundColor Yellow
        exit 1
    }
    Write-Host "Driver signed." -ForegroundColor Green

    # Copy to system32
    Write-Host "Installing driver to System32..." -ForegroundColor Cyan
    try {
        Copy-Item $driverSrc $driverDst -Force
        Write-Host "Driver installed." -ForegroundColor Green
    } catch {
        Write-Host "Failed to copy driver: $_" -ForegroundColor Red
        exit 1
    }

    # Ensure service exists and start it
    Ensure-ServiceExists
    Write-Host "Starting driver..." -ForegroundColor Cyan
    sc.exe start $serviceName
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Driver start failed! Check:" -ForegroundColor Red
        Write-Host "  - Test signing enabled: bcdedit | findstr testsigning" -ForegroundColor Yellow
        Write-Host "  - Certificate trusted in TrustedPublisher store" -ForegroundColor Yellow
        exit 1
    }
    Write-Host "=== Driver Ready ===" -ForegroundColor Green

    # If only -BuildDriver (not -All), exit here
    if (-not $All) {
        exit
    }
}

if ($Build -or $All -or (-not $Run)) {
    Write-Host "Building CLI (Release)..." -ForegroundColor Cyan
    cargo build --release -p sereno-cli --target x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Build failed!" -ForegroundColor Red
        exit 1
    }
    Write-Host "Build complete." -ForegroundColor Green
}

if ($Run -or $All -or (-not $Build -and -not $BuildDriver)) {
    if (-not (Test-Path $exe)) {
        Write-Host "Binary not found at $exe" -ForegroundColor Red
        Write-Host "Run with -Build first." -ForegroundColor Yellow
        exit 1
    }

    # Check driver status before starting TUI
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Write-Host "Driver: Running" -ForegroundColor Green
    } else {
        Write-Host "Driver: Not running (TUI will work in monitor-only mode)" -ForegroundColor Yellow
    }

    Write-Host "Starting TUI..." -ForegroundColor Cyan
    & $exe
}
