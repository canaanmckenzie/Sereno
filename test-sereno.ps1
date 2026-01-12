# Sereno Safe Test Script
# PURPOSE: Test driver incrementally with abort capability
#
# USAGE: Run as Administrator
#   .\test-sereno.ps1 -Phase 1   # Install driver, don't enable filtering
#   .\test-sereno.ps1 -Phase 2   # Test with filtering enabled
#   .\test-sereno.ps1 -Abort     # Emergency stop - run IMMEDIATELY if CPU spikes

param(
    [int]$Phase = 0,
    [switch]$Abort,
    [switch]$Status,
    [switch]$Build,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$DriverName = "SerenoFilter"
$SysPath = "C:\Windows\System32\drivers\SerenoFilter.sys"
$SrcPath = "C:\Users\Virgil\Desktop\sereno-dev\sereno-driver\bin\x64\Release\SerenoFilter.sys"

function Write-Header($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Write-OK($msg) { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err($msg) { Write-Host "[ERROR] $msg" -ForegroundColor Red }

# EMERGENCY ABORT - Run this IMMEDIATELY if CPU spikes
if ($Abort) {
    Write-Header "EMERGENCY ABORT"
    Write-Host "Stopping driver immediately..." -ForegroundColor Red

    # Stop the service first
    sc.exe stop $DriverName 2>$null
    Start-Sleep -Milliseconds 500

    # Delete the service (marks for deletion)
    sc.exe delete $DriverName 2>$null

    # Kill any sereno-service processes
    Get-Process -Name "sereno-service" -ErrorAction SilentlyContinue | Stop-Process -Force

    Write-Host "`nDriver stopped and marked for deletion." -ForegroundColor Yellow
    Write-Host "If VM is still unresponsive, hard reset it." -ForegroundColor Yellow
    Write-Host "The driver won't load on next boot." -ForegroundColor Green
    exit 0
}

# Status check
if ($Status) {
    Write-Header "DRIVER STATUS"

    $svc = sc.exe query $DriverName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host $svc

        # Check if device exists
        if (Test-Path "\\.\$DriverName") {
            Write-OK "Device \\.\$DriverName exists"
        }
        else {
            Write-Warn "Device \\.\$DriverName NOT found"
        }
    }
    else {
        Write-Warn "Driver service not installed"
    }

    # Check binary timestamps
    Write-Header "BINARY INFO"
    if (Test-Path $SrcPath) {
        $src = Get-Item $SrcPath
        Write-Host "Source .sys: $($src.LastWriteTime) ($($src.Length) bytes)"
    }
    else {
        Write-Warn "Source binary not found: $SrcPath"
    }

    if (Test-Path $SysPath) {
        $sys = Get-Item $SysPath
        Write-Host "System .sys: $($sys.LastWriteTime) ($($sys.Length) bytes)"

        if (Test-Path $SrcPath) {
            if ($src.Length -ne $sys.Length -or $src.LastWriteTime -ne $sys.LastWriteTime) {
                Write-Warn "Binaries DON'T MATCH - need to update System32 copy"
            }
            else {
                Write-OK "Binaries match"
            }
        }
    }
    else {
        Write-Warn "System binary not found: $SysPath"
    }

    exit 0
}

# Clean - fully remove driver
if ($Clean) {
    Write-Header "CLEANING UP"
    sc.exe stop $DriverName 2>$null
    sc.exe delete $DriverName 2>$null
    if (Test-Path $SysPath) {
        Remove-Item $SysPath -Force -ErrorAction SilentlyContinue
        if (Test-Path $SysPath) {
            Write-Warn "Could not delete $SysPath - driver may be loaded"
        }
        else {
            Write-OK "Removed $SysPath"
        }
    }
    Write-OK "Cleanup complete"
    exit 0
}

# Build
if ($Build) {
    Write-Header "BUILDING DRIVER"
    Push-Location "C:\Users\Virgil\Desktop\sereno-dev\sereno-driver"

    # Find MSBuild
    $msbuild = Get-ChildItem "C:\Program Files\Microsoft Visual Studio\2022\*\MSBuild\Current\Bin\MSBuild.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $msbuild) {
        Write-Err "MSBuild not found"
        Pop-Location
        exit 1
    }

    Write-Host "Using MSBuild: $($msbuild.FullName)"
    & $msbuild.FullName SerenoFilter.vcxproj /p:Configuration=Release /p:Platform=x64 /v:m

    if ($LASTEXITCODE -ne 0) {
        Write-Err "Build failed"
        Pop-Location
        exit 1
    }

    Write-OK "Build successful"

    # Sign the driver
    $signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" | Sort-Object FullName -Descending | Select-Object -First 1
    if ($signtool) {
        Write-Host "Signing driver..."
        & $signtool.FullName sign /fd sha256 /a "bin\x64\Release\SerenoFilter.sys" 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-OK "Driver signed"
        }
        else {
            Write-Warn "Signing failed (may still work in test mode)"
        }
    }

    Pop-Location

    # Show binary info
    if (Test-Path $SrcPath) {
        $info = Get-Item $SrcPath
        Write-OK "Built: $SrcPath ($($info.Length) bytes)"
    }

    exit 0
}

# Phase 0 - Show help
if ($Phase -eq 0) {
    Write-Host @"

Sereno Driver Test Script
=========================

PHASES:
  -Phase 1    Install driver (filtering OFF by default)
  -Phase 2    Run service (enables filtering) - WATCH CPU!

OTHER OPTIONS:
  -Status     Check driver/binary status
  -Build      Build and sign driver
  -Clean      Remove driver completely
  -Abort      EMERGENCY: Stop everything immediately

RECOMMENDED WORKFLOW:
  1. .\test-sereno.ps1 -Build       # Rebuild with latest code
  2. .\test-sereno.ps1 -Status      # Verify binaries
  3. .\test-sereno.ps1 -Clean       # Remove old driver
  4. .\test-sereno.ps1 -Phase 1     # Install fresh
  5. .\test-sereno.ps1 -Phase 2     # Test (watch CPU!)

IF CPU SPIKES:
  .\test-sereno.ps1 -Abort          # Or just run: sc.exe stop SerenoFilter

"@
    exit 0
}

# Phase 1 - Install driver but don't enable filtering
if ($Phase -eq 1) {
    Write-Header "PHASE 1: INSTALL DRIVER (SAFE MODE)"

    # Stop/remove old driver
    Write-Host "Removing old driver..."
    sc.exe stop $DriverName 2>$null
    sc.exe delete $DriverName 2>$null
    Start-Sleep -Seconds 1

    # Check source binary exists
    if (-not (Test-Path $SrcPath)) {
        Write-Err "Source binary not found: $SrcPath"
        Write-Host "Run: .\test-sereno.ps1 -Build"
        exit 1
    }

    # Copy to System32
    Write-Host "Copying driver to System32..."
    Copy-Item $SrcPath $SysPath -Force

    if (-not (Test-Path $SysPath)) {
        Write-Err "Failed to copy driver"
        exit 1
    }
    Write-OK "Driver copied"

    # Create service
    Write-Host "Creating service..."
    sc.exe create $DriverName type= kernel binPath= $SysPath start= demand
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to create service"
        exit 1
    }
    Write-OK "Service created"

    # Start driver
    Write-Host "Starting driver..."
    sc.exe start $DriverName
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to start driver"
        Write-Host "Check Event Viewer > Windows Logs > System for errors"
        exit 1
    }
    Write-OK "Driver started"

    # Verify device
    Start-Sleep -Milliseconds 500
    if (Test-Path "\\.\$DriverName") {
        Write-OK "Device \\.\$DriverName created"
    }
    else {
        Write-Warn "Device not found - driver may have failed to initialize"
        exit 1
    }

    Write-Host "`n" -NoNewline
    Write-OK "Phase 1 complete - driver loaded but filtering is OFF"
    Write-Host "`nNext step: Open a NEW terminal and run:"
    Write-Host "  .\test-sereno.ps1 -Phase 2" -ForegroundColor Yellow
    Write-Host "`nKEEP THIS TERMINAL OPEN for emergency abort:"
    Write-Host "  .\test-sereno.ps1 -Abort" -ForegroundColor Red

    exit 0
}

# Phase 2 - Run service (this enables filtering)
if ($Phase -eq 2) {
    Write-Header "PHASE 2: RUN SERVICE (ENABLES FILTERING)"

    # Check driver is running
    $svc = sc.exe query $DriverName 2>&1
    if ($LASTEXITCODE -ne 0 -or $svc -notmatch "RUNNING") {
        Write-Err "Driver not running. Run Phase 1 first."
        exit 1
    }
    Write-OK "Driver is running"

    Write-Host "`n!!! WARNING !!!" -ForegroundColor Red
    Write-Host "This will enable filtering. Watch CPU usage!" -ForegroundColor Yellow
    Write-Host "If CPU spikes, run in another terminal:" -ForegroundColor Yellow
    Write-Host "  .\test-sereno.ps1 -Abort" -ForegroundColor Red
    Write-Host "`nPress ENTER to continue or Ctrl+C to cancel..."
    Read-Host

    Write-Host "`nStarting service..."
    Push-Location "C:\Users\Virgil\Desktop\sereno-dev"
    cargo run --release -p sereno-service
    Pop-Location

    exit 0
}
