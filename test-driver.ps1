# Quick diagnostic for Sereno driver communication
# Run as Administrator!

param(
    [switch]$Status,
    [switch]$TestConnection
)

$ErrorActionPreference = "Continue"

Write-Host "=== Sereno Driver Diagnostic ===" -ForegroundColor Cyan
Write-Host ""

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host "[OK] Running as Administrator" -ForegroundColor Green
} else {
    Write-Host "[FAIL] NOT running as Administrator - this is required!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

# Check driver service
Write-Host ""
Write-Host "Checking driver service..." -ForegroundColor Cyan
$svc = Get-Service -Name "SerenoFilter" -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -eq "Running") {
        Write-Host "[OK] SerenoFilter service is RUNNING" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] SerenoFilter service exists but is $($svc.Status)" -ForegroundColor Red
        Write-Host "Run: sc.exe start SerenoFilter" -ForegroundColor Yellow
    }
} else {
    Write-Host "[FAIL] SerenoFilter service not found" -ForegroundColor Red
    Write-Host "Run: .\dev.ps1 -BuildDriver" -ForegroundColor Yellow
    exit 1
}

# Check driver file
Write-Host ""
Write-Host "Checking driver file..." -ForegroundColor Cyan
$driverPath = "C:\Windows\System32\drivers\SerenoFilter.sys"
if (Test-Path $driverPath) {
    $file = Get-Item $driverPath
    Write-Host "[OK] Driver file exists: $driverPath" -ForegroundColor Green
    Write-Host "     Size: $($file.Length) bytes" -ForegroundColor Gray
    Write-Host "     Modified: $($file.LastWriteTime)" -ForegroundColor Gray
} else {
    Write-Host "[FAIL] Driver file not found at $driverPath" -ForegroundColor Red
}

# Check device
Write-Host ""
Write-Host "Checking device handle..." -ForegroundColor Cyan

# Try to open the device using .NET
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class SerenoDevice {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    public static bool CanOpenDevice() {
        var handle = CreateFileW(
            @"\\.\SerenoFilter",
            0xC0000000, // GENERIC_READ | GENERIC_WRITE
            3,          // FILE_SHARE_READ | FILE_SHARE_WRITE
            IntPtr.Zero,
            3,          // OPEN_EXISTING
            0x80,       // FILE_ATTRIBUTE_NORMAL
            IntPtr.Zero);

        if (handle.IsInvalid) {
            return false;
        }
        handle.Close();
        return true;
    }
}
"@

try {
    if ([SerenoDevice]::CanOpenDevice()) {
        Write-Host "[OK] Can open \\.\SerenoFilter device" -ForegroundColor Green
    } else {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host "[FAIL] Cannot open device - Error code: $err" -ForegroundColor Red
        if ($err -eq 5) {
            Write-Host "     Error 5 = Access Denied (need admin)" -ForegroundColor Yellow
        } elseif ($err -eq 2) {
            Write-Host "     Error 2 = Device not found (driver not loaded)" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "[FAIL] Exception testing device: $_" -ForegroundColor Red
}

# Summary
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "If all checks pass but connections still hang:" -ForegroundColor Yellow
Write-Host "1. The TUI poll loop may not be receiving requests" -ForegroundColor White
Write-Host "2. The verdict may not be sent back correctly" -ForegroundColor White
Write-Host "3. Run the TUI and check if you see connections appearing" -ForegroundColor White
Write-Host ""
Write-Host "To test:" -ForegroundColor Cyan
Write-Host "  Terminal 1 (Admin): .\dev.ps1 -Run" -ForegroundColor White
Write-Host "  Terminal 2: curl google.com" -ForegroundColor White
Write-Host ""
Write-Host "You should see the curl connection appear in the TUI" -ForegroundColor White
