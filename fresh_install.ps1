# Fresh driver install script - run as admin
$ErrorActionPreference = "Stop"

# Stop and delete existing service
Write-Host "Stopping and deleting existing service..." -ForegroundColor Yellow
sc.exe stop SerenoFilter 2>&1 | Out-Null
sc.exe delete SerenoFilter 2>&1 | Out-Null
Start-Sleep -Seconds 2

# Clean up ALL old driver files
Write-Host "Cleaning up old driver files..." -ForegroundColor Yellow
Remove-Item C:\Windows\System32\drivers\Sereno*.sys -Force -ErrorAction SilentlyContinue
Remove-Item C:\Windows\System32\drivers\Sereno*.old -Force -ErrorAction SilentlyContinue

# Generate unique filename with timestamp
$ts = Get-Date -Format "HHmmss"
$newName = "Sereno$ts.sys"
Write-Host "Using driver filename: $newName" -ForegroundColor Cyan

# Copy driver with new unique name
$src = "C:\Users\Virgil\Desktop\sereno-dev\sereno-driver\bin\x64\Release\SerenoFilter.sys"
$dst = "C:\Windows\System32\drivers\$newName"
Copy-Item $src $dst -Force
Write-Host "Driver copied to $dst" -ForegroundColor Green

# Create and start service
Write-Host "Creating service..." -ForegroundColor Yellow
sc.exe create SerenoFilter type= kernel binPath= $dst start= demand
Start-Sleep -Seconds 1

Write-Host "Starting service..." -ForegroundColor Yellow
sc.exe start SerenoFilter
Start-Sleep -Seconds 2

Write-Host "`n=== Service Status ===" -ForegroundColor Cyan
sc.exe query SerenoFilter

# Test if device exists
Write-Host "`n=== Testing Device Access ===" -ForegroundColor Cyan
try {
    $handle = [System.IO.File]::Open("\\.\SerenoFilter", [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    $handle.Close()
    Write-Host "SUCCESS: Device \\.\SerenoFilter exists and is accessible!" -ForegroundColor Green
} catch {
    Write-Host "FAILED: Device \\.\SerenoFilter not accessible: $($_.Exception.Message)" -ForegroundColor Red
}
