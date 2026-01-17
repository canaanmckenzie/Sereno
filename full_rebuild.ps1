# Full driver rebuild, sign, and install script
# Run as Administrator!
$ErrorActionPreference = "Stop"

$projectDir = "C:\Users\Virgil\Desktop\sereno-dev"
$driverDir = "$projectDir\sereno-driver"
$driverSrc = "$driverDir\bin\x64\Release\SerenoFilter.sys"
$signtool = "C:\Program Files (x86)\Windows Kits\10\App Certification Kit\signtool.exe"
$certThumbprint = "1DC360B0502EDDBF7424ADF0D18EEDB70904523F"  # WDKTestCert

Write-Host "=== FULL DRIVER REBUILD ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Stop driver if running
Write-Host "Step 1: Stopping driver..." -ForegroundColor Yellow
sc.exe stop SerenoFilter 2>&1 | Out-Null
sc.exe delete SerenoFilter 2>&1 | Out-Null
Start-Sleep -Seconds 3

# Step 2: Clean up old files
Write-Host "Step 2: Cleaning up old driver files..." -ForegroundColor Yellow
Remove-Item C:\Windows\System32\drivers\Sereno*.sys -Force -ErrorAction SilentlyContinue
Remove-Item C:\Windows\System32\drivers\Sereno*.old -Force -ErrorAction SilentlyContinue

# Step 3: Rebuild driver
Write-Host "Step 3: Rebuilding driver..." -ForegroundColor Yellow
Push-Location $driverDir
try {
    & ".\scripts\build.ps1" -Configuration Release -Platform x64 -Clean
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed!"
    }
} finally {
    Pop-Location
}

if (-not (Test-Path $driverSrc)) {
    Write-Host "ERROR: Built driver not found at $driverSrc" -ForegroundColor Red
    exit 1
}
Write-Host "Driver built successfully." -ForegroundColor Green

# Step 4: Sign driver
Write-Host "Step 4: Signing driver with WDKTestCert..." -ForegroundColor Yellow
& $signtool sign /v /sha1 $certThumbprint /fd sha256 $driverSrc
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Driver signing failed!" -ForegroundColor Red
    exit 1
}
Write-Host "Driver signed." -ForegroundColor Green

# Step 5: Install with unique filename
$ts = Get-Date -Format "HHmmss"
$newName = "Sereno$ts.sys"
$dstPath = "C:\Windows\System32\drivers\$newName"

Write-Host "Step 5: Installing driver as $newName..." -ForegroundColor Yellow
Copy-Item $driverSrc $dstPath -Force
Write-Host "Driver installed." -ForegroundColor Green

# Step 6: Create and start service
Write-Host "Step 6: Creating and starting service..." -ForegroundColor Yellow
sc.exe create SerenoFilter type= kernel binPath= $dstPath start= demand
Start-Sleep -Seconds 1
sc.exe start SerenoFilter
Start-Sleep -Seconds 2

# Step 7: Verify
Write-Host ""
Write-Host "=== VERIFICATION ===" -ForegroundColor Cyan
sc.exe query SerenoFilter

Write-Host ""
Write-Host "Testing device access..." -ForegroundColor Yellow
try {
    $handle = [System.IO.FileStream]::new("\\.\SerenoFilter", [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)
    $handle.Close()
    Write-Host "SUCCESS: Device is accessible!" -ForegroundColor Green
} catch {
    # FileStream doesn't work with devices, try CreateFile approach
    Write-Host "Note: FileStream doesn't work with devices (expected), checking via CLI..." -ForegroundColor Gray
}

Write-Host ""
Write-Host "Running CLI status..." -ForegroundColor Yellow
& "$projectDir\target\x86_64-pc-windows-msvc\debug\sereno.exe" status

Write-Host ""
Write-Host "=== REBUILD COMPLETE ===" -ForegroundColor Cyan
