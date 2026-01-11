# Run Sereno Service with Administrator privileges
# This script will prompt for UAC elevation

$servicePath = "$PSScriptRoot\target\x86_64-pc-windows-msvc\release\sereno-service.exe"
$logPath = "$PSScriptRoot\sereno.log"

if (-not (Test-Path $servicePath)) {
    Write-Host "Building release version..."
    cargo build -p sereno-service --release
}

Write-Host "Starting Sereno Service with Administrator privileges..."
Write-Host "Log file: $logPath"
Write-Host ""
Write-Host "Press Ctrl+C in the elevated window to stop the service."

# Start elevated process
Start-Process -FilePath $servicePath -Verb RunAs
