# Archive debug log with timestamp
$logFile = "sereno-debug.log"
$archiveDir = "debug-archives"

if (-not (Test-Path $logFile)) {
    Write-Host "No log file to archive"
    exit
}

# Create archive dir
if (-not (Test-Path $archiveDir)) {
    New-Item -ItemType Directory -Path $archiveDir | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$originalSize = (Get-Item $logFile).Length
$archivePath = "$archiveDir\sereno-debug-$timestamp.zip"

# Compress
Compress-Archive -Path $logFile -DestinationPath $archivePath -CompressionLevel Optimal

$compressedSize = (Get-Item $archivePath).Length
$ratio = [math]::Round(($compressedSize / $originalSize) * 100, 1)

# Clear log
Set-Content $logFile ""

Write-Host "Archived: $archivePath" -ForegroundColor Green
Write-Host "Size: $([math]::Round($originalSize/1KB)) KB -> $([math]::Round($compressedSize/1KB)) KB ($ratio%)" -ForegroundColor Cyan
Write-Host "Fresh log started" -ForegroundColor Yellow
