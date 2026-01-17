# Run this script as Administrator!
# Right-click PowerShell -> Run as Administrator, then: .\fix-driver.ps1

Write-Host "=== Sereno Driver Fix Script ===" -ForegroundColor Cyan

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: Must run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell -> Run as Administrator" -ForegroundColor Yellow
    exit 1
}

# Step 1: Enable test signing
Write-Host "`n[1] Enabling test signing..." -ForegroundColor Yellow
bcdedit /set testsigning on
if ($LASTEXITCODE -eq 0) {
    Write-Host "   Test signing enabled" -ForegroundColor Green
} else {
    Write-Host "   Failed to enable test signing" -ForegroundColor Red
}

# Step 2: Check/add WDKTestCert to Root store
Write-Host "`n[2] Checking WDKTestCert in Root store..." -ForegroundColor Yellow
$thumbprint = "1DC360B0502EDDBF7424ADF0D18EEDB70904523F"
$rootCert = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $thumbprint }
if ($rootCert) {
    Write-Host "   Already present: $($rootCert.Subject)" -ForegroundColor Green
} else {
    Write-Host "   Not found - looking for cert to add..." -ForegroundColor Yellow
    # Try to find it in other stores
    $cert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $thumbprint } |
            Select-Object -First 1
    if ($cert) {
        Write-Host "   Found cert, adding to Root store..." -ForegroundColor Yellow
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
        $store.Open("ReadWrite")
        $store.Add($cert)
        $store.Close()
        Write-Host "   Added to Root store" -ForegroundColor Green
    } else {
        Write-Host "   WARNING: Cert not found anywhere. You may need to re-sign the driver." -ForegroundColor Red
    }
}

# Step 3: Check/add WDKTestCert to TrustedPublisher store
Write-Host "`n[3] Checking WDKTestCert in TrustedPublisher store..." -ForegroundColor Yellow
$pubCert = Get-ChildItem Cert:\LocalMachine\TrustedPublisher | Where-Object { $_.Thumbprint -eq $thumbprint }
if ($pubCert) {
    Write-Host "   Already present: $($pubCert.Subject)" -ForegroundColor Green
} else {
    Write-Host "   Not found - looking for cert to add..." -ForegroundColor Yellow
    $cert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $thumbprint } |
            Select-Object -First 1
    if ($cert) {
        Write-Host "   Found cert, adding to TrustedPublisher store..." -ForegroundColor Yellow
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher", "LocalMachine")
        $store.Open("ReadWrite")
        $store.Add($cert)
        $store.Close()
        Write-Host "   Added to TrustedPublisher store" -ForegroundColor Green
    } else {
        Write-Host "   WARNING: Cert not found anywhere." -ForegroundColor Red
    }
}

# Step 4: Try to start driver
Write-Host "`n[4] Attempting to start SerenoFilter..." -ForegroundColor Yellow
sc.exe start SerenoFilter
if ($LASTEXITCODE -eq 0) {
    Write-Host "   Driver started successfully!" -ForegroundColor Green
} elseif ($LASTEXITCODE -eq 1056) {
    Write-Host "   Driver already running" -ForegroundColor Green
} else {
    Write-Host "   Start failed - may need reboot for test signing to take effect" -ForegroundColor Yellow
    Write-Host "   Error code: $LASTEXITCODE" -ForegroundColor Yellow
}

# Final status
Write-Host "`n[5] Final Status:" -ForegroundColor Yellow
sc.exe query SerenoFilter

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
$bcd = bcdedit 2>&1
if ($bcd -match "testsigning\s+Yes") {
    Write-Host "Test Signing: ENABLED" -ForegroundColor Green
} else {
    Write-Host "Test Signing: Changed - REBOOT REQUIRED" -ForegroundColor Yellow
}

Write-Host "`nIf driver failed to start, REBOOT and then run:" -ForegroundColor Yellow
Write-Host "   sc.exe start SerenoFilter" -ForegroundColor White
Write-Host "   .\dev.ps1 -Run" -ForegroundColor White
