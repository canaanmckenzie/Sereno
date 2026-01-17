Write-Host "=== Checking Sereno Driver Status ===" -ForegroundColor Cyan

# Check test signing
Write-Host "`n[1] Test Signing:" -ForegroundColor Yellow
$bcd = bcdedit 2>&1
if ($bcd -match "testsigning\s+Yes") {
    Write-Host "   ENABLED" -ForegroundColor Green
} else {
    Write-Host "   DISABLED - Driver will not load!" -ForegroundColor Red
    Write-Host "   Run: bcdedit /set testsigning on" -ForegroundColor Red
}

# Check certs
Write-Host "`n[2] WDKTestCert in Root:" -ForegroundColor Yellow
$rootCert = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq "1DC360B0502EDDBF7424ADF0D18EEDB70904523F" }
if ($rootCert) {
    Write-Host "   FOUND: $($rootCert.Subject)" -ForegroundColor Green
} else {
    Write-Host "   MISSING - Need to add cert to Root store" -ForegroundColor Red
}

Write-Host "`n[3] WDKTestCert in TrustedPublisher:" -ForegroundColor Yellow
$pubCert = Get-ChildItem Cert:\LocalMachine\TrustedPublisher | Where-Object { $_.Thumbprint -eq "1DC360B0502EDDBF7424ADF0D18EEDB70904523F" }
if ($pubCert) {
    Write-Host "   FOUND: $($pubCert.Subject)" -ForegroundColor Green
} else {
    Write-Host "   MISSING - Need to add cert to TrustedPublisher store" -ForegroundColor Red
}

# Check driver file
Write-Host "`n[4] Driver File:" -ForegroundColor Yellow
$driverPath = "C:\Windows\System32\drivers\SerenoFilter.sys"
if (Test-Path $driverPath) {
    $file = Get-Item $driverPath
    Write-Host "   EXISTS: $($file.Length) bytes, modified $($file.LastWriteTime)" -ForegroundColor Green
} else {
    Write-Host "   MISSING" -ForegroundColor Red
}

# Verify signature
Write-Host "`n[5] Signature Verification:" -ForegroundColor Yellow
$signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
$result = & $signtool verify /pa $driverPath 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "   PASSES (signtool /pa)" -ForegroundColor Green
} else {
    Write-Host "   FAILS: $result" -ForegroundColor Red
}

# Check driver status
Write-Host "`n[6] Driver Service:" -ForegroundColor Yellow
$svc = sc.exe query SerenoFilter 2>&1
if ($svc -match "RUNNING") {
    Write-Host "   RUNNING" -ForegroundColor Green
} elseif ($svc -match "STOPPED") {
    Write-Host "   STOPPED" -ForegroundColor Yellow
} else {
    Write-Host "   $svc" -ForegroundColor Red
}

# Try to start if stopped
if ($svc -match "STOPPED") {
    Write-Host "`n[7] Attempting to start driver..." -ForegroundColor Yellow
    $startResult = sc.exe start SerenoFilter 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "   SUCCESS!" -ForegroundColor Green
    } else {
        Write-Host "   FAILED: $startResult" -ForegroundColor Red

        # Check code integrity log for clues
        Write-Host "`n[8] Recent Code Integrity Events:" -ForegroundColor Yellow
        Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 10 2>$null |
            Where-Object { $_.Message -match "SerenoFilter|driver|signature" } |
            ForEach-Object { Write-Host "   $($_.TimeCreated): $($_.Message.Substring(0, [Math]::Min(100, $_.Message.Length)))..." }
    }
}

Write-Host "`n=== Done ===" -ForegroundColor Cyan
