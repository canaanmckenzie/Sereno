#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enables test signing mode for Windows driver development.

.DESCRIPTION
    This script enables test signing mode which allows loading of test-signed drivers.
    A reboot is required after running this script.

.NOTES
    Must be run as Administrator.
#>

param(
    [switch]$Disable
)

$ErrorActionPreference = "Stop"

Write-Host "Sereno Driver - Test Signing Configuration" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Check current status
Write-Host "Checking current boot configuration..." -ForegroundColor Yellow
$bcdOutput = bcdedit /enum "{current}" 2>&1
$testsigningEnabled = $bcdOutput -match "testsigning\s+Yes"

if ($testsigningEnabled) {
    Write-Host "Test signing is currently: ENABLED" -ForegroundColor Green
} else {
    Write-Host "Test signing is currently: DISABLED" -ForegroundColor Red
}

Write-Host ""

if ($Disable) {
    if (-not $testsigningEnabled) {
        Write-Host "Test signing is already disabled." -ForegroundColor Yellow
        exit 0
    }

    Write-Host "Disabling test signing mode..." -ForegroundColor Yellow
    bcdedit /set testsigning off

    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "Test signing has been DISABLED." -ForegroundColor Green
        Write-Host "A REBOOT is required for changes to take effect." -ForegroundColor Yellow
        Write-Host ""

        $restart = Read-Host "Restart now? (y/N)"
        if ($restart -eq "y" -or $restart -eq "Y") {
            Restart-Computer -Force
        }
    } else {
        Write-Host "Failed to disable test signing." -ForegroundColor Red
        exit 1
    }
} else {
    if ($testsigningEnabled) {
        Write-Host "Test signing is already enabled." -ForegroundColor Yellow
        exit 0
    }

    Write-Host "Enabling test signing mode..." -ForegroundColor Yellow
    bcdedit /set testsigning on

    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "Test signing has been ENABLED." -ForegroundColor Green
        Write-Host "A REBOOT is required for changes to take effect." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "After reboot, you will see 'Test Mode' watermark on desktop." -ForegroundColor Cyan
        Write-Host ""

        $restart = Read-Host "Restart now? (y/N)"
        if ($restart -eq "y" -or $restart -eq "Y") {
            Restart-Computer -Force
        }
    } else {
        Write-Host "Failed to enable test signing." -ForegroundColor Red
        Write-Host ""
        Write-Host "If Secure Boot is enabled, you may need to disable it in BIOS/UEFI." -ForegroundColor Yellow
        exit 1
    }
}
