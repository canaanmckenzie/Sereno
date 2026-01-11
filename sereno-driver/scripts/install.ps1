#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs or uninstalls the Sereno WFP Callout Driver.

.DESCRIPTION
    This script manages the installation of the Sereno driver using PNPUTIL.

.PARAMETER Uninstall
    Uninstall the driver instead of installing.

.PARAMETER Configuration
    Build configuration to install from: Debug or Release. Default is Debug.

.PARAMETER Platform
    Target platform: x64 or ARM64. Default is x64.

.EXAMPLE
    .\install.ps1
    .\install.ps1 -Uninstall
    .\install.ps1 -Configuration Release
#>

param(
    [switch]$Uninstall,

    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",

    [ValidateSet("x64", "ARM64")]
    [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDir = Split-Path -Parent $scriptDir
$serviceName = "SerenoFilter"

Write-Host "Sereno Driver Installation" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
Write-Host ""

if ($Uninstall) {
    Write-Host "Uninstalling Sereno driver..." -ForegroundColor Yellow
    Write-Host ""

    # Stop the service if running
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq "Running") {
            Write-Host "Stopping service..." -ForegroundColor Yellow
            Stop-Service -Name $serviceName -Force
            Start-Sleep -Seconds 2
        }

        Write-Host "Removing service..." -ForegroundColor Yellow
        sc.exe delete $serviceName | Out-Null
    }

    # Find and remove the driver package
    Write-Host "Removing driver package..." -ForegroundColor Yellow
    $packages = pnputil /enum-drivers | Select-String -Pattern "sereno" -Context 0,10

    if ($packages) {
        foreach ($match in $packages) {
            $lines = $match.Context.PostContext + $match.Line
            $oemInf = ($lines | Select-String -Pattern "oem\d+\.inf").Matches.Value
            if ($oemInf) {
                Write-Host "  Removing $oemInf..." -ForegroundColor Gray
                pnputil /delete-driver $oemInf /force | Out-Null
            }
        }
    }

    Write-Host ""
    Write-Host "Uninstall complete." -ForegroundColor Green

} else {
    # Check for test signing
    $bcdOutput = bcdedit /enum "{current}" 2>&1
    $testsigningEnabled = $bcdOutput -match "testsigning\s+Yes"

    if (-not $testsigningEnabled) {
        Write-Host "WARNING: Test signing is not enabled!" -ForegroundColor Red
        Write-Host "Run 'scripts\enable-test-signing.ps1' as Administrator and reboot." -ForegroundColor Yellow
        Write-Host ""
        $continue = Read-Host "Continue anyway? (y/N)"
        if ($continue -ne "y" -and $continue -ne "Y") {
            exit 1
        }
    }

    # Find the built driver
    $outputDir = Join-Path $projectDir "bin\$Platform\$Configuration"
    $infPath = Join-Path $outputDir "sereno.inf"
    $sysPath = Join-Path $outputDir "SerenoFilter.sys"

    if (-not (Test-Path $sysPath)) {
        Write-Host "ERROR: Driver not found at $sysPath" -ForegroundColor Red
        Write-Host "Run 'scripts\build.ps1' first to build the driver." -ForegroundColor Yellow
        exit 1
    }

    if (-not (Test-Path $infPath)) {
        # Copy INF to output directory
        $sourceInf = Join-Path $projectDir "sereno.inf"
        Copy-Item $sourceInf $infPath -Force
    }

    Write-Host "Installing driver from: $outputDir" -ForegroundColor White
    Write-Host ""

    # Stop existing service if running
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        Write-Host "Stopping existing service..." -ForegroundColor Yellow
        Stop-Service -Name $serviceName -Force
        Start-Sleep -Seconds 2
    }

    # Install the driver package
    Write-Host "Installing driver package..." -ForegroundColor Yellow
    $result = pnputil /add-driver $infPath /install 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Host "pnputil output: $result" -ForegroundColor Gray

        # Try alternative installation via sc.exe
        Write-Host "Trying alternative installation method..." -ForegroundColor Yellow

        $driverDest = "$env:SystemRoot\System32\drivers\SerenoFilter.sys"
        Copy-Item $sysPath $driverDest -Force

        # Create the service
        sc.exe create $serviceName type= kernel binPath= $driverDest start= demand | Out-Null

        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR: Failed to install driver." -ForegroundColor Red
            exit 1
        }
    }

    Write-Host ""
    Write-Host "Driver installed successfully." -ForegroundColor Green
    Write-Host ""

    # Start the service
    $startNow = Read-Host "Start the driver now? (Y/n)"
    if ($startNow -ne "n" -and $startNow -ne "N") {
        Write-Host "Starting service..." -ForegroundColor Yellow
        Start-Service -Name $serviceName

        $service = Get-Service -Name $serviceName
        if ($service.Status -eq "Running") {
            Write-Host "Service is running." -ForegroundColor Green
        } else {
            Write-Host "WARNING: Service failed to start. Check Event Viewer for details." -ForegroundColor Red
        }
    }
}
