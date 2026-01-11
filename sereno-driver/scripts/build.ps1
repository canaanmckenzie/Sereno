<#
.SYNOPSIS
    Builds the Sereno WFP Callout Driver.

.DESCRIPTION
    This script builds the driver using MSBuild with the WDK.

.PARAMETER Configuration
    Build configuration: Debug or Release. Default is Debug.

.PARAMETER Platform
    Target platform: x64 or ARM64. Default is x64.

.PARAMETER Clean
    Clean build artifacts before building.

.EXAMPLE
    .\build.ps1 -Configuration Release -Platform x64
#>

param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",

    [ValidateSet("x64", "ARM64")]
    [string]$Platform = "x64",

    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDir = Split-Path -Parent $scriptDir
$solutionFile = Join-Path $projectDir "SerenoFilter.sln"

Write-Host "Sereno Driver Build" -ForegroundColor Cyan
Write-Host "===================" -ForegroundColor Cyan
Write-Host "Configuration: $Configuration" -ForegroundColor White
Write-Host "Platform: $Platform" -ForegroundColor White
Write-Host ""

# Find MSBuild
$msbuildPaths = @(
    "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe",
    "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe",
    "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
    "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
    "${env:ProgramFiles}\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\MSBuild.exe",
    "${env:ProgramFiles}\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe",
    "${env:ProgramFiles}\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
)

$msbuild = $null
foreach ($path in $msbuildPaths) {
    if (Test-Path $path) {
        $msbuild = $path
        break
    }
}

if (-not $msbuild) {
    # Try to find via vswhere
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -requires Microsoft.Component.MSBuild -property installationPath
        if ($vsPath) {
            $msbuild = Join-Path $vsPath "MSBuild\Current\Bin\MSBuild.exe"
        }
    }
}

if (-not $msbuild -or -not (Test-Path $msbuild)) {
    Write-Host "ERROR: Could not find MSBuild.exe" -ForegroundColor Red
    Write-Host "Please install Visual Studio 2019/2022 with C++ and WDK support." -ForegroundColor Yellow
    exit 1
}

Write-Host "Using MSBuild: $msbuild" -ForegroundColor Gray
Write-Host ""

# Clean if requested
if ($Clean) {
    Write-Host "Cleaning build artifacts..." -ForegroundColor Yellow
    $binDir = Join-Path $projectDir "bin"
    $objDir = Join-Path $projectDir "obj"

    if (Test-Path $binDir) { Remove-Item -Recurse -Force $binDir }
    if (Test-Path $objDir) { Remove-Item -Recurse -Force $objDir }

    Write-Host "Clean complete." -ForegroundColor Green
    Write-Host ""
}

# Build
Write-Host "Building driver..." -ForegroundColor Yellow
& $msbuild $solutionFile /p:Configuration=$Configuration /p:Platform=$Platform /t:Build /v:minimal

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "BUILD FAILED" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "BUILD SUCCEEDED" -ForegroundColor Green

# Output location
$outputDir = Join-Path $projectDir "bin\$Platform\$Configuration"
$driverPath = Join-Path $outputDir "SerenoFilter.sys"

if (Test-Path $driverPath) {
    Write-Host ""
    Write-Host "Output files:" -ForegroundColor Cyan
    Get-ChildItem $outputDir | ForEach-Object {
        Write-Host "  $($_.Name)" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "Driver location: $driverPath" -ForegroundColor Green
}
