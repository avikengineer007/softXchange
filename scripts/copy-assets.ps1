<#
.SYNOPSIS
    softXchange 3D Asset Distribution Script
    Copies shared 3D assets from packages/ into each service's static directory.

.DESCRIPTION
    Replaces symlinks (which require admin/Developer Mode on Windows) with a
    simple copy step. Run this after:
      - npm run 3d:generate     (regenerating .glb models)
      - vendoring a new Three.js version

    Single source of truth: packages/3d-assets/ and packages/vendor/
    Distributed to each service that needs 3D: currently listings-service only
    (auth-service index.html redirects to listings-service).

.EXAMPLE
    .\scripts\copy-assets.ps1
    .\scripts\copy-assets.ps1 -Verbose
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot

function Copy-IfNewer {
    param(
        [string]$Src,
        [string]$Dst
    )
    $srcItem = Get-Item $Src
    if (Test-Path $Dst) {
        $dstItem = Get-Item $Dst
        if ($srcItem.LastWriteTime -le $dstItem.LastWriteTime) {
            Write-Verbose "  skip (up-to-date)  $([System.IO.Path]::GetFileName($Dst))"
            return
        }
    }
    Copy-Item -Path $Src -Destination $Dst -Force
    $kb = [math]::Round($srcItem.Length / 1024, 1)
    Write-Host "  copied  $([System.IO.Path]::GetFileName($Dst))  ($kb KB)"
}

Write-Host ""
Write-Host " softXchange -- copy-assets"
Write-Host " -----------------------------------------------------"

# ── Source directories ────────────────────────────────────────────────────────
$AssetsDir = Join-Path $Root "packages\3d-assets"
$VendorDir = Join-Path $Root "packages\vendor"

# ── Target: web-unified (canonical unified frontend host) ────────────────────
$WebUnifiedJs = Join-Path $Root "apps\web-unified\static\js"
$WebUnifiedVendor = Join-Path $WebUnifiedJs "vendor"

New-Item -ItemType Directory -Force -Path $WebUnifiedVendor | Out-Null

Write-Host ""
Write-Host " → web-unified/static/js/"

# 3D model assets
foreach ($glb in Get-ChildItem -Path $AssetsDir -Filter "*.glb") {
    Copy-IfNewer -Src $glb.FullName -Dst (Join-Path $WebUnifiedJs $glb.Name)
}

# 3D modules (tier-detection.js, hero-3d.js, card-tilt.js)
$ThreeDDir = Join-Path $Root "packages\3d"
foreach ($js in Get-ChildItem -Path $ThreeDDir -Filter "*.js") {
    Copy-IfNewer -Src $js.FullName -Dst (Join-Path $WebUnifiedJs $js.Name)
}

# Vendor: Three.js and GLTFLoader
Write-Host ""
Write-Host " → web-unified/static/js/vendor/"
foreach ($vendor in Get-ChildItem -Path $VendorDir -Filter "*.js") {
    Copy-IfNewer -Src $vendor.FullName -Dst (Join-Path $WebUnifiedVendor $vendor.Name)
}

# ── Target: Android (app/src/main/res/raw) ────────────────────────────────────
$AndroidRaw = Join-Path $Root "apps\android\app\src\main\res\raw"
if (Test-Path $AndroidRaw) {
    Write-Host ""
    Write-Host " → android/app/src/main/res/raw/"
    # Android raw resources must use lowercase letters and underscores (no hyphens)
    $androidHiSrc = Join-Path $AssetsDir "logo-hi.glb"
    $androidLoSrc = Join-Path $AssetsDir "logo-lo.glb"
    if (Test-Path $androidHiSrc) {
        Copy-IfNewer -Src $androidHiSrc -Dst (Join-Path $AndroidRaw "logo_hi.glb")
    }
    if (Test-Path $androidLoSrc) {
        Copy-IfNewer -Src $androidLoSrc -Dst (Join-Path $AndroidRaw "logo_lo.glb")
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host " [OK] Asset distribution complete."
$glbCount = (Get-ChildItem $WebUnifiedJs -Filter "*.glb").Count
$jsCount  = (Get-ChildItem $WebUnifiedVendor -Filter "*.js").Count
$androidCount = if (Test-Path $AndroidRaw) { (Get-ChildItem $AndroidRaw -Filter "*.glb").Count } else { 0 }
Write-Host "   3D assets (web):     $glbCount .glb files"
Write-Host "   3D assets (Android): $androidCount .glb files"
Write-Host "   Vendor:              $jsCount .js files"
Write-Host ""
