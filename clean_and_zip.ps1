# ─── Shadow Guardian — Clean & Package ──────────────────────────────
# Cleans user data, rebuilds, and creates a distributable ZIP with
# structure: ShadowGuardian-Release.zip > Shadow Guardian > files
# ────────────────────────────────────────────────────────────────────

# 1. Clean local app data from previous installs
$targetDir = "$env:LOCALAPPDATA\ShadowGuardian"
if (Test-Path $targetDir) {
    Write-Host "[CLEAN] Removing $targetDir ..."
    Remove-Item -Recurse -Force $targetDir -ErrorAction SilentlyContinue
}

# 2. Determine source directory (PyInstaller output)
$source = $null
if (Test-Path 'dist\ShadowGuardian') {
    $source = 'dist\ShadowGuardian'
} elseif (Test-Path 'dist\Shadow Guardian') {
    $source = 'dist\Shadow Guardian'
} else {
    Write-Host "[ERROR] No build output found in dist\. Run build.py first."
    exit 1
}

# 3. Create a clean staging folder with the correct name
$staging = 'dist\_staging\Shadow Guardian'
if (Test-Path 'dist\_staging') {
    Remove-Item -Recurse -Force 'dist\_staging'
}
New-Item -ItemType Directory -Path $staging -Force | Out-Null

# 4. Copy all build artifacts into the staging folder
Write-Host "[COPY] $source  ->  $staging"
Copy-Item -Path "$source\*" -Destination $staging -Recurse -Force

# 5. Create the ZIP  (ZIP > Shadow Guardian > files with exe)
$zipName = 'ShadowGuardian-Release.zip'
if (Test-Path $zipName) { Remove-Item $zipName -Force }

Write-Host "[ZIP]  Creating $zipName ..."
Compress-Archive -Path $staging -DestinationPath $zipName -Force

# 6. Cleanup staging
Remove-Item -Recurse -Force 'dist\_staging'

Write-Host ""
Write-Host "========================================="
Write-Host "  Done!  ->  $zipName"
Write-Host "  Structure: Shadow Guardian\ShadowGuardian.exe + files"
Write-Host "========================================="
