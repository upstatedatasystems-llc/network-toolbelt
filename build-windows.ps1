# PowerShell script to build Network Toolbelt standalone release and verify it
$ErrorActionPreference = "Stop"

Write-Host "=== 1. Starting Build Process ==="

# Run PyInstaller with spec file
Write-Host "Running PyInstaller on NetworkToolbelt.spec..."
.venv\Scripts\pyinstaller --clean NetworkToolbelt.spec

Write-Host "=== 2. Creating Portable ZIP ==="
if (Test-Path "dist/NetworkToolbelt-portable.zip") {
    Remove-Item "dist/NetworkToolbelt-portable.zip"
}

Compress-Archive -Path "dist/NetworkToolbelt/*" -DestinationPath "dist/NetworkToolbelt-portable.zip"
Write-Host "Created dist/NetworkToolbelt-portable.zip successfully."

Write-Host "=== 3. Packaging Verification ==="
# Smoke test checks
if (-not (Test-Path "dist/NetworkToolbelt/NetworkToolbelt.exe")) {
    throw "Verification failed: NetworkToolbelt.exe not found."
}

if (-not (Test-Path "dist/NetworkToolbelt/_internal/pysnmp")) {
    throw "Verification failed: Bundled pysnmp folder not found in _internal."
}

if (-not (Test-Path "dist/NetworkToolbelt/_internal/cryptography")) {
    throw "Verification failed: Bundled cryptography folder not found in _internal."
}

Write-Host "Smoke tests passed. The standalone executable is ready."
Write-Host "Run the following command to execute packaged self-tests:"
Write-Host "  .\dist\NetworkToolbelt\NetworkToolbelt.exe --self-test"
