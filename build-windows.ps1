$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=== NetworkToolbelt Portable Build ===" -ForegroundColor Cyan
Write-Host ""

# ── Clean previous artifacts ──────────────────────────────
Write-Host "Cleaning previous build artifacts..."
if (Test-Path "build") { Remove-Item "build" -Recurse -Force }
if (Test-Path "dist")  { Remove-Item "dist"  -Recurse -Force }

# ── Build ─────────────────────────────────────────────────
if (Test-Path "NetworkToolbelt.spec") {
    Write-Host "Building from NetworkToolbelt.spec..."
    Write-Host "Note: PyInstaller options are controlled by the spec file. Edit the spec file to change build settings."
    python -m PyInstaller --noconfirm --clean NetworkToolbelt.spec
} else {
    Write-Host "No NetworkToolbelt.spec file found. Building from command-line options..."
    python -m PyInstaller `
      --noconfirm `
      --clean `
      --noupx `
      --onedir `
      --windowed `
      --name NetworkToolbelt `
      --collect-all netmiko `
      --collect-all paramiko `
      --collect-all cryptography `
      --collect-all bcrypt `
      --collect-all nacl `
      --collect-all ntc_templates `
      --collect-all textfsm `
      network-toolbelt.pyw
}

# ── Validate ──────────────────────────────────────────────
$exePath = "dist\NetworkToolbelt\NetworkToolbelt.exe"
if (-not (Test-Path $exePath)) {
    Write-Host "ERROR: $exePath not found. Build failed." -ForegroundColor Red
    exit 1
}
Write-Host "Build OK: $exePath" -ForegroundColor Green

# ── Create portable ZIP ──────────────────────────────────
Write-Host "Creating portable ZIP..."
Compress-Archive `
  -Path "dist\NetworkToolbelt" `
  -DestinationPath "dist\NetworkToolbelt-portable.zip" `
  -Force

if (-not (Test-Path "dist\NetworkToolbelt-portable.zip")) {
    Write-Host "ERROR: dist\NetworkToolbelt-portable.zip not found. ZIP creation failed." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Build complete!" -ForegroundColor Green
Write-Host "  EXE: dist\NetworkToolbelt\NetworkToolbelt.exe"
Write-Host "  ZIP: dist\NetworkToolbelt-portable.zip"
Write-Host ""
