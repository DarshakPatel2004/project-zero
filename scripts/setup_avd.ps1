<#
.SYNOPSIS
    Setup Android Emulator + Frida for DroidForensix dynamic analysis.

.DESCRIPTION
    Installs Android SDK command-line tools, platform-tools (adb),
    emulator binaries, creates a headless AVD, and deploys Frida server.

    Run this once before enabling ENABLE_DYNAMIC=true in .env.

    Requires: Windows 10+, ~8GB free disk, admin rights (for first SDK install).

    Usage:
        .\scripts\setup_avd.ps1 [-Force]

    Flags:
        -Force: Re-download SDK even if already present.
        -SkipFrida: Skip Frida server download (use if you have a custom build).
#>

param(
    [switch]$Force,
    [switch]$SkipFrida
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$ROOT = Split-Path -Parent $PSScriptRoot
$SDK_DIR = Join-Path (Join-Path $ROOT "tools") "android-sdk"
$AVD_NAME = "DroidForensix_AVD"
$API_LEVEL = 30
$ARCH = "x86"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  DroidForensix AVD + Frida Setup           " -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "SDK dir:    $SDK_DIR"
Write-Host "AVD name:   $AVD_NAME"
Write-Host "API level:  $API_LEVEL ($ARCH)"
Write-Host ""

# --------------------------------------------------
# Step 1: Install Android SDK command-line tools
# --------------------------------------------------
if ((Test-Path $SDK_DIR) -and -not $Force) {
    Write-Host "[SKIP] SDK already exists at $SDK_DIR (use -Force to reinstall)" -ForegroundColor Yellow
} else {
    Write-Host "[STEP 1] Downloading Android SDK command-line tools..." -ForegroundColor Green

    if (Test-Path $SDK_DIR) {
        Remove-Item -Recurse -Force $SDK_DIR -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Path $SDK_DIR -Force | Out-Null

    $CLI_URL = "https://dl.google.com/android/repository/commandlinetools-win-11076708_latest.zip"
    $CLI_ZIP = Join-Path $env:TEMP "cmdline-tools.zip"

    try {
        Invoke-WebRequest -Uri $CLI_URL -OutFile $CLI_ZIP -UseBasicParsing
        Expand-Archive -Path $CLI_ZIP -DestinationPath $SDK_DIR -Force
        Write-Host "  Extracted to $SDK_DIR\cmdline-tools"
    } catch {
        Write-Host "[FAIL] Download failed: $_" -ForegroundColor Red
        Write-Host "  Try downloading manually from:"
        Write-Host "  $CLI_URL"
        Write-Host "  Extract to: $SDK_DIR\cmdline-tools"
        exit 1
    }
}

    $SDKMANAGER = Join-Path (Join-Path (Join-Path $SDK_DIR "cmdline-tools") "bin") "sdkmanager.bat"
if (-not (Test-Path $SDKMANAGER)) {
    Write-Host "[FAIL] sdkmanager not found at $SDKMANAGER" -ForegroundColor Red
    exit 1
}

# --------------------------------------------------
# Step 2: Accept licenses & install platform-tools + emulator + system image
# --------------------------------------------------
Write-Host "[STEP 2] Accepting Android SDK licenses..." -ForegroundColor Green
"y" | & $SDKMANAGER --licenses --sdk_root=$SDK_DIR 2>&1 | Out-Null

Write-Host "[STEP 2] Installing platform-tools (adb), emulator, and system image..." -ForegroundColor Green
$PACKAGES = @(
    "platform-tools"
    "emulator"
    "platforms;android-$API_LEVEL"
    "system-images;android-$API_LEVEL;google_apis;$ARCH"
)
foreach ($pkg in $PACKAGES) {
    Write-Host "  Installing $pkg ..." -NoNewline
    & $SDKMANAGER --sdk_root=$SDK_DIR $pkg 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host " OK" -ForegroundColor Green
    } else {
        Write-Host " FAIL" -ForegroundColor Red
    }
}

    $ADB = Join-Path (Join-Path $SDK_DIR "platform-tools") "adb.exe"
    $EMULATOR = Join-Path (Join-Path $SDK_DIR "emulator") "emulator.exe"
if (-not (Test-Path $ADB)) {
    Write-Host "[FAIL] adb not found after install" -ForegroundColor Red
    exit 1
}

# --------------------------------------------------
# Step 3: Create AVD
# --------------------------------------------------
Write-Host "[STEP 3] Creating AVD '$AVD_NAME'..." -ForegroundColor Green
    $AVD_CREATE = Join-Path (Join-Path (Join-Path $SDK_DIR "cmdline-tools") "bin") "avdmanager.bat"
if (Test-Path $AVD_CREATE) {
    & $AVD_CREATE --sdk_root=$SDK_DIR create avd `
        -n $AVD_NAME `
        -k "system-images;android-$API_LEVEL;google_apis;$ARCH" `
        -d "pixel_4" `
        -f 2>&1 | Out-Null
    Write-Host "  AVD '$AVD_NAME' created" -ForegroundColor Green
} else {
    Write-Host "[WARN] avdmanager not found, creating AVD manually..." -ForegroundColor Yellow
    $AVD_DIR = Join-Path (Join-Path (Join-Path $env:USERPROFILE ".android") "avd") "${AVD_NAME}.avd"
    New-Item -ItemType Directory -Path $AVD_DIR -Force | Out-Null
    $CONFIG_INI = @"
avd.ini.encoding=UTF-8
path=$AVD_DIR
path.rel=avd\${AVD_NAME}.avd
target=android-$API_LEVEL
"@
    $CONFIG_INI | Out-File -FilePath (Join-Path (Split-Path $AVD_DIR -Parent) "${AVD_NAME}.ini") -Encoding utf8
    Write-Host "  Created minimal AVD at $AVD_DIR" -ForegroundColor Yellow
}

# --------------------------------------------------
# Step 4: Download & deploy Frida server
# --------------------------------------------------
if (-not $SkipFrida) {
    Write-Host "[STEP 4] Identifying Frida server version..." -ForegroundColor Green

    $FRIDA_VERSION = & $ROOT\venv\Scripts\python.exe -c "import frida; print(frida.__version__)" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[FAIL] Frida not installed. Run: pip install frida" -ForegroundColor Red
        Write-Host "  Then re-run this script."
        exit 1
    }

    $FRIDA_SERVER = "frida-server-$FRIDA_VERSION-android-x86"
    $FRIDA_URL = "https://github.com/frida/frida/releases/download/$FRIDA_VERSION/$FRIDA_SERVER.xz"
    $FRIDA_XZ = Join-Path $env:TEMP "$FRIDA_SERVER.xz"
    $FRIDA_BIN = Join-Path $SDK_DIR "frida-server"

    if ((Test-Path $FRIDA_BIN) -and -not $Force) {
        Write-Host "[SKIP] Frida server already at $FRIDA_BIN" -ForegroundColor Yellow
    } else {
        Write-Host "  Downloading $FRIDA_SERVER.xz ..."
        try {
            Invoke-WebRequest -Uri $FRIDA_URL -OutFile $FRIDA_XZ -UseBasicParsing
            # Decompress .xz using Python (7z may not handle .xz well)
            & $ROOT\venv\Scripts\python.exe -c "
import lzma, shutil, sys
with lzma.open(sys.argv[1], 'rb') as f_in:
    with open(sys.argv[2], 'wb') as f_out:
        shutil.copyfileobj(f_in, f_out)
" $FRIDA_XZ $FRIDA_BIN
            Write-Host "  Frida server extracted to $FRIDA_BIN" -ForegroundColor Green
        } catch {
            Write-Host "[FAIL] Frida server download failed: $_" -ForegroundColor Red
            Write-Host "  Download manually from: $FRIDA_URL"
            Write-Host "  Extract and place at: $FRIDA_BIN"
        }
    }
} else {
    Write-Host "[SKIP] Frida server download skipped (-SkipFrida)" -ForegroundColor Yellow
}

# --------------------------------------------------
# Step 5: Boot AVD, push Frida server, save snapshot
# --------------------------------------------------
Write-Host "[STEP 5] Booting AVD to deploy Frida server..." -ForegroundColor Green
$EMULATOR_PROC = Start-Process -FilePath $EMULATOR -ArgumentList @(
    "-avd", $AVD_NAME,
    "-no-window",
    "-no-audio",
    "-port", "5554",
    "-memory", "2048",
    "-cores", "2"
) -PassThru -NoNewWindow

Write-Host "  Waiting for device to boot (up to 120s)..." -NoNewline
$booted = $false
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Seconds 3
    $state = & $ADB get-state 2>&1
    if ($state -match "device") {
        Write-Host " OK" -ForegroundColor Green
        $booted = $true
        break
    }
    Write-Host "." -NoNewline
}
if (-not $booted) {
    Write-Host " FAIL (device not ready)" -ForegroundColor Red
    Write-Host "  You can manually push Frida server later:"
    Write-Host "  $ADB root"
    Write-Host "  $ADB push $FRIDA_BIN /data/local/tmp/frida-server"
    Write-Host "  $ADB shell chmod 755 /data/local/tmp/frida-server"
    exit 1
}

# Push Frida server to AVD
if (Test-Path $FRIDA_BIN) {
    Write-Host "  Pushing Frida server to /data/local/tmp/ ..."
    & $ADB root 2>&1 | Out-Null
    & $ADB push $FRIDA_BIN /data/local/tmp/frida-server 2>&1 | Out-Null
    & $ADB shell chmod 755 /data/local/tmp/frida-server 2>&1 | Out-Null
    Write-Host "  Frida server deployed" -ForegroundColor Green

    Write-Host "  Verifying Frida server starts..."
    & $ADB shell "/data/local/tmp/frida-server -D &" 2>&1 | Out-Null
    Start-Sleep -Seconds 2
    $FRIDA_CHECK = & $ROOT\venv\Scripts\python.exe -c "
import frida, sys
try:
    d = frida.get_usb_device(timeout=5)
    sys.exit(0)
except:
    sys.exit(1)
" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Frida server verified OK" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Frida server verification failed (may need manual start)" -ForegroundColor Yellow
        Write-Host "  Run: $ADB shell /data/local/tmp/frida-server &"
    }

    # Save snapshot
    Write-Host "  Saving snapshot 'clean'..."
    & $ADB emu avd snapshot save clean 2>&1 | Out-Null
    Write-Host "  Snapshot 'clean' saved" -ForegroundColor Green
}

# Stop emulator
& $ADB emu kill 2>&1 | Out-Null
Write-Host "  Emulator stopped" -ForegroundColor Green

# --------------------------------------------------
# Summary
# --------------------------------------------------
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Setup Complete                            " -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "SDK installed at:     $SDK_DIR"
Write-Host "AVD created:          $AVD_NAME"
Write-Host "Frida server:         $FRIDA_BIN"
Write-Host "Snapshot:             clean"
Write-Host ""
Write-Host "To enable dynamic analysis, add to .env:"
Write-Host "  ENABLE_DYNAMIC=true"
Write-Host ""
Write-Host "To run a test:"
Write-Host "  python -m analysis.pipeline <apk.apk> --dynamic"
Write-Host ""
