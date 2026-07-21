# Setup OpenCode alias with Obsidian vault context injection
# PowerShell script for Windows
# Usage: powershell -ExecutionPolicy Bypass -File Setup-OpenCodeAlias.ps1

param(
    [string]$VaultPath = "$env:USERPROFILE\Documents\my-forensics-vault",
    [string]$ScriptDir = $PSScriptRoot
)

Write-Host "Setting up OpenCode alias..." -ForegroundColor Blue

# Determine PowerShell profile location
if ($PROFILE) {
    $profilePath = $PROFILE
} else {
    $profilePath = "$env:USERPROFILE\Documents\PowerShell\profile.ps1"
}

# Create directory if it doesn't exist
$profileDir = Split-Path -Parent $profilePath
if (-not (Test-Path $profileDir)) {
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
}

# Create the PowerShell function and alias
$aliasScript = @"

# ============================================
# OpenCode + Obsidian Vault Integration
# ============================================

`$env:OBSIDIAN_VAULT = "$VaultPath"

function Invoke-OpenCodeBrain {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromRemainingArguments=`$true)]
        [string[]]`$Arguments
    )
    
    try {
        `$vaultContext = node --experimental-strip-types "$ScriptDir\Inject-Context.ts" 2>$null
        
        if (`$vaultContext) {
            # Inject context into OpenCode
            opencode --system "`$vaultContext" @Arguments
        } else {
            # Fallback if context injection fails
            Write-Host "Warning: Could not inject vault context" -ForegroundColor Yellow
            opencode @Arguments
        }
    } catch {
        Write-Host "Error: `$_" -ForegroundColor Red
        Write-Host "Attempting to run OpenCode without context..." -ForegroundColor Yellow
        opencode @Arguments
    }
}

Set-Alias -Name oc -Value Invoke-OpenCodeBrain -Force

"@

# Append to PowerShell profile
try {
    Add-Content -Path $profilePath -Value $aliasScript -Encoding UTF8
    Write-Host "✓ Added to PowerShell profile: $profilePath" -ForegroundColor Green
    Write-Host ""
    Write-Host "To apply changes, run:" -ForegroundColor White
    Write-Host "  . `$PROFILE" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Then use:" -ForegroundColor White
    Write-Host "  oc                 # OpenCode with vault context auto-loaded" -ForegroundColor Cyan
    Write-Host "  oc --help          # Show OpenCode options" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Profile location: $profilePath" -ForegroundColor Cyan
} catch {
    Write-Host "✗ Failed to update profile: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "Manual setup:" -ForegroundColor Yellow
    Write-Host "1. Open PowerShell profile: `$PROFILE" -ForegroundColor White
    Write-Host "2. Add the following:" -ForegroundColor White
    Write-Host ""
    Write-Host $aliasScript -ForegroundColor Gray
    Write-Host ""
    Write-Host "3. Save and reload PowerShell" -ForegroundColor White
}
