# DroidForensix Downloader PowerShell Script

# Navigate to the project directory
Set-Location -Path "D:\\DroidForensix"

# Source the .env file to load environment variables
. .\\.env

# Load Python module path
$env:PYTHONPATH = "D:\\DroidForensix\\scripts"

Write-Host "Starting DroidForensix sample downloads..."
Write-Host "Environment variables loaded:"
Get-ChildItem Env: | Where-Object Name -like "*API*" | ForEach-Object {
    Write-Host "  $($_.Name): $($_.Value.Substring(0,10))..."
}

# Import and run the download samples module
python scripts/download_samples.py --malware-only 10

Write-Host "Script execution completed."