# DroidForensix Downloader PowerShell Script

# Navigate to the project directory
Set-Location -Path "D:\\DroidForensix"

# Load environment variables from .env file
$envPath = ".\\.env"
if (Test-Path $envPath) {
    Write-Host "Loading environment variables from $envPath..."
    
    # Read and set each environment variable
    $lines = Get-Content $envPath
    foreach ($line in $lines) {
        $line = $line.Trim()
        if ($line -and !$line.StartsWith("#") -and $line.Contains("=")) {
            $parts = $line.Split("=", 2)
            $key = $parts[0].Trim()
            $value = $parts[1].Trim()
            
            # Remove quotes if present
            if ($value.StartsWith("'") -and $value.EndsWith("'")) {
                $value = $value.Substring(1, $value.Length - 2)
            }
            
            Set-Item env:$key $value
            Write-Host "  Set $($key): $($value.Substring(0, [Math]::Min(10, $value.Length)))..."
        }
    }
} else {
    Write-Host "Warning: .env file not found at $envPath"
}

# Set PYTHONPATH
Set-Item env:PYTHONPATH "D:\\DroidForensix\\scripts"

Write-Host "Environment setup complete."
Write-Host "Ready to run DroidForensix sample downloads..."

# Run the main downloader
python scripts/download_samples.py --malware-only 10 --koodous Anubis 10

Write-Host "Script execution completed."