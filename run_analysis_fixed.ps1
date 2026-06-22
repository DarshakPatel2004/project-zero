# DroidForensix Batch Analysis PowerShell Script (with JAVA_HOME)

# Navigate to the project directory
Set-Location -Path "D:\\DroidForensix"

# Set JAVA_HOME for jadx
$env:JAVA_HOME = "C:\\Program Files\\Microsoft\\jdk-21.0.11.10-hotspot"

# Load environment variables from .env file
$envPath = ".\\.env"
if (Test-Path $envPath) {
    Write-Host "Loading environment variables from $envPath..."
    $lines = Get-Content $envPath
    foreach ($line in $lines) {
        $line = $line.Trim()
        if ($line -and !$line.StartsWith("#") -and $line.Contains("=")) {
            $parts = $line.Split("=", 2)
            $key = $parts[0].Trim()
            $value = $parts[1].Trim()
            if ($value.StartsWith("'") -and $value.EndsWith("'")) {
                $value = $value.Substring(1, $value.Length - 2)
            }
            Set-Item env:$key $value
        }
    }
}

# Set PYTHONPATH
$env:PYTHONPATH = "D:\\DroidForensix\\scripts"

Write-Host "Environment setup complete with JAVA_HOME."
Write-Host "Running DroidForensix batch analysis on new samples..."

# Run batch analysis on all pending samples
python scripts/run_batch_analysis.py --small-timeout 180 --large-timeout 600 --max-samples 0

Write-Host "Batch analysis completed."