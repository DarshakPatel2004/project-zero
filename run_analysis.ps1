# DroidForensix Batch Analysis PowerShell Script

# Navigate to the project directory
Set-Location -Path "D:\\DroidForensix"

# Load environment variables from .env file
$envPath = ".\\.env"

# Set PYTHONPATH
$env:PYTHONPATH = "D:\\DroidForensix\\scripts"

Write-Host "Environment setup complete."
Write-Host "Running DroidForensix batch analysis on new samples..."

# Run batch analysis on all pending samples
python scripts/run_batch_analysis.py --small-timeout 180 --large-timeout 600 --max-samples 0

Write-Host "Batch analysis completed."