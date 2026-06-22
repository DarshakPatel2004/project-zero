# DroidForensix Batch Analysis PowerShell Script (fixed)

Set-Location -Path "D:\\DroidForensix"

# Set JAVA_HOME for jadx
$env:JAVA_HOME = "C:\\Program Files\\Microsoft\\jdk-21.0.11.10-hotspot"

# Disable NVIDIA NIM to force Ollama fallback
$env:NVIDIA_NIM_API_KEY = ""

$env:OLLAMA_HOST = "http://localhost:11434"

Write-Host "JAVA_HOME: $env:JAVA_HOME"
Write-Host "Running batch analysis..."

python scripts/run_batch_analysis.py --small-timeout 300 --large-timeout 900 --max-samples 0

Write-Host "Done."