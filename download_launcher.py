#!/usr/bin/env python3
"""
DroidForensix Sample Downloader Launcher
This script sets environment variables and calls the download_samples.py module.
"""

import os
import subprocess
import sys

def run_download():
    # Set environment variables from .env file
    env = os.environ.copy()
    
    # Read .env file
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if "=" in line:
                        key, value = line.split("=", 1)
                        env[key.strip()] = value.strip()
    
    # MalwareBazaar download
    print("Downloading 10 samples from MalwareBazaar...")
    result = subprocess.run(
        [sys.executable, "scripts/download_samples.py", "--malware-only", "10"],
        env=env,
        cwd=os.path.dirname(__file__)
    )
    
    if result.returncode == 0:
        print("✓ MalwareBazaar download complete")
    else:
        print("✗ MalwareBazaar download failed")
        sys.exit(1)
    
    return True

if __name__ == "__main__":
    run_download()