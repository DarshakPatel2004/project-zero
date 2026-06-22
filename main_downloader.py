#!/usr/bin/env python3
"""
Main DroidForensix Sample Downloader
Executes the full download pipeline for MalwareBazaar, Koodous, and AndroZoo
"""

import os
import sys
import time

def load_env():
    """Load environment variables from .env file"""
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ[key.strip()] = value.strip()
    else:
        print("Warning: .env file not found")

def run_malwarebazaar():
    """Download 10 samples from MalwareBazaar"""
    print("=" * 60)
    print("1. Downloading 10 samples from MalwareBazaar")
    print("=" * 60)
    
    import scripts.download_samples
    result = scripts.download_samples.fetch_malware(10)
    print(f"MalwareBazaar fetch complete. Downloaded: {result} samples")
    return result

def run_koodous(search_family="Anubis"):
    """Download 10 samples from Koodous by family"""
    print("=" * 60)
    print(f"2. Downloading 10 samples from Koodous (family: {search_family})")
    print("=" * 60)
    
    import scripts.download_samples
    result = scripts.download_samples.fetch_koodous(10, search=search_family)
    print(f"Koodous fetch complete. Downloaded: {result} samples")
    return result

def run_androzoo_modern():
    """Download 10 modern-market samples from AndroZoo"""
    print("=" * 60)
    print("3. Downloading 10 modern-market samples from AndroZoo")
    print("=" * 60)
    
    import scripts.download_samples
    result = scripts.download_samples.fetch_androzoo(10, min_vt=2)
    print(f"AndroZoo fetch complete. Downloaded: {result} samples")
    return result

def main():
    print("DroidForensix Sample Downloader - Full Pipeline")
    print("=" * 60)
    
    # Load environment variables
    load_env()
    
    # Run downloads
    try:
        mb_result = run_malwarebazaar()
        koodous_result = run_koodous("Anubis")  # Default to Anubis as requested
        androzoo_result = run_androzoo_modern()
        
        # Summary
        print("\n" + "=" * 60)
        print("DOWNLOAD SUMMARY")
        print("=" * 60)
        print(f"MalwareBazaar samples: {mb_result}")
        print(f"Koodous samples (Anubis): {koodous_result}")
        print(f"AndroZoo samples (modern markets): {androzoo_result}")
        print(f"Total samples downloaded: {mb_result + koodous_result + androzoo_result}")
        print("=" * 60)
        
    except Exception as e:
        print(f"Error during download: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()