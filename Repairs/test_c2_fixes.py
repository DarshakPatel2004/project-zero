#!/usr/bin/env python3
"""
Minimal test of C2 extraction fixes on your actual APK samples.
Run: python3 test_c2_fixes.py
"""

import sys
import json
import re
from pathlib import Path
from urllib.parse import urlparse

# Import the FIXED C2 extraction module
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analysis.step5_c2_extraction import is_benign_url, calculate_c2_confidence, parse_url

import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

print("="*70)
print("C2 EXTRACTION FIX VERIFICATION TEST")
print("="*70)

# Test 1: Benign domain filtering (fixes jRPN false positive)
print("\n[TEST 1] Benign Domain Filtering")
print("-" * 70)

benign_urls = [
    "http://java.sun.com/dtd/properties.dtd",
    "http://www.w3.org/2001/XMLSchema",
    "http://android.com/",
]

print("Should be FILTERED (benign):")
for url in benign_urls:
    result = is_benign_url(url)
    status = "✓ FILTERED" if result else "✗ PASSED"
    print(f"  {url}: {status}")
    if not result:
        print(f"    ERROR: Should have been filtered!")

# Test 2: Malicious URLs should NOT be filtered
print("\nShould be ALLOWED (potentially malicious):")

malicious_urls = [
    "https://47.116.192.150:444/cBYFilXD/HNbfYsYd8Shi2GHLBHyb-gDN9Hwbd6Itpm3jtM4fQpWreFMkgGdQyEmayxRNMBKyMfb6kZsi71hMzOxV8VpPRQrcsurLqQCsGxh7PvRmdUTTbgDb/",
    "https://evil-c2.example.com/beacon",
]

for url in malicious_urls:
    result = is_benign_url(url)
    status = "✓ ALLOWED" if not result else "✗ BLOCKED"
    print(f"  {url[:60]}...: {status}")
    if result:
        print(f"    ERROR: Should NOT have been filtered!")

# Test 3: C2 confidence calculation (fixes Metasploit under-detection)
print("\n[TEST 2] C2 Confidence Scoring")
print("-" * 70)

test_cases = [
    {
        "url": "https://47.116.192.150:444/cBYFilXD/endpoint",
        "name": "Metasploit C2 (private IP, HTTPS, path)",
        "expected_min": 0.75,
    },
    {
        "url": "http://malicious.tk/beacon",
        "name": "Freenom malicious domain",
        "expected_min": 0.60,
    },
    {
        "url": "http://java.sun.com/dtd/properties.dtd",
        "name": "Benign DTD (would be filtered anyway)",
        "expected_min": 0.0,
    },
]

for test in test_cases:
    url = test["url"]
    parsed = parse_url(url)
    
    if parsed:
        confidence = calculate_c2_confidence(parsed, "unknown")
        expected = test["expected_min"]
        status = "✓ PASS" if confidence >= expected else "⚠ LOW"
        print(f"\n  {test['name']}")
        print(f"    URL: {url[:60]}...")
        print(f"    Confidence: {confidence:.2f} (expected >= {expected:.2f}) {status}")
        
        if confidence < expected:
            print(f"    Details: domain={parsed.get('domain')}, ip={parsed.get('ip')}, path={parsed.get('path')}")

# Test 4: Summary
print("\n" + "="*70)
print("EXPECTED RESULTS AFTER FIX")
print("="*70)
print("\njRPN Calculator (should be benign):")
print("  ✓ java.sun.com/dtd/properties.dtd filtered out")
print("  ✓ C2 count: 0 (was 1)")
print("  ✓ Threat chains: 0 (was 82)")
print("  ✓ Risk score: < 20 (was 75)")

print("\nMetasploit Stager (should be malware):")
print("  ✓ 47.116.192.150:444/... C2 found")
print("  ✓ C2 confidence: >= 0.75 (was too low)")
print("  ✓ Risk score: 80+ (was 59)")
print("\nNote: jrpn.jovial.com is intentionally filtered as a benign app domain.")

print("\n" + "="*70)
print("To test against full pipeline, run:")
print("  python analysis/pipeline.py <path_to_apk>")
print("="*70)
