#!/usr/bin/env python3
"""
Metasploit Stager Debugger
==========================

Diagnoses why the pipeline fails to detect Metasploit Android payloads.

Metasploit staggers typically:
1. Are small (~10-50KB) with minimal legitimate app code
2. Use reflection/dynamic loading to unpack payload
3. Contain Base64-encoded DEX or native payloads
4. Make callback requests (HTTP/DNS) at runtime
5. Use obfuscated strings and indirect API calls

This tool helps you understand why your C2 and payload detectors are missing them.
"""

import re
import base64
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from collections import Counter


@dataclass
class StringIndicator:
    """A suspicious string found in the APK."""
    value: str
    encoding: str = "plaintext"  # plaintext, base64, hex, xor, etc.
    context: str = ""  # Where it was found
    threat_type: str = ""  # "callback", "class_ref", "api_call", "encoding_key"
    confidence: float = 0.5


@dataclass
class APIUsageIndicator:
    """A suspicious API call found in decompiled code."""
    api_name: str
    full_path: str  # e.g., java.lang.reflect.Method.invoke
    occurrences: int = 1
    threat_type: str = ""  # "reflection", "dynamic_load", "process_execution"
    confidence: float = 0.5


@dataclass
class MetasploitSignature:
    """Collection of detected Metasploit indicators."""
    apk_name: str
    file_size_kb: int
    
    # Decompilation
    class_count: int = 0
    string_count: int = 0
    
    # Indicators
    suspicious_strings: List[StringIndicator] = field(default_factory=list)
    api_usage: List[APIUsageIndicator] = field(default_factory=list)
    
    # Scores
    obfuscation_score: float = 0.0
    reflection_density: float = 0.0  # reflection_calls / class_count
    dynamic_load_density: float = 0.0  # dynamic_load_calls / class_count
    
    # Audit
    audit_notes: List[str] = field(default_factory=list)


class MetasploitDetector:
    """Analyzes APK to identify Metasploit stager characteristics."""
    
    # Patterns: dangerous APIs used by Metasploit staggers
    DANGEROUS_APIS = {
        # Reflection (runtime class loading)
        r"java\.lang\.reflect\.Method": {
            "type": "reflection",
            "weight": 0.8,
            "reason": "Runtime method invocation (bytecode unpacking)"
        },
        r"java\.lang\.reflect\.Class\.forName": {
            "type": "reflection",
            "weight": 0.85,
            "reason": "Dynamic class loading by name"
        },
        r"java\.lang\.reflect\.Field": {
            "type": "reflection",
            "weight": 0.7,
            "reason": "Runtime field access"
        },
        r"java\.lang\.reflect\.Constructor": {
            "type": "reflection",
            "weight": 0.75,
            "reason": "Dynamic constructor invocation"
        },
        
        # Dynamic loading (ClassLoader)
        r"DexClassLoader": {
            "type": "dynamic_load",
            "weight": 0.95,
            "reason": "Android DEX class injection (critical stager indicator)"
        },
        r"PathClassLoader": {
            "type": "dynamic_load",
            "weight": 0.85,
            "reason": "Android path-based class loading"
        },
        r"BaseDexClassLoader": {
            "type": "dynamic_load",
            "weight": 0.9,
            "reason": "Base DEX class loader"
        },
        r"java\.lang\.ClassLoader\.(loadClass|defineClass)": {
            "type": "dynamic_load",
            "weight": 0.8,
            "reason": "Runtime class loading mechanism"
        },
        
        # Process execution
        r"Runtime\.getRuntime\(\)\.exec": {
            "type": "process_execution",
            "weight": 0.85,
            "reason": "Native code/shell execution"
        },
        r"java\.lang\.ProcessBuilder": {
            "type": "process_execution",
            "weight": 0.8,
            "reason": "Process builder (obfuscated execution)"
        },
        
        # Network callbacks
        r"java\.net\.HttpURLConnection": {
            "type": "callback",
            "weight": 0.75,
            "reason": "HTTP callback (potential C2)"
        },
        r"java\.net\.URLConnection\.openConnection": {
            "type": "callback",
            "weight": 0.75,
            "reason": "Generic network connection"
        },
        r"okhttp3\.(OkHttpClient|Request)": {
            "type": "callback",
            "weight": 0.7,
            "reason": "Modern HTTP library (callback)"
        },
        
        # Crypto/encoding (payload obfuscation)
        r"javax\.crypto\.(Cipher|KeyGenerator)": {
            "type": "crypto",
            "weight": 0.6,
            "reason": "Encryption (payload protection)"
        },
        r"java\.util\.Base64\.(encode|decode)": {
            "type": "encoding",
            "weight": 0.5,
            "reason": "Base64 encoding (payload wrapper)"
        },
        r"java\.security\.MessageDigest": {
            "type": "hashing",
            "weight": 0.4,
            "reason": "Hashing (integrity checks)"
        },
    }
    
    # Patterns: suspicious strings (URLs, hex, Base64 payloads)
    SUSPICIOUS_STRING_PATTERNS = {
        r"^https?://": {
            "type": "url",
            "threat_type": "callback",
            "weight": 0.8,
        },
        r"^[A-Za-z0-9+/]{100,}={0,2}$": {
            "type": "base64_payload",
            "threat_type": "encoded_payload",
            "weight": 0.85,
        },
        r"^[0-9A-Fa-f]{200,}$": {
            "type": "hex_payload",
            "threat_type": "encoded_payload",
            "weight": 0.9,
        },
        r"(cmd|/system|/bin|sh|bash|chmod|su\b)": {
            "type": "shell_cmd",
            "threat_type": "process_execution",
            "weight": 0.7,
        },
        r"(\.so|\.dex|\.jar)$": {
            "type": "binary_artifact",
            "threat_type": "dynamic_load",
            "weight": 0.8,
        },
    }
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
    
    def analyze_decompiled_code(self, java_files: List[str]) -> Tuple[List[APIUsageIndicator], int]:
        """
        Scan decompiled Java files for dangerous API calls.
        
        Args:
            java_files: List of decompiled .java file contents or file paths
        
        Returns:
            (list of API indicators, total API call count)
        """
        api_indicators = []
        api_call_counter = Counter()
        
        for file_content in java_files:
            for api_pattern, metadata in self.DANGEROUS_APIS.items():
                matches = re.findall(api_pattern, file_content, re.IGNORECASE)
                if matches:
                    api_name = metadata.get("type", "unknown")
                    count = len(matches)
                    api_call_counter[api_name] += count
                    
                    if self.verbose:
                        print(f"  [!] Found {count}x {api_name}: {metadata['reason']}")
        
        # Create indicators for each API type
        for api_name, count in api_call_counter.items():
            # Find weight from patterns
            weight = 0.5
            for pattern, meta in self.DANGEROUS_APIS.items():
                if meta.get("type") == api_name:
                    weight = meta.get("weight", 0.5)
                    break
            
            indicator = APIUsageIndicator(
                api_name=api_name,
                full_path=f"android.{api_name}",
                occurrences=count,
                threat_type=api_name,
                confidence=min(weight * (1 + count * 0.05), 1.0)  # Boost confidence with occurrence count
            )
            api_indicators.append(indicator)
        
        return api_indicators, sum(api_call_counter.values())
    
    def analyze_strings(self, strings_list: List[str]) -> List[StringIndicator]:
        """
        Scan strings for suspicious patterns (URLs, Base64, hex payloads).
        
        Args:
            strings_list: List of extracted strings from APK
        
        Returns:
            List of suspicious string indicators
        """
        indicators = []
        
        for string_val in strings_list:
            for pattern, metadata in self.SUSPICIOUS_STRING_PATTERNS.items():
                if re.match(pattern, string_val.strip()):
                    indicator = StringIndicator(
                        value=string_val[:100],  # Truncate for readability
                        encoding=metadata.get("type", "unknown"),
                        threat_type=metadata.get("threat_type", "unknown"),
                        confidence=metadata.get("weight", 0.5)
                    )
                    indicators.append(indicator)
                    
                    if self.verbose:
                        print(f"  [!] Suspicious string ({metadata['type']}): {string_val[:60]}...")
                    break
        
        return indicators
    
    def compute_stager_score(self, sig: MetasploitSignature) -> float:
        """
        Compute likelihood that APK is a Metasploit stager.
        
        Factors:
        - File size (small = more likely)
        - Reflection density (high = likely)
        - Dynamic loading (high = very likely)
        - Suspicious strings (Base64, hex payloads)
        - API usage patterns
        """
        score = 0.0
        weights = {
            'size': 0.15,
            'reflection': 0.2,
            'dynamic_load': 0.35,
            'strings': 0.2,
            'api_pattern': 0.1,
        }
        
        # Factor 1: File size (small APKs are suspiciously small)
        # A 10KB APK with 12 classes is EXTREMELY suspicious
        if sig.file_size_kb < 100:
            size_score = 1.0 - (sig.file_size_kb / 100)  # 10KB = 0.9 score
            score += weights['size'] * size_score
            sig.audit_notes.append(f"Small file size ({sig.file_size_kb}KB) = {size_score:.1%} likelihood increase")
        
        # Factor 2: Reflection density
        reflection_count = sum(a.occurrences for a in sig.api_usage if a.threat_type == "reflection")
        sig.reflection_density = reflection_count / max(sig.class_count, 1)
        # 7 reflection usages in 12 classes = 58% density = HIGH ALERT
        if sig.reflection_density > 0.1:  # >10% is already suspicious
            density_contribution = min(sig.reflection_density * 1.5, 1.0)
            score += weights['reflection'] * density_contribution
            sig.audit_notes.append(f"High reflection density ({sig.reflection_density:.2%}) = {density_contribution:.1%} likelihood increase")
        
        # Factor 3: Dynamic loading (strongest signal)
        dynamic_load_count = sum(a.occurrences for a in sig.api_usage if a.threat_type == "dynamic_load")
        sig.dynamic_load_density = dynamic_load_count / max(sig.class_count, 1)
        # 4 dynamic loading in 12 classes = 33% density = CRITICAL
        if sig.dynamic_load_density > 0.05:  # >5% is very suspicious
            density_contribution = min(sig.dynamic_load_density * 3.0, 1.0)
            score += weights['dynamic_load'] * density_contribution
            sig.audit_notes.append(f"High dynamic loading ({sig.dynamic_load_density:.2%}) = {density_contribution:.1%} likelihood increase")
        
        # Factor 4: Suspicious strings (payloads, URLs)
        payload_strings = [s for s in sig.suspicious_strings if "payload" in s.threat_type]
        callback_strings = [s for s in sig.suspicious_strings if "callback" in s.threat_type]
        total_suspicious = len(payload_strings) + len(callback_strings)
        
        if total_suspicious > 0:
            # String density: suspicious_strings / total_strings
            string_density = total_suspicious / max(sig.string_count, 1)
            string_score = min(string_density * 2.0, 1.0)  # 2x multiplier
            score += weights['strings'] * string_score
            sig.audit_notes.append(f"Found {total_suspicious} suspicious strings ({payload_strings.__len__()} payloads, {callback_strings.__len__()} callbacks) = {string_score:.1%} likelihood increase")
        
        # Factor 5: Dangerous API pattern matching
        dangerous_apis = [a for a in sig.api_usage if a.threat_type in ["dynamic_load", "process_execution", "callback"]]
        if len(dangerous_apis) > 0:
            api_score = min(len(dangerous_apis) / 3.0, 1.0)  # Each API type adds 33%
            score += weights['api_pattern'] * api_score
            sig.audit_notes.append(f"Found {len(dangerous_apis)} dangerous API categories = {api_score:.1%} likelihood increase")
        
        # Bonus: combination of indicators
        if sig.reflection_density > 0.1 and dynamic_load_count > 0:
            score += 0.15  # Reflection + dynamic loading is very characteristic
            sig.audit_notes.append("Bonus: Reflection + Dynamic Loading combination (classic stager pattern) = +15%")
        
        # Normalize
        sig.obfuscation_score = min(score * 100, 100.0)
        return sig.obfuscation_score
    
    def diagnose_apk(self, apk_name: str, file_size_kb: int, class_count: int, 
                    strings_list: List[str], decompiled_code: List[str]) -> MetasploitSignature:
        """
        Full diagnosis of an APK.
        
        Args:
            apk_name: Name of APK file
            file_size_kb: Size in KB
            class_count: Number of DEX classes
            strings_list: All extracted strings
            decompiled_code: All decompiled .java code
        
        Returns:
            MetasploitSignature with all analysis
        """
        sig = MetasploitSignature(
            apk_name=apk_name,
            file_size_kb=file_size_kb,
            class_count=class_count,
            string_count=len(strings_list)
        )
        
        if self.verbose:
            print(f"\n[*] Analyzing {apk_name} ({file_size_kb}KB, {class_count} classes)")
        
        # Analyze code
        if self.verbose:
            print("[*] Scanning for dangerous API calls...")
        api_indicators, api_count = self.analyze_decompiled_code(decompiled_code)
        sig.api_usage = api_indicators
        sig.audit_notes.append(f"Found {api_count} total dangerous API calls across {len(api_indicators)} categories")
        
        # Analyze strings
        if self.verbose:
            print("[*] Scanning for suspicious strings...")
        string_indicators = self.analyze_strings(strings_list)
        sig.suspicious_strings = string_indicators
        sig.audit_notes.append(f"Found {len(string_indicators)} suspicious strings (URLs, Base64, hex)")
        
        # Compute stager score
        self.compute_stager_score(sig)
        
        return sig
    
    def report(self, sig: MetasploitSignature) -> Dict:
        """Generate diagnostic report."""
        return {
            'apk_name': sig.apk_name,
            'file_size_kb': sig.file_size_kb,
            'class_count': sig.class_count,
            'string_count': sig.string_count,
            'stager_likelihood_score': sig.obfuscation_score,
            'reflection_density': sig.reflection_density,
            'dynamic_load_density': sig.dynamic_load_density,
            'api_usage_count': len(sig.api_usage),
            'suspicious_strings_count': len(sig.suspicious_strings),
            'audit_notes': sig.audit_notes,
            'api_findings': [
                {
                    'api': a.api_name,
                    'occurrences': a.occurrences,
                    'confidence': a.confidence,
                    'threat_type': a.threat_type,
                }
                for a in sig.api_usage
            ],
            'string_findings': [
                {
                    'value': s.value,
                    'encoding': s.encoding,
                    'threat_type': s.threat_type,
                    'confidence': s.confidence,
                }
                for s in sig.suspicious_strings[:10]  # Top 10
            ],
        }


# Example: test against the output.txt case
def test_metasploit_case():
    """Test against the Metasploit stager from output.txt."""
    detector = MetasploitDetector(verbose=True)
    
    # Simulate the Metasploit stager profile
    print("="*70)
    print("METASPLOIT STAGER DIAGNOSIS TEST")
    print("="*70)
    
    # From output.txt:
    # Sample name: 1722087714.apk
    # File size: 10,461 bytes (10.5 KB)
    # Classes: 12
    # Strings: 107
    # Reflection usages: 7
    # Dynamic loading: 4
    
    simulated_decompiled_code = [
        # Simulated reflection patterns (7x as reported in output.txt)
        "java.lang.reflect.Method m = c.getDeclaredMethod(...)",
        "m.invoke(null, ...)",
        "java.lang.reflect.Class.forName('com.example.Payload')",
        "java.lang.reflect.Constructor cons = c.getConstructor(...)",
        "java.lang.reflect.Field f = c.getDeclaredField(...)",
        "java.lang.reflect.Method m2 = c.getMethod(...)",
        "java.lang.reflect.Class.forName('android.stage.One')",
        # Simulated dynamic loading (4x as reported in output.txt)
        "DexClassLoader dcl = new DexClassLoader(...)",
        "dcl.loadClass('android.stage.One')",
        "PathClassLoader pcl = (PathClassLoader) c.getClassLoader()",
        "BaseDexClassLoader bdcl = new BaseDexClassLoader(...)",
        # Simulated process execution
        "Runtime.getRuntime().exec(...)",
    ]
    
    simulated_strings = [
        "http://attacker.tk/beacon",
        "QUdJAAAAAEZJTEU=",  # Base64 payload
        "c3RhZ2VyLnBlYXkuZGV4",  # More Base64
        "android.stage.One",
        "com.android.hidden",
    ]
    
    sig = detector.diagnose_apk(
        apk_name="1722087714.apk",
        file_size_kb=10,
        class_count=12,
        strings_list=simulated_strings,
        decompiled_code=simulated_decompiled_code
    )
    
    report = detector.report(sig)
    print("\n" + "="*70)
    print("DIAGNOSTIC REPORT")
    print("="*70)
    print(json.dumps(report, indent=2))
    
    print(f"\n[VERDICT]")
    print(f"  Stager Likelihood Score: {report['stager_likelihood_score']:.1f}/100")
    print(f"  Classification: {'LIKELY STAGER' if report['stager_likelihood_score'] > 70 else 'UNCERTAIN'}")


if __name__ == '__main__':
    test_metasploit_case()
