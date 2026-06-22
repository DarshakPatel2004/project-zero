import os
os.environ['JAVA_HOME'] = r'C:\Program Files\Microsoft\jdk-21.0.11.10-hotspot'
import sys
sys.path.insert(0, 'D:/DroidForensix')
from analysis.pipeline import run_pipeline

result = run_pipeline(
    'D:/DroidForensix/samples/malware/androzoo/00000a7eacfd7e392ea3aaee14bec0224e62bf72823a8101f6717d704dce3a79.apk', 
    'D:/DroidForensix/analysis/work'
)
print(f"Encodings: {len(result.get('encodings', []))}")
print(f"Payloads: {len(result.get('payloads', []))}")
print(f"C2s: {len(result.get('c2_infrastructure', []))}")
print(f"Chains: {len(result.get('threat_chains', []))}")