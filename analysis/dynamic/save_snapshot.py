#!/usr/bin/env python3
"""Cold boot emulator with SELinux permissive, start Frida, save snapshot."""

import os, sys, logging, time

logging.basicConfig(level=logging.INFO)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from analysis.dynamic.config import settings
from analysis.dynamic.orchestrator import (
    wait_for_device, ensure_frida_server,
    forward_frida_port, adb_command, stop_emulator,
)

print("=== BOOTING EMULATOR WITH WRITABLE SYSTEM ===")
import subprocess
cmd = [
    str(settings.EMULATOR_PATH),
    "-avd", settings.AVD_NAME,
    "-no-window",
    "-no-audio",
    "-port", "5554",
    "-memory", "2048",
    "-cores", "2",
    "-writable-system",
    "-no-snapshot",
]
proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(f"Emulator PID: {proc.pid}")
print("Booting...")

print("Waiting for boot (cold boot may take 5+ minutes)...")
if not wait_for_device(timeout=300):
    print("FAILED: device not ready after 5 min")
    stop_emulator()
    sys.exit(1)

# Root the device
r = adb_command(["root"], timeout=10)
print(f"adb root: {r.stdout.strip()[:200]} {r.stderr.strip()[:200]}")

r = adb_command(["shell", "id"], timeout=5)
print(f"id after root: {r.stdout.strip()}")

r = adb_command(["remount"], timeout=10)
print(f"adb remount: {r.stdout.strip()[:200]} {r.stderr.strip()[:200]}")

# Set SELinux permissive (we should be root now)
r = adb_command(["shell", "setenforce", "0"], timeout=5)
print(f"setenforce 0: rc={r.returncode}, {r.stdout.strip()[:200]}")

r = adb_command(["shell", "getenforce"], timeout=5)
print(f"SELinux: {r.stdout.strip()}")

# Start Frida server
if not ensure_frida_server():
    print("FAILED to start Frida")
    stop_emulator()
    sys.exit(1)

if not forward_frida_port():
    print("FAILED port forward")
    stop_emulator()
    sys.exit(1)

# Verify Frida
r = adb_command(["shell", "pidof", "frida-server"], timeout=5)
print(f"Frida PID: {r.stdout.strip()}")

if r.stdout.strip():
    pid = r.stdout.strip()
    r = adb_command(["shell", "cat", f"/proc/{pid}/status"], timeout=5)
    for line in r.stdout.splitlines():
        if "Uid" in line or "CapEff" in line:
            print(f"  {line.strip()}")

# Save snapshot
print("\nSaving snapshot 'clean_permissive'...")
r = adb_command(["emu", "avd", "snapshot", "save", "clean_permissive"], timeout=60)
print(f"Snapshot save: rc={r.returncode}, {r.stdout.strip()[:200]}")

stop_emulator()
print("Done")
