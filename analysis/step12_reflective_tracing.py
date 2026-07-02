"""
Step 12: Reflective Method Invocation Tracing.

Scans smali/ and jadx output for reflective Java calls (Class.forName,
Method.invoke, getDeclaredMethod/Field/Constructor) and flags references
to sensitive Android API classes.
"""

import logging
import os
import re
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

CLASS_FOR_NAME = re.compile(r';->forName\(')
METHOD_INVOKE = re.compile(r'Method;->invoke\(')
DECLARED_METHOD = re.compile(r'getDeclared(Method|Field|Constructor)\(')

SENSITIVE_API_CLASSES: Dict[str, List[str]] = {
    "android.telephony.SmsManager": [
        "sendTextMessage",
        "sendDataMessage",
        "sendMultipartTextMessage",
    ],
    "android.telephony.TelephonyManager": [
        "getDeviceId",
        "getSubscriberId",
        "getSimSerialNumber",
        "getLine1Number",
    ],
    "android.location.LocationManager": [
        "getLastKnownLocation",
        "requestLocationUpdates",
        "getAllProviders",
    ],
    "android.accounts.AccountManager": [
        "getAccounts",
        "getAccountsByType",
        "getAuthToken",
    ],
    "android.content.Context": [
        "getContentResolver",
        "getSystemService",
    ],
    "java.lang.Runtime": [
        "exec",
        "loadLibrary",
    ],
    "android.app.ActivityManager": [
        "getRunningTasks",
        "getRunningAppProcesses",
    ],
    "android.hardware.Camera": [
        "open",
    ],
    "android.media.AudioRecord": [
        "startRecording",
        "read",
    ],
    "android.net.wifi.WifiManager": [
        "getScanResults",
        "getConnectionInfo",
    ],
    "android.bluetooth.BluetoothAdapter": [
        "getAddress",
        "startDiscovery",
    ],
    "android.app.admin.DevicePolicyManager": [
        "lockNow",
        "wipeData",
        "resetPassword",
    ],
    "android.telephony.CellLocation": [
        "getLocation",
    ],
    "android.telephony.gsm.GsmCellLocation": [
        "getLac",
        "getCid",
    ],
}

RISK_CATEGORY_MAP: Dict[str, str] = {
    "android.telephony.SmsManager": "sms",
    "android.telephony.TelephonyManager": "telephony",
    "android.location.LocationManager": "location",
    "android.accounts.AccountManager": "accounts",
    "android.content.Context": "system",
    "java.lang.Runtime": "code_execution",
    "android.app.ActivityManager": "system",
    "android.hardware.Camera": "camera",
    "android.media.AudioRecord": "audio_recording",
    "android.net.wifi.WifiManager": "network_info",
    "android.bluetooth.BluetoothAdapter": "bluetooth",
    "android.app.admin.DevicePolicyManager": "device_admin",
    "android.telephony.CellLocation": "location",
    "android.telephony.gsm.GsmCellLocation": "location",
}

CONST_STRING_RE = re.compile(r'\s*const-string\s+[vp0-9]+,\s*"([^"]*)"')


def _find_preceding_const_string(lines: List[str], current_index: int) -> str:
    start = max(0, current_index - 5)
    for i in range(current_index - 1, start - 1, -1):
        m = CONST_STRING_RE.match(lines[i])
        if m:
            return m.group(1)
    return ""


def _check_sensitive(class_name: str) -> bool:
    return class_name in SENSITIVE_API_CLASSES


def _get_category(class_name: str) -> str:
    return RISK_CATEGORY_MAP.get(class_name, "other")


def _process_smali_file(filepath: str, extracted_path: str) -> List[Dict[str, Any]]:
    rel_path = os.path.relpath(filepath, extracted_path)
    calls = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        entry = None
        if CLASS_FOR_NAME.search(stripped):
            class_name = _find_preceding_const_string(lines, lineno - 1)
            entry = {
                "file": rel_path,
                "line": lineno,
                "type": "class_forName",
                "class_name": class_name,
            }
        elif METHOD_INVOKE.search(stripped):
            entry = {
                "file": rel_path,
                "line": lineno,
                "type": "method_invoke",
                "class_name": "",
            }
        elif DECLARED_METHOD.search(stripped):
            entry = {
                "file": rel_path,
                "line": lineno,
                "type": "declared_method",
                "class_name": "",
            }
        if entry:
            class_name = entry.get("class_name", "")
            if class_name and _check_sensitive(class_name):
                entry["sensitive"] = True
                entry["category"] = _get_category(class_name)
            else:
                entry["sensitive"] = False
            calls.append(entry)
    return calls


def find_reflective_calls(extraction: Dict[str, Any]) -> Dict[str, Any]:
    extracted_path = extraction.get("extracted_path", "")
    if not extracted_path or not os.path.isdir(extracted_path):
        return {
            "reflective_calls": [],
            "total_reflective_calls": 0,
            "total_sensitive": 0,
            "risk_categories": {},
        }

    search_base = None
    for subdir in ("smali", os.path.join("jadx_output", "sources")):
        candidate = os.path.join(extracted_path, subdir)
        if os.path.isdir(candidate):
            search_base = candidate
            break

    if search_base is None:
        search_base = extracted_path

    reflective_calls = []
    for root, _, files in os.walk(search_base):
        for fname in files:
            if not fname.endswith(".smali"):
                continue
            filepath = os.path.join(root, fname)
            try:
                calls = _process_smali_file(filepath, extracted_path)
                reflective_calls.extend(calls)
            except Exception as e:
                logger.warning("Error reading %s: %s", filepath, e)

    total_sensitive = 0
    risk_categories: Dict[str, int] = {}
    for call in reflective_calls:
        if call.get("sensitive"):
            total_sensitive += 1
            cat = call.get("category", "other")
            risk_categories[cat] = risk_categories.get(cat, 0) + 1

    return {
        "reflective_calls": reflective_calls,
        "total_reflective_calls": len(reflective_calls),
        "total_sensitive": total_sensitive,
        "risk_categories": risk_categories,
    }
