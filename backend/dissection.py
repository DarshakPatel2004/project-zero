"""
APK dissection engine for DroidForensix.

Extracts structural metadata, manifest data, permissions, components, native
libraries, resources, DEX statistics, and file structure from an APK without
running the full analysis pipeline.
"""

import json
import math
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from androguard.core.apk import APK
from androguard.core.dex import DEX

from backend.config import settings


# Android namespace used in binary XML manifests
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Common permission protection levels for quick classification
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.ACTIVITY_RECOGNITION",
}

SIGNATURE_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_AUTOFILL_SERVICE",
    "android.permission.BIND_APPWIDGET",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_DREAM_SERVICE",
    "android.permission.BIND_INPUT_METHOD",
    "android.permission.BIND_MIDI_DEVICE_SERVICE",
    "android.permission.BIND_NFC_SERVICE",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.BIND_PRINT_SERVICE",
    "android.permission.BIND_SCREENING_SERVICE",
    "android.permission.BIND_TELECOM_CONNECTION_SERVICE",
    "android.permission.BIND_TEXT_SERVICE",
    "android.permission.BIND_TV_INPUT",
    "android.permission.BIND_VISUAL_VOICEMAIL_SERVICE",
    "android.permission.BIND_VOICE_INTERACTION",
    "android.permission.BIND_VPN_SERVICE",
    "android.permission.BIND_VR_LISTENER_SERVICE",
    "android.permission.BIND_WALLPAPER",
    "android.permission.CLEAR_APP_USER_DATA",
    "android.permission.MANAGE_DEVICE_POLICY",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
}


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte string."""
    if not data:
        return 0.0
    length = len(data)
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class APKDissector:
    """Fast APK structural dissection."""

    def __init__(self, apk_path: str, work_dir: str = None):
        self.apk_path = Path(apk_path)
        self.work_dir = Path(work_dir) if work_dir else settings.WORK_DIR
        self._apk: Optional[APK] = None

    def _get_apk(self) -> APK:
        if self._apk is None:
            self._apk = APK(str(self.apk_path))
        return self._apk

    def dissect(self) -> Dict[str, Any]:
        """Return all dissected APK data as a JSON-serializable dict."""
        return {
            "metadata": self.extract_metadata(),
            "manifest": self.extract_manifest(),
            "permissions": self.extract_permissions(),
            "components": self.extract_components(),
            "native_libs": self.extract_native_libs(),
            "resources": self.extract_resources_structure(),
            "dex_stats": self.extract_dex_stats(),
            "file_structure": self.extract_file_structure(),
        }

    def extract_metadata(self) -> Dict[str, Any]:
        """Extract basic APK metadata."""
        apk = self._get_apk()
        return {
            "apk_path": str(self.apk_path),
            "file_size_bytes": self.apk_path.stat().st_size,
            "package_name": apk.get_package(),
            "version_code": apk.get_androidversion_code(),
            "version_name": apk.get_androidversion_name(),
            "min_sdk_version": apk.get_min_sdk_version(),
            "target_sdk_version": apk.get_target_sdk_version(),
            "effective_target_sdk_version": apk.get_effective_target_sdk_version(),
            "max_sdk_version": apk.get_max_sdk_version(),
            "is_multidex": apk.is_multidex(),
        }

    def extract_manifest(self) -> Dict[str, Any]:
        """Return parsed AndroidManifest.xml fields."""
        apk = self._get_apk()
        manifest = apk.get_android_manifest_xml()
        app = manifest.find("application")
        app_attrs = {}
        if app is not None:
            for key, value in app.attrib.items():
                # Strip Android namespace for readability
                short_key = key.replace(ANDROID_NS, "")
                app_attrs[short_key] = value

        return {
            "package": apk.get_package(),
            "version_code": apk.get_androidversion_code(),
            "version_name": apk.get_androidversion_name(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
            "max_sdk": apk.get_max_sdk_version(),
            "application": app_attrs,
            "features": sorted(set(apk.get_features() or [])),
            "libraries": sorted(set(apk.get_libraries() or [])),
            "raw_manifest": apk.get_raw().decode("utf-8", errors="ignore") if apk.get_raw() else None,
        }

    def extract_permissions(self) -> List[Dict[str, Any]]:
        """Return declared permissions with risk levels."""
        apk = self._get_apk()
        declared = apk.get_declared_permissions() or []
        requested = apk.get_permissions() or []
        details = apk.get_details_permissions() or {}

        permissions = []
        seen = set()

        for perm in requested:
            if perm in seen:
                continue
            seen.add(perm)
            perm_details = details.get(perm, [])
            protection_level = self._classify_protection_level(perm, perm_details)
            permissions.append({
                "name": perm,
                "type": "uses_permission",
                "protection_level": protection_level,
                "label": perm_details[1] if len(perm_details) > 1 else None,
                "description": perm_details[2] if len(perm_details) > 2 else None,
                "is_aosp": perm.startswith("android.permission."),
            })

        for perm in declared:
            if perm in seen:
                continue
            seen.add(perm)
            perm_details = details.get(perm, [])
            protection_level = self._classify_protection_level(perm, perm_details)
            permissions.append({
                "name": perm,
                "type": "declared_permission",
                "protection_level": protection_level,
                "label": perm_details[1] if len(perm_details) > 1 else None,
                "description": perm_details[2] if len(perm_details) > 2 else None,
                "is_aosp": perm.startswith("android.permission."),
            })

        return permissions

    def _classify_protection_level(self, permission: str, details: List[Any]) -> str:
        """Classify a permission's risk level."""
        if details:
            level = details[0]
            if isinstance(level, str):
                level_lower = level.lower()
                # Compound levels like "signature|system|development"
                if "dangerous" in level_lower:
                    return "dangerous"
                if "signature" in level_lower:
                    return "signature"
                if "normal" in level_lower:
                    return "normal"
                return level_lower
        if permission in DANGEROUS_PERMISSIONS:
            return "dangerous"
        if permission in SIGNATURE_PERMISSIONS:
            return "signature"
        if permission.startswith("android.permission."):
            return "normal"
        return "unknown"

    def extract_components(self) -> Dict[str, List[Dict[str, Any]]]:
        """Return activities, services, broadcast receivers, content providers."""
        apk = self._get_apk()
        manifest = apk.get_android_manifest_xml()
        components = {"activities": [], "services": [], "receivers": [], "providers": []}

        for tag, key in [
            ("activity", "activities"),
            ("service", "services"),
            ("receiver", "receivers"),
            ("provider", "providers"),
        ]:
            for elem in manifest.findall(f".//{tag}"):
                name = elem.get(f"{ANDROID_NS}name")
                if not name:
                    continue
                exported = elem.get(f"{ANDROID_NS}exported")
                # Default exported rules: activities/receivers/services with
                # intent filters are exported by default; providers are not.
                has_filters = elem.find("intent-filter") is not None
                if exported is None:
                    if tag == "provider":
                        exported_default = False
                    else:
                        exported_default = has_filters
                else:
                    exported_default = exported.lower() == "true"

                intent_filters = apk.get_intent_filters(tag, name)

                components[key].append({
                    "name": name,
                    "exported": exported_default,
                    "exported_declared": exported,
                    "intent_filters": intent_filters if intent_filters else [],
                    "attributes": {
                        k.replace(ANDROID_NS, ""): v
                        for k, v in elem.attrib.items()
                    },
                })

        return components

    def extract_native_libs(self) -> List[Dict[str, Any]]:
        """Return list of .so files and architectures."""
        apk = self._get_apk()
        libs = []
        # Build a map of filename -> (size, crc32) from the APK zip
        with zipfile.ZipFile(self.apk_path, "r") as zf:
            zip_info = {info.filename: info for info in zf.infolist()}
        for file_name in apk.get_files():
            if not file_name.endswith(".so"):
                continue
            parts = Path(file_name).parts
            # Typical path: lib/<arch>/<name>.so
            arch = parts[1] if len(parts) >= 3 else "unknown"
            info = zip_info.get(file_name)
            libs.append({
                "path": file_name,
                "arch": arch,
                "name": Path(file_name).name,
                "size": info.file_size if info else 0,
                "crc32": f"{info.CRC & 0xFFFFFFFF:08x}" if info else None,
            })
        return libs

    def extract_resources_structure(self) -> Dict[str, Any]:
        """Return high-level resource tree."""
        apk = self._get_apk()
        counts: Dict[str, int] = {}
        resource_files = []
        for file_name in apk.get_files():
            if file_name.startswith("res/"):
                resource_files.append(file_name)
                parts = Path(file_name).parts
                if len(parts) >= 2:
                    category = parts[1]
                    counts[category] = counts.get(category, 0) + 1

        return {
            "total_resource_files": len(resource_files),
            "counts_by_type": counts,
            "sample_files": resource_files[:50],
        }

    def extract_dex_stats(self) -> Dict[str, Any]:
        """Parse DEX header for statistics."""
        apk = self._get_apk()
        stats = {
            "dex_count": 0,
            "total_classes": 0,
            "total_methods": 0,
            "total_strings": 0,
            "total_bytes": 0,
            "entropy": 0.0,
            "dex_files": [],
        }

        all_dex_bytes = []
        for idx, dex_data in enumerate(apk.get_all_dex()):
            all_dex_bytes.append(dex_data)
            try:
                dex = DEX(dex_data)
                classes = len(list(dex.get_classes()))
                methods = len(list(dex.get_methods()))
                strings = len(list(dex.get_strings()))
            except Exception:
                classes = methods = strings = 0

            stats["dex_files"].append({
                "index": idx,
                "size": len(dex_data),
                "classes": classes,
                "methods": methods,
                "strings": strings,
            })
            stats["total_classes"] += classes
            stats["total_methods"] += methods
            stats["total_strings"] += strings

        stats["dex_count"] = len(all_dex_bytes)
        combined = b"".join(all_dex_bytes)
        stats["total_bytes"] = len(combined)
        stats["entropy"] = round(_shannon_entropy(combined), 4)
        return stats

    def extract_file_structure(self) -> Dict[str, Any]:
        """Return directory tree of APK contents."""
        apk = self._get_apk()
        structure: Dict[str, List[str]] = {}
        for file_name in apk.get_files():
            parts = Path(file_name).parts
            top = parts[0] if parts else "root"
            structure.setdefault(top, []).append(file_name)

        return {
            "top_level_directories": sorted(structure.keys()),
            "files_by_directory": {k: v[:100] for k, v in structure.items()},
            "total_files": sum(len(v) for v in structure.values()),
        }

    def list_decompiled_classes(self) -> List[str]:
        """List Java classes from JADX output for this sample."""
        sample_id = self._sample_id_from_apk()
        sources_dir = self.work_dir / sample_id / "jadx" / "sources"
        if not sources_dir.exists():
            return []

        classes = []
        for java_file in sources_dir.rglob("*.java"):
            rel = java_file.relative_to(sources_dir)
            # Convert path to dotted class name
            class_name = str(rel.with_suffix("")).replace("/", ".").replace("\\", ".")
            classes.append(class_name)
        return sorted(classes)

    def list_decompiled_class_objects(self) -> List[Dict[str, Any]]:
        """Return class objects with method/network summaries for the dashboard."""
        import re

        CONTROL_NAMES = {"if", "for", "while", "switch", "catch", "synchronized", "try", "finally"}
        NETWORK_PATTERNS = [
            re.compile(r"https?://[^\\s\"'<>]+", re.IGNORECASE),
            re.compile(r"\b(new\s+URL|new\s+URI|openConnection|getInputStream|getOutputStream)\s*\("),
            re.compile(r"\b(HttpURLConnection|URLConnection|Socket|ServerSocket|InetAddress)\b"),
            re.compile(r"\b(okhttp3|retrofit2)\b", re.IGNORECASE),
        ]

        classes = []
        for class_name in self.list_decompiled_classes():
            source = self.read_class_source(class_name) or ""
            lines = source.splitlines()

            # Extract method declarations more carefully.
            method_pattern = re.compile(
                r"^\s*(?:(?:public|private|protected|static|final|abstract|synchronized)\s+)+"
                r"(?:[\w\[\]<>?]+(?:\s*<[^>]+>\s*)?\s+)+"
                r"(\w+)\s*\([^)]*\)\s*\{",
                re.MULTILINE,
            )

            methods = []
            for m in method_pattern.finditer(source):
                name = m.group(1)
                if name in CONTROL_NAMES:
                    continue
                body_start = m.end()
                brace_count = 1
                idx = body_start
                while idx < len(source) and brace_count > 0:
                    if source[idx] == "{":
                        brace_count += 1
                    elif source[idx] == "}":
                        brace_count -= 1
                    idx += 1
                body = source[body_start:idx]
                methods.append({"name": name, "body": body})

            # Extract network-related snippets, skipping import lines.
            network_calls = []
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("import "):
                    continue
                for pattern in NETWORK_PATTERNS:
                    if pattern.search(stripped):
                        network_calls.append(stripped.strip(";"))
                        break
            network_calls = list(dict.fromkeys(network_calls))[:20]

            # Extract permission-like API usages.
            permission_lines = [
                stripped.strip(";")
                for stripped in (line.strip() for line in lines)
                if "checkSelfPermission" in stripped or "checkCallingOrSelfPermission" in stripped
            ]
            permissions_used = list(dict.fromkeys(permission_lines))[:10]

            classes.append({
                "name": class_name,
                "methods": methods,
                "network_calls": network_calls,
                "permissions_used": permissions_used,
            })
        return classes

    def read_class_source(self, class_name: str) -> Optional[str]:
        """Read decompiled Java source for a specific class."""
        sample_id = self._sample_id_from_apk()
        parts = class_name.split(".")
        source_file = self.work_dir / sample_id / "jadx" / "sources" / Path(*parts).with_suffix(".java")
        if not source_file.exists():
            return None
        try:
            with open(source_file, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception:
            return None

    def load_strings(self) -> Optional[Dict[str, Any]]:
        """Load extracted strings from Step 2 result."""
        sample_id = self._sample_id_from_apk()
        strings_path = self.work_dir / sample_id / "step2_strings.json"
        if not strings_path.exists():
            return None
        try:
            with open(strings_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _sample_id_from_apk(self) -> str:
        """Compute sample_id as SHA-256 of the APK, matching Step 1."""
        import hashlib
        h = hashlib.sha256()
        with open(self.apk_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()


def load_dissection(work_dir: str, sample_id: str) -> Optional[Dict[str, Any]]:
    """Load cached dissection.json for a sample if it exists."""
    path = Path(work_dir) / sample_id / "dissection.json"
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def dissect_apk(apk_path: str, work_dir: str = None) -> Dict[str, Any]:
    """Convenience function to dissect an APK."""
    return APKDissector(apk_path, work_dir).dissect()
