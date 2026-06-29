"""
Step 1: APK Extraction & Decompilation

Unpacks APK using apktool, decompiles DEX to Java using jadx-cli,
extracts native library strings using the `strings` utility (Windows-native
when available via Git Bash or Sysinternals), and generates metadata.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from backend.config import settings
from analysis.retry_utils import safe_decompile_apk, DecompilationError


class APKExtractionError(Exception):
    """Raised when APK extraction fails."""
    pass


def compute_sha256(file_path: str) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_md5(file_path: str) -> str:
    """Compute MD5 hash of a file."""
    h = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _tool_cmd(path: str) -> list:
    """Return a subprocess-ready command list from a configured tool path."""
    tool = Path(path)
    return [str(tool)] if tool.exists() else [path]


def run_apktool(apk_path: str, output_dir: str) -> dict:
    """Run apktool to unpack APK. Returns result dict."""
    result = {"success": False, "output_dir": output_dir, "error": None}
    try:
        cmd = _tool_cmd(settings.APKTOOL_PATH) + ["d", "-f", "-o", output_dir, apk_path]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120, shell=(os.name == "nt")
        )
        if proc.returncode == 0:
            result["success"] = True
        else:
            result["error"] = f"apktool exit {proc.returncode}: {proc.stderr}"
    except subprocess.TimeoutExpired:
        result["error"] = "apktool timed out after 120s"
    except FileNotFoundError:
        result["error"] = "apktool not found; check APKTOOL_PATH in backend/config.py"
    except Exception as e:
        result["error"] = str(e)
    return result


def run_jadx(apk_path: str, output_dir: str) -> dict:
    """Run jadx-cli to decompile DEX to Java source."""
    result = {"success": False, "output_dir": output_dir, "error": None}
    try:
        cmd = _tool_cmd(settings.JADX_PATH) + [
            "-d", output_dir,
            "--deobf",
            "--deobf-min", "2",
            apk_path,
        ]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300, shell=(os.name == "nt")
        )
        if proc.returncode == 0:
            result["success"] = True
        else:
            result["error"] = f"jadx exit {proc.returncode}: {proc.stderr}"
    except subprocess.TimeoutExpired:
        result["error"] = "jadx timed out after 300s"
    except FileNotFoundError:
        result["error"] = "jadx not found; check JADX_PATH in backend/config.py"
    except Exception as e:
        result["error"] = str(e)
    return result


def _extract_printable_strings(data: bytes, min_len: int = 6) -> list:
    """Pure-Python fallback to extract printable ASCII strings."""
    strings = []
    current = bytearray()
    for b in data:
        if 32 <= b <= 126:
            current.append(b)
        else:
            if len(current) >= min_len:
                strings.append(current.decode("ascii", errors="ignore"))
            current.clear()
    if len(current) >= min_len:
        strings.append(current.decode("ascii", errors="ignore"))
    return strings


def extract_native_strings(apk_dir: str) -> list:
    """Extract strings from native .so libraries using r2, rabin2, strings, or a Python fallback."""
    strings = []
    lib_dir = Path(apk_dir) / "lib"
    if not lib_dir.exists():
        return strings

    strings_bin = shutil.which("strings")
    r2_bin = shutil.which("r2")
    rabin2_bin = shutil.which("rabin2")

    for so_file in lib_dir.rglob("*.so"):
        try:
            # Method 1: radare2 (r2)
            if r2_bin:
                cmd = [r2_bin, "-qq", "-c", "iz", str(so_file)]
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=60, shell=(os.name == "nt")
                )
                if proc.returncode == 0:
                    for line in proc.stdout.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        if '"' in line:
                            parts = line.split('"')
                            if len(parts) >= 2:
                                s = parts[1].strip()
                                if s:
                                    strings.append({
                                        "value": s,
                                        "source": so_file.relative_to(apk_dir).as_posix(),
                                    })
                    continue

            # Method 2: rabin2
            if rabin2_bin:
                cmd = [rabin2_bin, "-zz", str(so_file)]
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=60, shell=(os.name == "nt")
                )
                if proc.returncode == 0:
                    for line in proc.stdout.splitlines():
                        line = line.strip()
                        if line.startswith("0x") and "   " in line:
                            parts = line.split("   ", 1)
                            if len(parts) == 2:
                                s = parts[1].strip()
                                if s:
                                    strings.append({
                                        "value": s,
                                        "source": so_file.relative_to(apk_dir).as_posix(),
                                    })
                    continue

            # Method 3: strings command or Python fallback
            with open(so_file, "rb") as f:
                data = f.read()

            if strings_bin:
                proc = subprocess.run(
                    [strings_bin, "-n", "6", "-"],
                    input=data,
                    capture_output=True,
                    timeout=60,
                )
                text = proc.stdout.decode("utf-8", errors="ignore")
                lines = text.splitlines()
            else:
                lines = _extract_printable_strings(data, min_len=6)

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                strings.append({
                    "value": line,
                    "source": so_file.relative_to(apk_dir).as_posix(),
                })
        except Exception:
            continue
    return strings


def extract_package_name(apk_dir: str) -> Optional[str]:
    """Extract package name from AndroidManifest.xml."""
    manifest_path = Path(apk_dir) / "AndroidManifest.xml"
    if not manifest_path.exists():
        return None
    try:
        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            import re
            m = re.search(r'package="([^"]+)"', content)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


def extract_manifest_info(apk_dir: str) -> dict:
    """Extract version, SDK levels, and permissions from AndroidManifest.xml."""
    manifest_path = Path(apk_dir) / "AndroidManifest.xml"
    info = {
        "version_name": None,
        "version_code": None,
        "target_sdk_version": None,
        "min_sdk_version": None,
        "uses_permissions": [],
    }
    if not manifest_path.exists():
        return info
    try:
        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        # Match manifest attributes
        m = re.search(r'android:versionName="([^"]+)"', content)
        if m:
            info["version_name"] = m.group(1)
        m = re.search(r'android:versionCode="(\d+)"', content)
        if m:
            info["version_code"] = int(m.group(1))
        m = re.search(r'android:targetSdkVersion="(\d+)"', content)
        if m:
            info["target_sdk_version"] = int(m.group(1))
        m = re.search(r'android:minSdkVersion="(\d+)"', content)
        if m:
            info["min_sdk_version"] = int(m.group(1))
        # Match uses-permission names
        for m in re.finditer(r'<uses-permission[^>]*android:name="([^"]+)"', content):
            info["uses_permissions"].append(m.group(1))
    except Exception:
        pass
    return info


def count_decompiled_classes(output_dir: str) -> int:
    """Count number of decompiled .java files."""
    java_dir = Path(output_dir) / "sources"
    if not java_dir.exists():
        return 0
    return len(list(java_dir.rglob("*.java")))


def extract_apk(apk_path: str, work_dir: Optional[str] = None) -> dict:
    """
    Full Step 1: Extract and decompile an APK.

    Args:
        apk_path: Path to the APK file.
        work_dir: Working directory for intermediate outputs. Defaults to
            settings.WORK_DIR.

    Returns:
        dict with extraction results, metadata, and status.
    """
    apk_path = Path(apk_path).resolve()
    if not apk_path.exists():
        raise APKExtractionError(f"APK not found: {apk_path}")

    work_dir = Path(work_dir) if work_dir else settings.WORK_DIR
    work_dir = work_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)

    sample_id = compute_sha256(str(apk_path))
    sample_work = work_dir / sample_id
    sample_work.mkdir(parents=True, exist_ok=True)

    apktool_dir = sample_work / "apktool"
    jadx_dir = sample_work / "jadx"

    # Run apktool
    apktool_result = run_apktool(str(apk_path), str(apktool_dir))

    # Run jadx with retry logic (3 attempts, exponential backoff)
    retry_result = None
    jadx_result = {"success": False, "output_dir": str(jadx_dir), "error": None}
    try:
        retry_result = safe_decompile_apk(
            str(apk_path),
            str(jadx_dir),
            timeout=settings.STEP_TIMEOUT,
            max_retries=3,
            jadx_path=settings.JADX_PATH,
        )
        jadx_result = {"success": True, "output_dir": str(jadx_dir), "error": None}
    except DecompilationError as e:
        jadx_result["error"] = e.to_dict()["message"]
    except Exception as e:
        jadx_result["error"] = str(e)

    # Extract native strings
    native_strings = []
    if apktool_result["success"]:
        native_strings = extract_native_strings(str(apktool_dir))

    # Metadata
    package_name = None
    manifest_info = {}
    if apktool_result["success"]:
        package_name = extract_package_name(str(apktool_dir))
        manifest_info = extract_manifest_info(str(apktool_dir))

    decompiled_classes = retry_result.get("classes", 0) if jadx_result["success"] else 0
    jadx_success = jadx_result["success"]
    if jadx_success and not decompiled_classes:
        decompiled_classes = count_decompiled_classes(str(jadx_dir))
    if not jadx_success:
        try:
            from androguard.core.apk import APK
            from androguard.core.dex import DEX
            apk = APK(str(apk_path))
            total_classes = 0
            for dex_data in apk.get_all_dex():
                try:
                    dex = DEX(dex_data)
                    total_classes += len(list(dex.get_classes()))
                except Exception:
                    continue
            if total_classes > 0:
                decompiled_classes = total_classes
                jadx_success = True
        except Exception:
            pass

    result = {
        "sample_id": sample_id,
        "sample_name": apk_path.name,
        "file_size_bytes": apk_path.stat().st_size,
        "sha256": sample_id,
        "md5": compute_md5(str(apk_path)),
        "package_name": package_name,
        "manifest_info": manifest_info,
        "apktool_success": apktool_result["success"],
        "jadx_success": jadx_success,
        "apktool_output_dir": str(apktool_dir) if apktool_result["success"] else None,
        "jadx_output_dir": str(jadx_dir) if jadx_result["success"] else None,
        "apk_path": str(apk_path),
        "native_libs_found": list(
            set(s["source"] for s in native_strings)
        ) if native_strings else [],
        "decompiled_classes": decompiled_classes,
        "native_strings_count": len(native_strings),
        "native_strings": native_strings,
        "errors": [],
    }

    if not apktool_result["success"]:
        result["errors"].append(apktool_result["error"])
    if not jadx_result["success"] and not jadx_success:
        result["errors"].append(jadx_result["error"])

    # Save intermediate result
    result_path = sample_work / "step1_extraction.json"
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python step1_apk_extraction.py <apk_path> [work_dir]")
        sys.exit(1)
    apk = sys.argv[1]
    work = sys.argv[2] if len(sys.argv) > 2 else str(settings.WORK_DIR)
    print(json.dumps(extract_apk(apk, work), indent=2))
