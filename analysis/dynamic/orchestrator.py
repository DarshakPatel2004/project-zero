import logging
import subprocess
import time
import socket
import os
from pathlib import Path
from typing import Optional

from analysis.dynamic.config import settings

logger = logging.getLogger(__name__)


class OrchestratorError(Exception):
    pass


def _run_cmd(cmd: list, timeout: int, desc: str) -> subprocess.CompletedProcess:
    logger.debug("Running: %s", " ".join(str(c) for c in cmd))
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        raise OrchestratorError(f"{desc} timed out after {timeout}s")
    except FileNotFoundError as e:
        raise OrchestratorError(f"{desc} failed: {e}")
    except Exception as e:
        raise OrchestratorError(f"{desc} failed: {e}")


def adb_command(args: list, timeout: int = 10) -> subprocess.CompletedProcess:
    cmd = [str(settings.ADB_PATH)] + args
    return _run_cmd(cmd, timeout, f"adb {' '.join(args)}")


def check_frida_server() -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(settings.FRIDA_CONNECT_TIMEOUT)
    try:
        result = sock.connect_ex(("127.0.0.1", settings.FRIDA_PORT))
        return result == 0
    finally:
        sock.close()


def forward_frida_port() -> bool:
    try:
        result = adb_command(
            ["forward", f"tcp:{settings.FRIDA_PORT}", f"tcp:{settings.FRIDA_PORT}"],
            timeout=5,
        )
        ok = result.returncode == 0
        if ok:
            logger.info("Forwarded host:%d -> emulator:%d", settings.FRIDA_PORT, settings.FRIDA_PORT)
        else:
            logger.warning("Port forward failed: %s", result.stderr.strip())
        return ok
    except OrchestratorError as e:
        logger.warning("Port forward error: %s", e)
        return False


def setup_root_access() -> bool:
    try:
        r = adb_command(["shell", "getenforce"], timeout=5)
        if r.stdout.strip() != "Permissive":
            r = adb_command(["root"], timeout=10)
            time.sleep(2)
            r = adb_command(["shell", "setenforce", "0"], timeout=5)
            r = adb_command(["shell", "getenforce"], timeout=5)
            if r.stdout.strip() != "Permissive":
                logger.warning("Failed to set SELinux permissive")
                return False
        return True
    except Exception as e:
        logger.warning("SELinux check failed: %s", e)
        return True  # non-fatal, Frida may still work


def ensure_frida_server() -> bool:
    try:
        result = adb_command(["shell", "pidof", "frida-server"], timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            logger.info("Frida server already running (pid %s)", result.stdout.strip())
            return True
    except Exception:
        pass
    cmd = [str(settings.ADB_PATH), "shell", "nohup", "/data/local/tmp/frida-server"]
    try:
        subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(3)
        result = adb_command(["shell", "pidof", "frida-server"], timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            logger.info("Frida server started (pid %s)", result.stdout.strip())
            return True
        logger.warning("Frida server not running after start attempt")
        return False
    except Exception as e:
        logger.warning("Failed to start Frida server: %s", e)
        return False


def wait_for_frida(retries: int = None) -> bool:
    retries = retries or settings.FRIDA_CONNECT_RETRIES
    if not setup_root_access():
        return False
    if not ensure_frida_server():
        return False
    if not forward_frida_port():
        return False
    for i in range(retries):
        if check_frida_server():
            logger.info("Frida server ready (port %d)", settings.FRIDA_PORT)
            return True
        if i < retries - 1:
            logger.debug("Waiting for Frida server (attempt %d/%d)", i + 1, retries)
            time.sleep(2)
    logger.warning("Frida server not reachable after %d retries", retries)
    return False


def start_emulator() -> bool:
    cmd = [
        str(settings.EMULATOR_PATH),
        "-avd", settings.AVD_NAME,
        "-no-window",
        "-no-audio",
        "-read-only",
        "-snapshot", "clean_selinux_permissive",
        "-port", "5554",
        "-memory", "2048",
        "-cores", "2",
    ]
    try:
        subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        logger.info("Emulator launched for AVD: %s", settings.AVD_NAME)
        return True
    except Exception as e:
        logger.error("Failed to start emulator: %s", e)
        return False


def wait_for_device(timeout: int = 60) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            result = adb_command(["get-state"], timeout=5)
            if result.returncode == 0 and "device" in result.stdout.lower():
                break
        except Exception:
            pass
        time.sleep(3)
    else:
        logger.warning("Device not ready after %ds", timeout)
        return False

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            result = adb_command(
                ["shell", "getprop", "sys.boot_completed"],
                timeout=5,
            )
            boot = result.stdout.strip()
            if boot == "1":
                logger.info("Device ready (boot completed)")
                return True
        except Exception:
            pass
        time.sleep(3)
    logger.warning("Boot not completed after %ds", timeout)
    return False


def install_apk(apk_path: str) -> bool:
    if not os.path.isfile(apk_path):
        logger.error("APK not found: %s", apk_path)
        return False
    try:
        result = adb_command(
            ["install", "-r", "-t", "-d", apk_path],
            timeout=settings.INSTALL_TIMEOUT,
        )
        if result.returncode != 0:
            logger.info("adb install failed, trying pm install directly...")
            dest = f"/data/local/tmp/{os.path.basename(apk_path)}"
            push_r = adb_command(["push", apk_path, dest], timeout=30)
            if push_r.returncode == 0:
                result = adb_command(
                    ["shell", "pm", "install", "-r", "-t", "-d", "--no-restore", dest],
                    timeout=settings.INSTALL_TIMEOUT,
                )
        if result.returncode != 0:
            logger.warning("APK install failed: %s", result.stderr.strip())
            return False
        logger.info("APK installed: %s", apk_path)
        return True
    except OrchestratorError as e:
        logger.warning("APK install error: %s", e)
        return False


def launch_activity(package_name: str, activity: Optional[str] = None) -> bool:
    if activity:
        intent = f"{package_name}/{activity}"
    else:
        result = adb_command(
            ["shell", "cmd", "package", "resolve-activity", "--brief", package_name],
            timeout=10,
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        intent = lines[-1] if lines else None
        if not intent or "/" not in intent:
            intent = _resolve_launcher_activity(package_name)
    if not intent:
        logger.warning("Could not resolve launch activity for %s", package_name)
        return False
    try:
        result = adb_command(
            ["shell", "am", "start", "-n", intent, "-W"],
            timeout=settings.RUN_TIMEOUT,
        )
        logger.info("Launched: %s", intent)
        return result.returncode == 0
    except OrchestratorError as e:
        logger.warning("Activity launch failed: %s", e)
        return False


def _resolve_launcher_activity(package_name: str) -> Optional[str]:
    try:
        result = adb_command(
            ["shell", "pm", "resolve-activity", "--brief", package_name],
            timeout=10,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if "/" in line:
                return line
    except Exception:
        pass
    return None


def stop_emulator() -> None:
    try:
        adb_command(["emu", "kill"], timeout=10)
        logger.info("Emulator stopped")
    except Exception as e:
        logger.warning("Emulator stop error: %s", e)


def get_package_name(apk_path: str) -> Optional[str]:
    try:
        result = adb_command(
            ["shell", "pm", "dump", "packages"],
            timeout=10,
        )
        return None
    except Exception:
        return None


def save_snapshot(name: str = "post_install") -> bool:
    try:
        adb_command(["emu", "avd", "snapshot", "save", name], timeout=30)
        logger.info("Snapshot saved: %s", name)
        return True
    except Exception as e:
        logger.warning("Snapshot save failed: %s", e)
        return False
