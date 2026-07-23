import json
import logging
import os
import time
import subprocess
import threading
from pathlib import Path
from typing import Dict, Any, Optional

from analysis.dynamic.config import settings as dyn_config
from analysis.dynamic.frida_hooks import build_frida_script, hook_count
from backend.config import settings as app_config
from analysis.dynamic.orchestrator import (
    start_emulator,
    wait_for_device,
    wait_for_frida,
    install_apk,
    launch_activity,
    stop_emulator,
    adb_command,
    OrchestratorError,
)
from analysis.dynamic.capture import CaptureResult, parse_line, check_idle_timeout
from analysis.dynamic.correlator import correlate

logger = logging.getLogger(__name__)


class DynamicValidationError(Exception):
    pass


def preflight_check() -> Dict[str, Any]:
    checks = {
        "emulator_exists": False,
        "adb_exists": False,
        "frida_importable": False,
        "avd_created": False,
    }
    checks["adb_exists"] = os.path.isfile(str(dyn_config.ADB_PATH))
    checks["emulator_exists"] = os.path.isfile(str(dyn_config.EMULATOR_PATH))
    avd_dir = dyn_config.AVD_HOME / f"{dyn_config.AVD_NAME}.avd"
    checks["avd_created"] = avd_dir.is_dir()
    try:
        import frida
        checks["frida_importable"] = True
    except ImportError:
        pass
    checks["all_ok"] = all(checks.values())
    return checks


def _resolve_frida_device():
    import frida
    mgr = frida.get_device_manager()
    strategies = [
        ("enumerate_tcp", lambda: next(
            d for d in mgr.enumerate_devices()
            if d.type == "tcp"
        )),
        ("remote", lambda: mgr.add_remote_device(
            f"127.0.0.1:{dyn_config.FRIDA_PORT}"
        )),
        ("usb", lambda: frida.get_usb_device(timeout=10)),
        ("enumerate_any", lambda: next(
            d for d in mgr.enumerate_devices()
            if d.type in ("tcp", "usb")
        )),
        ("local", lambda: frida.get_local_device()),
    ]
    for name, fn in strategies:
        try:
            device = fn()
            logger.info("Frida device resolved via %s: %s", name, device)
            return device
        except Exception as e:
            logger.debug("Frida device strategy '%s' failed: %s", name, e)
    logger.warning("No Frida device available")
    return None


def _start_frida_session(package_name: str, script_source: str, result: CaptureResult):
    import frida
    device = _resolve_frida_device()
    if not device:
        return None

    try:
        session = device.attach(package_name)
        logger.info("Frida attached to running process: %s", package_name)
    except Exception:
        logger.info("Process %s not running, trying spawn", package_name)
        try:
            pid = device.spawn([package_name])
            session = device.attach(pid)
            device.resume(pid)
            time.sleep(1)
            logger.info("Frida spawned and attached to %s (pid %d)", package_name, pid)
        except Exception as e2:
            logger.warning("Frida attach/spawn to %s failed: %s", package_name, e2)
            return None

    script = session.create_script(script_source)

    def on_message(message, data):
        if message.get("type") == "send":
            payload = message.get("payload", "")
            if isinstance(payload, str):
                parse_line(payload, result)
        elif message.get("type") == "error":
            logger.debug("Frida hook error: %s", message.get("description", ""))

    script.on("message", on_message)

    try:
        script.load()
        logger.info("Frida script loaded (%d hooks)", hook_count())
        return script
    except Exception as e:
        logger.warning("Frida script load failed: %s", e)
        return None


def _run_dynamic_analysis(
    apk_path: str,
    package_name: Optional[str] = None,
    work_dir: Optional[str] = None,
    static_c2_list: Optional[list] = None,
) -> Dict[str, Any]:
    if static_c2_list is None:
        static_c2_list = []
    start_time = time.time()
    result = CaptureResult()

    logger.info("Starting dynamic validation for %s", apk_path)

    if not start_emulator():
        return {
            "status": "failed",
            "reason": "Emulator failed to start",
            "duration_seconds": round(time.time() - start_time, 1),
            "events": result.to_dict(),
            "correlation": {},
        }

    try:
        if not wait_for_device(timeout=60):
            return {
                "status": "failed",
                "reason": "Device not ready after 60s",
                "duration_seconds": round(time.time() - start_time, 1),
                "events": result.to_dict(),
                "correlation": {},
            }

        if not wait_for_frida():
            return {
                "status": "failed",
                "reason": "Frida server not reachable",
                "duration_seconds": round(time.time() - start_time, 1),
                "events": result.to_dict(),
                "correlation": {},
            }

        if not install_apk(apk_path):
            return {
                "status": "failed",
                "reason": "APK installation failed",
                "duration_seconds": round(time.time() - start_time, 1),
                "events": result.to_dict(),
                "correlation": {},
            }

        if package_name:
            script_source = build_frida_script()
            frida_script = _start_frida_session(package_name, script_source, result)
            if not frida_script:
                return {
                    "status": "partial",
                    "reason": "Frida session failed, no runtime data captured",
                    "duration_seconds": round(time.time() - start_time, 1),
                    "events": result.to_dict(),
                    "correlation": {},
                }

            adb_command(["shell", "input", "keyevent", "82"])  # WAKEUP/UNLOCK
            time.sleep(2)
            adb_command(["shell", "input", "keyevent", "3"])   # HOME
            time.sleep(1)
            adb_command(["shell", "input", "keyevent", "61"])  # TAB
            time.sleep(1)

            app_running = True
            hook_start = time.time()
            while app_running:
                elapsed = time.time() - hook_start
                if elapsed > dyn_config.RUN_TIMEOUT:
                    logger.info("Run timeout reached (%ds)", dyn_config.RUN_TIMEOUT)
                    break
                if elapsed > 30 and elapsed % 30 < 0.5:
                    adb_command(["shell", "input", "touchscreen", "swipe", "500", "1000", "500", "500"],
                                timeout=5)
                if check_idle_timeout(result, timeout=dyn_config.IDLE_TIMEOUT):
                    logger.info("No Frida output for %ds, stopping", dyn_config.IDLE_TIMEOUT)
                    break
                time.sleep(0.5)
        else:
            logger.info("No package name provided, skipping Frida attachment")

    except Exception as e:
        logger.error("Dynamic analysis error: %s", e, exc_info=True)
        return {
            "status": "error",
            "reason": str(e),
            "duration_seconds": round(time.time() - start_time, 1),
            "events": result.to_dict(),
            "correlation": {},
        }
    finally:
        stop_emulator()

    correlation_result = correlate(
        static_c2_list=static_c2_list,
        dynamic_events=result.artifacts,
    )

    total_duration = round(time.time() - start_time, 1)
    logger.info(
        "Dynamic validation complete: %d events in %.1fs",
        len(result.events), total_duration,
    )

    return {
        "status": "success",
        "duration_seconds": total_duration,
        "events": result.to_dict(),
        "correlation": correlation_result,
        "errors": [],
    }


def apply_to_result(
    pipeline_result: Dict[str, Any],
    dynamic_result: Dict[str, Any],
) -> Dict[str, Any]:
    if not dynamic_result or dynamic_result.get("status") not in ("success", "partial"):
        return pipeline_result

    correlation = dynamic_result.get("correlation", {})
    if not correlation:
        return pipeline_result

    c2_list = pipeline_result.get("c2_infrastructure", [])
    if not isinstance(c2_list, list):
        c2_list = []

    validated = {c["domain"]: c for c in correlation.get("c2_validated", [])}
    contradicted = {c["domain"]: c for c in correlation.get("c2_contradicted", [])}

    updated_c2 = []
    for c2 in c2_list:
        domain = (c2.get("domain") or "").lower().strip()
        if domain in validated:
            c2["confidence"] = validated[domain]["new_confidence"]
            c2["validation"] = "dynamic_verified"
            c2["dynamic_multiplier"] = dyn_config.CONFIDENCE_MULTIPLIER_VALIDATED
        elif domain in contradicted:
            c2["confidence"] = contradicted[domain]["new_confidence"]
            c2["validation"] = "dynamic_contradicted"
            c2["dynamic_multiplier"] = dyn_config.CONFIDENCE_MULTIPLIER_CONTRADICTED
        updated_c2.append(c2)

    pipeline_result["c2_infrastructure"] = updated_c2
    pipeline_result["dynamic_validation"] = dynamic_result

    return pipeline_result


def validate_with_dynamic(
    apk_path: str,
    package_name: Optional[str] = None,
    work_dir: Optional[str] = None,
    pipeline_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if not app_config.ENABLE_DYNAMIC:
        return {"status": "skipped", "reason": "Dynamic analysis disabled (ENABLE_DYNAMIC=False)"}

    static_c2_list = (pipeline_result or {}).get("c2_infrastructure", []) or []
    dynamic_result = _run_dynamic_analysis(
        apk_path=apk_path,
        package_name=package_name,
        work_dir=work_dir,
        static_c2_list=static_c2_list,
    )

    if pipeline_result:
        pipeline_result = apply_to_result(pipeline_result, dynamic_result)

    return dynamic_result
