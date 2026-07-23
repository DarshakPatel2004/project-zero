import logging
import time
from pathlib import Path

LOG_DIR = Path("analysis/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("droidforenix.retry")
logger.setLevel(logging.DEBUG)

if not logger.handlers:
    handler = logging.FileHandler(LOG_DIR / "retry_log.txt")
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)


class DecompilationError(Exception):
    def __init__(self, apk_path: str, error_type: str, message: str):
        self.apk_path = apk_path
        self.error_type = error_type
        self.message = message
        super().__init__(message)

    def to_dict(self) -> dict:
        return {
            "error": self.error_type,
            "message": self.message,
            "apk": self.apk_path,
        }


NO_RETRY_ERRORS = {"not_found", "malformed", "disk_space"}


def safe_decompile_apk(
    apk_path: str,
    output_dir: str,
    timeout: int = 120,
    max_retries: int = 3,
    jadx_path: str = "jadx",
) -> dict:
    import subprocess
    import shutil

    apk_path_obj = Path(apk_path)
    output_dir_obj = Path(output_dir)

    if not apk_path_obj.exists():
        raise DecompilationError(
            str(apk_path), "not_found", f"APK file not found: {apk_path}"
        )

    if output_dir_obj.exists():
        shutil.rmtree(output_dir_obj)
    output_dir_obj.mkdir(parents=True, exist_ok=True)

    logger.info("Starting decompilation: %s -> %s", apk_path, output_dir)

    last_error = None
    for attempt in range(1, max_retries + 1):
        logger.debug("Attempt %d/%d: Running JADX (timeout=%ss)", attempt, max_retries, timeout)

        try:
            result = subprocess.run(
                [jadx_path, str(apk_path_obj), "-d", str(output_dir_obj)],
                timeout=timeout,
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                stderr = result.stderr[:500]
                lower_stderr = result.stderr.lower()

                if "not a valid zip" in lower_stderr or "malformed" in lower_stderr:
                    raise DecompilationError(
                        str(apk_path), "malformed",
                        "APK file is corrupted or not a valid ZIP archive"
                    )
                if "no space left" in lower_stderr:
                    raise DecompilationError(
                        str(apk_path), "disk_space",
                        "Not enough disk space to extract APK"
                    )
                raise DecompilationError(
                    str(apk_path), "decompilation_failed", f"JADX error: {stderr}"
                )

            classes_dir = output_dir_obj / "sources"
            if not classes_dir.exists():
                raise DecompilationError(
                    str(apk_path), "incomplete",
                    "JADX succeeded but output structure is unexpected"
                )

            class_count = len(list(classes_dir.rglob("*.java")))
            logger.info("Success on attempt %d: %d classes extracted", attempt, class_count)
            return {
                "success": True,
                "output_dir": str(output_dir_obj),
                "classes": class_count,
                "attempt": attempt,
            }

        except subprocess.TimeoutExpired:
            logger.warning("Attempt %d/%d: JADX timeout after %ss", attempt, max_retries, timeout)
            last_error = DecompilationError(
                str(apk_path), "timeout",
                f"JADX decompilation timed out after {timeout}s. "
                f"Large APKs may need more time."
            )
        except DecompilationError as e:
            logger.error("Attempt %d: %s - %s", attempt, e.error_type, e.message)
            last_error = e
            if e.error_type in NO_RETRY_ERRORS:
                raise
        except Exception as e:
            logger.error("Attempt %d: Unexpected error: %s: %s", attempt, type(e).__name__, str(e)[:100])
            last_error = DecompilationError(
                str(apk_path), "internal_error",
                f"Unexpected error: {type(e).__name__}"
            )

        if attempt < max_retries:
            wait_time = 2 ** attempt
            logger.info("Waiting %ds before retry...", wait_time)
            time.sleep(wait_time)

    logger.error("All %d attempts failed: %s", max_retries, last_error)
    raise last_error


def retry_with_backoff(
    fn,
    max_retries=3,
    base_delay=2.0,
    backoff_factor=2.0,
    max_delay=60.0,
    jitter=True,
    retryable_exceptions=(Exception,),
    on_retry=None,
) -> tuple:
    """Retry a callable with exponential backoff.

    Args:
        fn: Zero-argument callable to retry.
        max_retries: Maximum number of retry attempts.
        base_delay: Initial delay in seconds.
        backoff_factor: Multiplier applied to delay each attempt.
        max_delay: Maximum delay cap in seconds.
        jitter: Add random jitter (±50%) to delay.
        retryable_exceptions: Exception types that trigger retry.
        on_retry: Optional callback(retry_attempt, exception).

    Returns:
        (success: bool, result_or_exception, attempts: int)
    """
    import random

    for attempt in range(max_retries + 1):
        try:
            result = fn()
            return (True, result, attempt + 1)
        except retryable_exceptions as e:
            if attempt == max_retries:
                return (False, e, attempt)
            if on_retry:
                on_retry(attempt + 1, e)
            delay = min(base_delay * (backoff_factor ** attempt), max_delay)
            if jitter:
                delay = delay * (0.5 + random.random() * 0.5)
            logger.debug("Retry %d/%d after %.2fs (error: %s)", attempt + 1, max_retries, delay, e)
            time.sleep(delay)
