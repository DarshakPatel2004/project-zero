import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from analysis.retry_utils import safe_decompile_apk, DecompilationError


def _make_jadx_success(output_dir):
    """Factory: returns a function that creates JADX output and returns success mock."""
    def _run(*args, **kwargs):
        sources_dir = Path(output_dir) / "sources"
        sources_dir.mkdir(parents=True, exist_ok=True)
        (sources_dir / "Test.java").write_text("class Test {}")
        return MagicMock(returncode=0, stderr="")
    return _run


class TestSafeDecompileAPK:
    def test_success_on_first_try(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            apk_file = Path(tmpdir) / "test.apk"
            apk_file.write_bytes(b"test")
            output_dir = Path(tmpdir) / "output"

            with patch("subprocess.run", _make_jadx_success(output_dir)):
                result = safe_decompile_apk(
                    str(apk_file), str(output_dir), timeout=10, max_retries=3
                )

                assert result["success"] is True
                assert result["attempt"] == 1

    def test_retry_on_timeout(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            from subprocess import TimeoutExpired

            apk_file = Path(tmpdir) / "test.apk"
            apk_file.write_bytes(b"test")
            output_dir = Path(tmpdir) / "output"

            call_count = [0]

            def side_effect(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] < 3:
                    raise TimeoutExpired("jadx", 10)
                sources_dir = Path(output_dir) / "sources"
                sources_dir.mkdir(parents=True, exist_ok=True)
                (sources_dir / "Test.java").write_text("class Test {}")
                return MagicMock(returncode=0, stderr="")

            with patch("subprocess.run", side_effect=side_effect) as mock_run:
                result = safe_decompile_apk(
                    str(apk_file), str(output_dir), timeout=10, max_retries=3
                )

                assert result["success"] is True
                assert result["attempt"] == 3
                assert call_count[0] == 3

    def test_max_retries_exceeded(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            apk_file = Path(tmpdir) / "test.apk"
            apk_file.write_bytes(b"test")
            output_dir = Path(tmpdir) / "output"

            with patch("subprocess.run") as mock_run:
                from subprocess import TimeoutExpired
                mock_run.side_effect = TimeoutExpired("jadx", 10)

                with pytest.raises(DecompilationError) as exc_info:
                    safe_decompile_apk(
                        str(apk_file), str(output_dir), timeout=10, max_retries=2
                    )

                assert exc_info.value.error_type == "timeout"
                assert mock_run.call_count == 2

    def test_malformed_apk_no_retry(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            apk_file = Path(tmpdir) / "test.apk"
            apk_file.write_bytes(b"not_a_zip")
            output_dir = Path(tmpdir) / "output"

            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=1, stderr="error: not a valid zip file"
                )

                with pytest.raises(DecompilationError) as exc_info:
                    safe_decompile_apk(
                        str(apk_file), str(output_dir), timeout=10, max_retries=3
                    )

                assert exc_info.value.error_type == "malformed"
                assert mock_run.call_count == 1

    def test_disk_space_no_retry(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            apk_file = Path(tmpdir) / "test.apk"
            apk_file.write_bytes(b"test")
            output_dir = Path(tmpdir) / "output"

            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=1, stderr="error: no space left on device"
                )

                with pytest.raises(DecompilationError) as exc_info:
                    safe_decompile_apk(
                        str(apk_file), str(output_dir), timeout=10, max_retries=3
                    )

                assert exc_info.value.error_type == "disk_space"
                assert mock_run.call_count == 1

    def test_exponential_backoff_timing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            apk_file = Path(tmpdir) / "test.apk"
            apk_file.write_bytes(b"test")
            output_dir = Path(tmpdir) / "output"

            from subprocess import TimeoutExpired

            def always_timeout(*args, **kwargs):
                raise TimeoutExpired("jadx", 10)

            with patch("subprocess.run", side_effect=always_timeout):
                with patch("time.sleep") as mock_sleep:
                    with pytest.raises(DecompilationError):
                        safe_decompile_apk(
                            str(apk_file), str(output_dir), timeout=10, max_retries=3
                        )

                    assert mock_sleep.call_count == 2
                    sleep_args = [call[0][0] for call in mock_sleep.call_args_list]
                    assert sleep_args[0] == 2
                    assert sleep_args[1] == 4

    def test_not_found_no_retry(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "output"
            apk_file = Path(tmpdir) / "nonexistent.apk"

            with pytest.raises(DecompilationError) as exc_info:
                safe_decompile_apk(
                    str(apk_file), str(output_dir), timeout=10, max_retries=3
                )

            assert exc_info.value.error_type == "not_found"
