from pathlib import Path
from typing import Dict, Any

ROOT_DIR = Path(__file__).resolve().parent.parent.parent


class DynamicConfig:
    AVD_HOME: Path = Path.home() / ".android" / "avd"
    AVD_NAME: str = "DroidForensix_AVD"
    ANDROID_SDK_ROOT: Path = ROOT_DIR / "tools" / "android-sdk"
    ADB_PATH: Path = ANDROID_SDK_ROOT / "platform-tools" / "adb.exe"
    EMULATOR_PATH: Path = ANDROID_SDK_ROOT / "emulator" / "emulator.exe"
    FRIDA_SERVER_PATH: Path = ANDROID_SDK_ROOT / "frida-server"

    FRIDA_PORT: int = 27042
    FRIDA_CONNECT_RETRIES: int = 3
    FRIDA_CONNECT_TIMEOUT: int = 10

    INSTALL_TIMEOUT: int = 60
    RUN_TIMEOUT: int = 180
    IDLE_TIMEOUT: int = 60

    MAX_OUTPUT_BYTES: int = 10 * 1024 * 1024

    ENABLE_HOOK_METHOD_INVOKE: bool = True
    ENABLE_HOOK_URL_OPENCONNECTION: bool = True
    ENABLE_HOOK_STRING_INIT: bool = True
    ENABLE_HOOK_CIPHER_DOFINAL: bool = True
    ENABLE_HOOK_CLASSLOADER: bool = True

    MAX_CIPHER_CALLS: int = 50
    MAX_OUTPUT_LINES: int = 5000

    CONFIDENCE_MULTIPLIER_VALIDATED: float = 1.3
    CONFIDENCE_MULTIPLIER_CONTRADICTED: float = 0.7
    NEW_C2_CONFIDENCE_THRESHOLD: float = 0.85

    ENABLED: bool = False

    @classmethod
    def setup_env(cls) -> None:
        import os
        os.environ.setdefault("ANDROID_SDK_ROOT", str(cls.ANDROID_SDK_ROOT))
        os.environ.setdefault("ANDROID_HOME", str(cls.ANDROID_SDK_ROOT))

    @classmethod
    def to_dict(cls) -> Dict[str, Any]:
        return {k: v for k, v in vars(cls).items() if not k.startswith("_")}


settings = DynamicConfig()
settings.setup_env()
