from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralized Windows-native DroidForensix configuration."""

    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parent.parent / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # File system paths (Windows absolute)
    WORK_DIR: Path = Path(r"D:\DroidForensix\analysis\work")
    REPORTS_DIR: Path = Path(r"D:\DroidForensix\reports")
    SAMPLES_DIR: Path = Path(r"D:\DroidForensix\samples")
    UPLOADS_DIR: Path = Path(r"D:\DroidForensix\uploads")

    # Analysis tools (Windows installations)
    JADX_PATH: str = r"D:\DroidForensix\tools\jadx\bin\jadx.bat"
    APKTOOL_PATH: str = r"D:\DroidForensix\tools\apktool\apktool.bat"
    DIE_PATH: str = r"D:\DroidForensix\tools\die\die\diec.exe"
    YARA_RULES_PATH: str = r"D:\DroidForensix\analysis\yara_rules.yar"
    SEVEN_ZIP_PATH: str = r"C:\Program Files\7-Zip\7z.exe"

    # Ollama / LLM inference (local Windows service)
    OLLAMA_HOST: str = "http://localhost:11434"
    # Default model; override via the OLLAMA_MODEL environment variable or .env
    OLLAMA_MODEL: str = "mistral:7b-instruct-q4_K_M"
    OLLAMA_TIMEOUT: int = 120

    # NVIDIA NIM (optional, for future expansion)
    NIM_ENABLED: bool = False
    NIM_HOST: Optional[str] = None
    NIM_MODEL: Optional[str] = None
    NIM_API_KEY: Optional[str] = None

    # LLM provider selection: "auto" (default), "nvidia", or "ollama".
    # "auto" prefers NVIDIA NIM if NVIDIA_NIM_API_KEY is set, otherwise Ollama.
    LLM_PROVIDER: str = "auto"

    # Pipeline settings
    STEP_TIMEOUT: int = 300  # seconds per step
    MAX_UPLOAD_SIZE_MB: int = 100
    ENABLE_LOGGING: bool = True
    LOG_LEVEL: str = "INFO"

    # Web server
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000
    FRONTEND_URL: str = "http://localhost:5173"
    # Allow both localhost and 127.0.0.1: browsers treat them as distinct
    # origins, and the Vite dev server may be reached via either host.
    # Include the configured FRONTEND_URL plus common Vite dev/preview ports.
    CORS_ORIGINS: list = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:4173",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:4173",
    ]


settings = Settings()

# Ensure directories exist
for dir_path in [settings.WORK_DIR, settings.REPORTS_DIR, settings.SAMPLES_DIR, settings.UPLOADS_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)
