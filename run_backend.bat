@echo off
cd /d D:\DroidForensix

if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
) else (
    echo Virtual environment not found at venv\Scripts\activate.bat
    exit /b 1
)

REM Use the bundled JRE for APKTool/JADX
set "JAVA_HOME=D:\DroidForensix\tools\jdk\jdk-21.0.3+9-jre"
set "PATH=%JAVA_HOME%\bin;D:\DroidForensix\tools\jadx\bin;D:\DroidForensix\tools\apktool;%PATH%"

REM Force local Ollama endpoint (overrides any inherited 0.0.0.0 value)
set "OLLAMA_HOST=http://localhost:11434"

echo Starting FastAPI backend...
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
