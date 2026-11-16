@echo off
setlocal enabledelayedexpansion

REM ============================================================================
REM Baut unter Windows sowohl ddneo-server.exe als auch ddneo.exe (Release)
REM ============================================================================

cd /d "%~dp0"
set "SERVER_DIR=%CD%"
cd ..
set "ROOT_DIR=%CD%"

echo [1/2] Kompiliere DDNeo Dedicated Server (ddneo-server.exe) ...
cargo build --release -p ddneo-server
if errorlevel 1 (
    echo [FEHLER] Build von ddneo-server.exe fehlgeschlagen! Ist Rust installiert (https://rustup.rs)?
    pause
    exit /b 1
)

if not exist "%SERVER_DIR%\dist\windows\saves" mkdir "%SERVER_DIR%\dist\windows\saves"
copy /Y "%ROOT_DIR%\target\release\ddneo-server.exe" "%SERVER_DIR%\dist\windows\ddneo-server.exe" >nul
if not exist "%SERVER_DIR%\dist\windows\server_config.json" (
    copy /Y "%SERVER_DIR%\server_config.example.json" "%SERVER_DIR%\dist\windows\server_config.json" >nul
)
echo       OK: %SERVER_DIR%\dist\windows\ddneo-server.exe

echo [2/2] Kompiliere DDNeo Spiel-Client (ddneo.exe) ...
cargo build --release --bin ddneo
if errorlevel 1 (
    echo [HINWEIS] ddneo-server.exe ist fertig, Spiel-Build benoetigt ggf. sqlite3/MSVC Build Tools.
    pause
    exit /b 0
)

if not exist "%ROOT_DIR%\dist\windows-game" mkdir "%ROOT_DIR%\dist\windows-game"
copy /Y "%ROOT_DIR%\target\release\ddneo.exe" "%ROOT_DIR%\dist\windows-game\ddneo.exe" >nul
xcopy /E /I /Y "%ROOT_DIR%\assets" "%ROOT_DIR%\dist\windows-game\assets" >nul
xcopy /E /I /Y "%ROOT_DIR%\data" "%ROOT_DIR%\dist\windows-game\data" >nul
echo       OK: %ROOT_DIR%\dist\windows-game\ddneo.exe

echo.
echo ==============================================================
echo   FERTIG! Beide .exe-Pakete wurden erfolgreich erstellt:
echo   - Server : %SERVER_DIR%\dist\windows\ddneo-server.exe
echo   - Spiel  : %ROOT_DIR%\dist\windows-game\ddneo.exe
echo ==============================================================
pause
