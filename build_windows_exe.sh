#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Cross-Compile-Skript unter Linux -> erzeugt Windows .exe Dateien:
#   1. server/dist/windows/ddneo-server.exe  (Dedicated Server für Windows)
#   2. dist/windows-game/ddneo.exe           (Optional mit --with-game)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET="x86_64-pc-windows-gnu"
OUT_SRV="${SCRIPT_DIR}/dist/windows"

if ! command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "=============================================================="
    echo "  [Fehlt] MinGW-w64 Cross-Compiler für Windows (.exe) Build"
    echo "=============================================================="
    echo "  Bitte einmalig installieren:"
    echo "    Arch Linux    : sudo pacman -S mingw-w64-gcc rustup"
    echo "                    rustup default stable && rustup target add ${TARGET}"
    echo "    Ubuntu/Debian : sudo apt install gcc-mingw-w64-x86-64"
    echo "                    rustup target add ${TARGET}"
    echo ""
    echo "  Alternativ direkt unter Windows 'server\\build_windows.bat' starten!"
    echo "=============================================================="
    exit 1
fi

if command -v rustup >/dev/null 2>&1; then
    rustup target add "${TARGET}" >/dev/null 2>&1 || true
fi

echo "[1/2] Baue Windows Dedicated Server (ddneo-server.exe) ..."
cargo build --release --target "${TARGET}" --manifest-path "${SCRIPT_DIR}/Cargo.toml"

BIN_EXE="${SCRIPT_DIR}/target/${TARGET}/release/ddneo-server.exe"
if [[ ! -f "${BIN_EXE}" && -f "${ROOT_DIR}/target/${TARGET}/release/ddneo-server.exe" ]]; then
    BIN_EXE="${ROOT_DIR}/target/${TARGET}/release/ddneo-server.exe"
fi

mkdir -p "${OUT_SRV}/saves"
cp -f "${BIN_EXE}" "${OUT_SRV}/ddneo-server.exe"
if [[ ! -f "${OUT_SRV}/server_config.json" ]]; then
    cp -f "${SCRIPT_DIR}/server_config.example.json" "${OUT_SRV}/server_config.json"
fi
echo "      -> ${OUT_SRV}/ddneo-server.exe erstellt!"

if [[ "${1:-}" == "--with-game" ]]; then
    echo "[2/2] Baue Windows Spiel-Client (ddneo.exe) ..."
    cargo build --release --target "${TARGET}" --manifest-path "${ROOT_DIR}/Cargo.toml" --bin ddneo
    OUT_GAME="${ROOT_DIR}/dist/windows-game"
    mkdir -p "${OUT_GAME}"
    cp -f "${ROOT_DIR}/target/${TARGET}/release/ddneo.exe" "${OUT_GAME}/ddneo.exe"
    cp -rf "${ROOT_DIR}/assets" "${OUT_GAME}/"
    cp -rf "${ROOT_DIR}/data" "${OUT_GAME}/"
    echo "      -> ${OUT_GAME}/ddneo.exe inkl. assets/ & data/ erstellt!"
else
    echo "[Tipp] Mit './build_windows_exe.sh --with-game' wird zusätzlich ddneo.exe gebaut."
fi
