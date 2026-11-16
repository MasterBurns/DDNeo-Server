#!/usr/bin/env bash
set -euo pipefail

# Baut den Linux Dedicated Server (und optional das Hauptspiel) in server/dist/linux/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT_DIR="${SCRIPT_DIR}/dist/linux"

echo "[1/2] Baue ddneo-server (Linux x86_64 Release) ..."
cargo build --release --manifest-path "${ROOT_DIR}/Cargo.toml" -p ddneo-server

mkdir -p "${OUT_DIR}/saves"
cp -f "${ROOT_DIR}/target/release/ddneo-server" "${OUT_DIR}/ddneo-server"
cp -f "${SCRIPT_DIR}/server_config.example.json" "${OUT_DIR}/server_config.example.json"
if [[ ! -f "${OUT_DIR}/server_config.json" ]]; then
    cp -f "${SCRIPT_DIR}/server_config.example.json" "${OUT_DIR}/server_config.json"
fi
cp -f "${SCRIPT_DIR}/ddneo-server.service" "${OUT_DIR}/ddneo-server.service"
cp -f "${SCRIPT_DIR}/install_vps_linux.sh" "${OUT_DIR}/install_vps_linux.sh"
chmod +x "${OUT_DIR}/ddneo-server" "${OUT_DIR}/install_vps_linux.sh"

echo "[2/2] Fertiges Linux-Server-Paket bereit unter:"
echo "      ${OUT_DIR}/ddneo-server"
