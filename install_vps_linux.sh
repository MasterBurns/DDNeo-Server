#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# DDNeo Dedicated Server — Automatischer Linux-VPS Installer (1–2 CPU / 8 GB RAM)
# Baut das schlanke Rust-Server-Binary nativ auf dem VPS (keine Grafik-/C-Libs
# nötig) und richtet es als dauerhaften systemd-Hintergrunddienst ein.
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/ddneo-server"
SERVICE_NAME="ddneo-server"

echo "=============================================================="
echo "  DDNeo Dedicated Server — Linux VPS Setup"
echo "=============================================================="

if [[ $EUID -ne 0 ]]; then
    echo "[Hinweis] Bitte mit sudo ausführen: sudo ./install_vps_linux.sh"
    exit 1
fi

# 1. Basis-Build-Tools prüfen (nur cc/gcc + curl für rustup falls Rust noch fehlt)
if ! command -v cc >/dev/null 2>&1; then
    echo "[1/5] Installiere C-Linker (gcc/build-essential) ..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y && apt-get install -y build-essential curl ca-certificates
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y gcc curl ca-certificates
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm base-devel curl ca-certificates
    fi
fi

# 2. Rust-Compiler prüfen / installieren
if ! command -v cargo >/dev/null 2>&1; then
    if [[ -x "/root/.cargo/bin/cargo" ]]; then
        export PATH="/root/.cargo/bin:${PATH}"
    else
        echo "[2/5] Installiere aktuelle Rust-Toolchain via rustup ..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
        export PATH="/root/.cargo/bin:${PATH}"
    fi
else
    echo "[2/5] Rust-Toolchain gefunden: $(cargo --version)"
fi

# 3. Nativ auf dem VPS kompilieren (dauert nur wenige Sekunden, 100% glibc-kompatibel!)
echo "[3/5] Kompiliere 'ddneo-server' (Release, optimiert) ..."
cd "${SCRIPT_DIR}"
cargo build --release --manifest-path "${SCRIPT_DIR}/Cargo.toml"

BIN_SRC="${SCRIPT_DIR}/target/release/ddneo-server"
if [[ ! -f "${BIN_SRC}" && -f "${SCRIPT_DIR}/../target/release/ddneo-server" ]]; then
    BIN_SRC="${SCRIPT_DIR}/../target/release/ddneo-server"
fi

# 4. Systembenutzer & /opt/ddneo-server anlegen (bestehende Spielstände bleiben erhalten!)
echo "[4/5] Richte '${INSTALL_DIR}' ein ..."
if ! id -u ddneo >/dev/null 2>&1; then
    useradd --system --home-dir "${INSTALL_DIR}" --shell /usr/sbin/nologin ddneo
fi

mkdir -p "${INSTALL_DIR}/saves"
if systemctl is-active --quiet "${SERVICE_NAME}"; then
    echo "      Stoppe laufenden Dienst sauber (speichert aktuellen Weltstatus) ..."
    systemctl stop "${SERVICE_NAME}"
fi

cp -f "${BIN_SRC}" "${INSTALL_DIR}/ddneo-server"
chmod 755 "${INSTALL_DIR}/ddneo-server"

if [[ ! -f "${INSTALL_DIR}/server_config.json" ]]; then
    cp "${SCRIPT_DIR}/server_config.example.json" "${INSTALL_DIR}/server_config.json"
    echo "      Neue Konfiguration angelegt: ${INSTALL_DIR}/server_config.json"
else
    echo "      Bestehende Konfiguration behalten: ${INSTALL_DIR}/server_config.json"
fi

chown -R ddneo:ddneo "${INSTALL_DIR}"

# 5. systemd-Dienst aktivieren & starten
echo "[5/5] Aktiviere systemd-Dienst '${SERVICE_NAME}.service' ..."
cp -f "${SCRIPT_DIR}/ddneo-server.service" "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}.service"
sleep 1

echo ""
echo "=============================================================="
echo "  FERTIG! DDNeo Dedicated Server läuft jetzt dauerhaft (24/7)."
echo "=============================================================="
echo "  Status prüfen     : sudo systemctl status ${SERVICE_NAME}"
echo "  Live-Logs ansehen : sudo journalctl -u ${SERVICE_NAME} -f"
echo "  Welt-Status JSON  : cat ${INSTALL_DIR}/saves/server_status.json"
echo "  Konfiguration     : sudo nano ${INSTALL_DIR}/server_config.json"
echo "                      (danach: sudo systemctl restart ${SERVICE_NAME})"
echo ""
echo "  Web-Admin-Zugangsdaten (in ${INSTALL_DIR}/server_config.json):"
grep -E '"admin_(port|username|password)"' "${INSTALL_DIR}/server_config.json" || true
echo ""
echo "  WICHTIG — Firewall-Ports freigeben (falls UFW aktiv):"
echo "    sudo ufw allow 27777/tcp   # Spielserver"
echo "    sudo ufw allow 27779/tcp   # Web-Admin-Oberfläche im Browser"
echo "=============================================================="
