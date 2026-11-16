#!/usr/bin/env bash
set -euo pipefail

# Synchronisiert den Ordner server/ direkt in das eigenständige GitHub-Repository
# https://github.com/MasterBurns/DDNeo-Server.git (Branch: main)
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if ! git remote get-url server-origin >/dev/null 2>&1; then
    git remote add server-origin https://github.com/MasterBurns/DDNeo-Server.git
fi

git subtree push --prefix=server server-origin main
echo "✔ MasterBurns/DDNeo-Server (main) erfolgreich aktualisiert!"
