# DDNeo Dedicated Server (`ddneo-server`)

Eigenständiger, ressourcenschonender 24/7-Multiplayer-Server in **Rust** für **Linux-VPS** (bereits ab 1 vCPU & 512 MB RAM lauffähig; ideal für 1–2 CPU / 8 GB RAM VPS) sowie als **`ddneo-server.exe` für Windows**.

## Eigenschaften
- **Keine Grafik-/Karten-Abhängigkeiten:** Benötigt weder GPU/Vulkan noch X11/Wayland oder OpenStreetMap-`.pbf`-Dateien (nur ca. 20–40 MB RAM).
- **0 %-CPU-Hibernation im Leerlauf (`pause_when_empty: true`):** Ist kein Spieler verbunden, legt sich die `20 Hz`-Schleife komplett schlafen und pausiert optional die Weltzeit, sodass über Nacht keine Gildenvorräte verbraucht werden.
- **Zentrale Server-Charaktere & Persistenter Weltstatus (`saves/server_world.bin`):** Verwaltet alle Online-Charaktere zentral auf dem Server (strikt getrennt vom lokalen Offline-Einzelspieler; Start auf Stufe 1 beim ersten Beitritt, zentrales Server-Charakterregister für alle Mitspieler) sowie Gilden, Außenposten, Kisten-Inventare, Forschung, Fahrzeuge, Diplomatie/PvP-Kriege, Welt-Seed und versiegelte/stabilisierte Portale alle 30 s sowie automatisch beim Stoppen (`SIGTERM` / `Strg+C`).
- **Live-Statusdatei (`saves/server_status.json`):** Jederzeit per `cat saves/server_status.json` einsehbar.

---

## 1. Installation auf deinem Linux-VPS per Git Clone (Empfohlen)

Auf deinem Linux-VPS einfach dieses Repository klonen und das Installationsskript ausführen:

```bash
# 1. Auf dem Linux-VPS einloggen und das Server-Repository klonen:
git clone https://github.com/MasterBurns/DDNeo-Server.git ~/ddneo-server
cd ~/ddneo-server

# 2. Automatisch kompilieren & als dauerhaften 24/7 systemd-Dienst einrichten:
chmod +x install_vps_linux.sh
sudo ./install_vps_linux.sh
```

**Spätere Updates auf dem VPS einspielen (Spielstand & Config bleiben erhalten!):**
```bash
cd ~/ddneo-server && git pull && sudo ./install_vps_linux.sh
```

Das Skript prüft/installiert Rust automatisch, kompiliert `ddneo-server` exakt passend für das Linux-System des VPS nach `/opt/ddneo-server` und startet den dauerhaften `systemd`-Dienst `ddneo-server.service` (startet auch nach einem VPS-Reboot automatisch neu).

**Port in der VPS-Firewall öffnen:**
```bash
sudo ufw allow 27777/tcp
```

**Im Spiel verbinden:**
Im Hauptmenü oder im Spiel `[P]` drücken → Tab **`Direkt-IP`** → `DEINE_VPS_IP:27777` eintragen → optional **`+ Als Favorit merken`** → **`Direkt verbinden`**.

---

## 2. Windows `.exe` erstellen (`ddneo-server.exe` & `ddneo.exe`)

### Variante A: Direkt unter Windows bauen
1. Rust installieren ([rustup.rs](https://rustup.rs)).
2. Doppelklick auf `server\build_windows.bat`.
3. Fertige `.exe`-Dateien liegen in:
   - Server: `server\dist\windows\ddneo-server.exe`
   - Spiel: `dist\windows-game\ddneo.exe`

### Variante B: Unter Linux für Windows cross-kompilieren
```bash
# Einmalig unter Arch Linux:
#   sudo pacman -S mingw-w64-gcc rustup
#   rustup default stable && rustup target add x86_64-pc-windows-gnu
cd server
chmod +x build_windows_exe.sh
./build_windows_exe.sh              # baut server/dist/windows/ddneo-server.exe
./build_windows_exe.sh --with-game  # baut zusätzlich dist/windows-game/ddneo.exe
```

---

## 3. Alternativ: Betrieb per Docker auf dem VPS

```bash
cd server
docker build -t ddneo-server .
docker run -d --name ddneo-server --restart unless-stopped \
  -p 27777:27777 \
  -v "$(pwd)/saves:/app/saves" \
  ddneo-server
```

---

## 4. Konfiguration (`server_config.json`)

| Feld | Standard | Beschreibung |
| :--- | :--- | :--- |
| `bind_ip` | `"0.0.0.0"` | Lauscht auf allen Netzwerkinterfaces |
| `tcp_port` | `27777` | TCP-Spielport |
| `max_players` | `12` | Maximale gleichzeitige Spieler |
| `session_name` | `"DDNeo 24/7 Weltserver"` | Name der Welt |
| `password` | `""` | Optionales Beitritts-Passwort (leer = öffentlich) |
| `pause_when_empty` | `true` | `true` = 0 % CPU & Weltzeit pausiert bei 0 Spielern |
| `save_interval_secs` | `30` | Automatisches Speicherintervall in Sekunden |
