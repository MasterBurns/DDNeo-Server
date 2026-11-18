use crate::bytes32_to_hex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ADMIN_HTML: &str = include_str!("admin_ui.html");
const MAX_HTTP_REQ_BYTES: usize = 256 * 1024;
const SESSION_TTL_SECS: u64 = 12 * 3600;

/// Generates a strong 16-character alphanumeric password when `server_config.json` has an empty `admin_password`.
pub fn generate_random_admin_password() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut out = String::with_capacity(16);
    let entropy: [u8; 16] = rand::random();
    for b in entropy {
        out.push(ALPHABET[(b as usize) % ALPHABET.len()] as char);
    }
    out
}

fn constant_time_str_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let mut diff = ab.len() ^ bb.len();
    let max_len = ab.len().max(bb.len());
    for i in 0..max_len {
        let x = ab.get(i).copied().unwrap_or(0);
        let y = bb.get(i).copied().unwrap_or(0);
        diff |= (x ^ y) as usize;
    }
    diff == 0
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BanEntry {
    pub ban_id: u64,
    #[serde(default)]
    pub device_fingerprint: String,
    #[serde(default)]
    pub pubkey_hex: String,
    #[serde(default)]
    pub player_uid: Option<u64>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub player_name: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub banned_at_unix_secs: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PlayerAdminMeta {
    pub last_ip: String,
    pub last_seen_unix_secs: u64,
    pub device_fingerprint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminLogEntry {
    pub time: String,
    pub text: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminCharacterRow {
    pub uid: u64,
    pub name: String,
    pub level: u32,
    pub role_label: String,
    pub online: bool,
    pub guild_name: String,
    pub guild_role: String,
    pub dimension: String,
    pub lat: f64,
    pub lon: f64,
    pub device_fingerprint: String,
    pub pubkey_hex: String,
    pub last_ip: String,
    pub last_seen_unix: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminBaseRow {
    pub building_id: u64,
    pub name: String,
    pub module_count: u32,
    pub lat: f64,
    pub lon: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminGuildRow {
    pub guild_id: u64,
    pub name: String,
    pub founder_name: String,
    pub member_count: usize,
    pub hostile_wars: usize,
    pub bases: Vec<AdminBaseRow>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminVehicleRow {
    pub vehicle_id: u64,
    pub label_de: String,
    pub owner_label: String,
    pub fuel_liters: f32,
    pub body_pct: f32,
    pub tires_pct: f32,
    pub driver_uid: Option<u64>,
    pub passenger_count: usize,
    pub lat: f64,
    pub lon: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminRiftPin {
    pub id: u64,
    pub level: u32,
    pub theme: String,
    pub lat: f64,
    pub lon: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminBackupRow {
    pub filename: String,
    pub size_bytes: u64,
    pub modified_unix: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminDashboardState {
    pub session_name: String,
    pub tcp_port: u16,
    pub online_players: usize,
    pub max_players: u8,
    pub server_password: String,
    pub pause_when_empty: bool,
    pub hibernating: bool,
    pub world_seed: u64,
    pub world_hour: f32,
    pub ingame_day_real_secs: f32,
    pub world_tier: i32,
    pub world_level_offset: i32,
    pub sample_min_rift_level: u32,
    pub sample_max_rift_level: u32,
    pub cached_rift_chunks: usize,
    pub sealed_portal_count: usize,
    pub uptime_secs: u64,
    pub characters: Vec<AdminCharacterRow>,
    pub bans: Vec<BanEntry>,
    pub guilds: Vec<AdminGuildRow>,
    pub vehicles: Vec<AdminVehicleRow>,
    pub rifts_preview: Vec<AdminRiftPin>,
    pub backups: Vec<AdminBackupRow>,
    pub recent_events: Vec<AdminLogEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AdminCommand {
    GetDashboard,
    ForceSave,
    SetWorldDifficulty {
        world_tier: i32,
        world_level_offset: i32,
    },
    SetWorldTime {
        world_hour: f32,
        ingame_day_real_secs: Option<f32>,
    },
    UpdateServerSettings {
        session_name: String,
        max_players: u8,
        password: String,
        pause_when_empty: bool,
    },
    BroadcastMessage {
        text: String,
    },
    KickPlayer {
        player_uid: u64,
        reason: String,
    },
    BanDevice {
        player_uid: Option<u64>,
        #[serde(default)]
        pubkey_hex: String,
        #[serde(default)]
        device_fingerprint: String,
        #[serde(default)]
        ip_address: Option<String>,
        #[serde(default)]
        player_name: String,
        #[serde(default)]
        reason: String,
        #[serde(default)]
        delete_character: bool,
    },
    UnbanDevice {
        ban_id: u64,
    },
    TeleportOrUnstuckPlayer {
        player_uid: u64,
        lat: Option<f64>,
        lon: Option<f64>,
        #[serde(default)]
        unstuck_to_overworld: bool,
    },
    SetCharacterLevel {
        player_uid: u64,
        new_level: u32,
    },
    DeleteCharacter {
        player_uid: u64,
    },
    ResetArea {
        lat: f64,
        lon: f64,
        radius_km: f64,
        reset_rifts: bool,
        restore_buildings: bool,
        remove_vehicles: bool,
        remove_bases: bool,
    },
    ResetAllRiftsGlobal,
    RegenerateWorld {
        new_seed: Option<u64>,
        keep_characters: bool,
    },
    RepairAndRefuelVehicle {
        vehicle_id: u64,
    },
    UnlockVehicleSeats {
        vehicle_id: u64,
    },
    DeleteVehicle {
        vehicle_id: u64,
    },
    DeleteBase {
        guild_id: u64,
        building_id: u64,
    },
    DisbandGuild {
        guild_id: u64,
    },
    ForceGlobalGuildPeace,
    CreateBackup {
        #[serde(default)]
        label: String,
    },
    RestoreBackup {
        filename: String,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct AdminActionReply {
    pub ok: bool,
    pub message: String,
    pub state: AdminDashboardState,
}

struct SessionRecord {
    csrf_token: String,
    expires_at: Instant,
}

struct RateLimitEntry {
    failures: u32,
    window_started: Instant,
}

pub struct AdminAuthStore {
    pub username: String,
    pub password: String,
    pub server_title: Mutex<String>,
    sessions: Mutex<HashMap<String, SessionRecord>>,
    rate_limits: Mutex<HashMap<IpAddr, RateLimitEntry>>,
}

impl AdminAuthStore {
    pub fn new(username: String, password: String, server_title: String) -> Self {
        Self {
            username,
            password,
            server_title: Mutex::new(server_title),
            sessions: Mutex::new(HashMap::new()),
            rate_limits: Mutex::new(HashMap::new()),
        }
    }

    fn verify_session(&self, cookie_token: Option<&str>) -> Option<String> {
        let tok = cookie_token?.trim();
        if tok.is_empty() {
            return None;
        }
        let mut map = self.sessions.lock().ok()?;
        let now = Instant::now();
        map.retain(|_, v| v.expires_at > now);
        map.get(tok).map(|s| s.csrf_token.clone())
    }

    fn attempt_login(&self, ip: IpAddr, user: &str, pass: &str) -> Result<(String, String), (u16, String)> {
        if self.password.trim().is_empty() {
            return Err((
                403,
                "Admin-Login deaktiviert: 'admin_password' in server_config.json ist leer.".to_string(),
            ));
        }
        {
            let mut rl = self.rate_limits.lock().unwrap();
            let now = Instant::now();
            let ent = rl.entry(ip).or_insert(RateLimitEntry {
                failures: 0,
                window_started: now,
            });
            if now.duration_since(ent.window_started) > Duration::from_secs(60) {
                ent.failures = 0;
                ent.window_started = now;
            }
            if ent.failures >= 6 {
                return Err((
                    429,
                    "Zu viele Fehlversuche — bitte 60 Sekunden warten.".to_string(),
                ));
            }
        }

        let u_ok = constant_time_str_eq(user.trim(), self.username.trim());
        let p_ok = constant_time_str_eq(pass, &self.password);
        if !u_ok || !p_ok {
            if let Ok(mut rl) = self.rate_limits.lock() {
                if let Some(ent) = rl.get_mut(&ip) {
                    ent.failures += 1;
                }
            }
            return Err((401, "Ungültiger Benutzername oder Passwort.".to_string()));
        }

        if let Ok(mut rl) = self.rate_limits.lock() {
            rl.remove(&ip);
        }

        let session_bytes: [u8; 32] = rand::random();
        let csrf_bytes: [u8; 32] = rand::random();
        let session_token = bytes32_to_hex(&session_bytes);
        let csrf_token = bytes32_to_hex(&csrf_bytes);
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.insert(
                session_token.clone(),
                SessionRecord {
                    csrf_token: csrf_token.clone(),
                    expires_at: Instant::now() + Duration::from_secs(SESSION_TTL_SECS),
                },
            );
        }
        Ok((session_token, csrf_token))
    }

    fn logout(&self, cookie_token: Option<&str>) {
        if let Some(tok) = cookie_token {
            if let Ok(mut sessions) = self.sessions.lock() {
                sessions.remove(tok.trim());
            }
        }
    }
}

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    password: String,
}

pub type AdminDispatchFn =
    Arc<dyn Fn(AdminCommand) -> tokio::sync::oneshot::Receiver<Result<AdminActionReply, String>> + Send + Sync>;

pub async fn run_admin_http_server(
    listener: tokio::net::TcpListener,
    auth: Arc<AdminAuthStore>,
    dispatch: AdminDispatchFn,
    stop_flag: Arc<AtomicBool>,
) {
    while !stop_flag.load(Ordering::Relaxed) {
        let Ok(Ok((mut stream, peer_addr))) =
            tokio::time::timeout(Duration::from_millis(350), listener.accept()).await
        else {
            continue;
        };
        let auth_c = Arc::clone(&auth);
        let disp_c = Arc::clone(&dispatch);
        tokio::spawn(async move {
            let _ = handle_http_connection(&mut stream, peer_addr.ip(), &auth_c, &disp_c).await;
        });
    }
}

async fn handle_http_connection(
    stream: &mut tokio::net::TcpStream,
    peer_ip: IpAddr,
    auth: &AdminAuthStore,
    dispatch: &AdminDispatchFn,
) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let header_end;

    loop {
        let n = match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => return Ok(()),
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
        };
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_HTTP_REQ_BYTES {
            return write_json_response(stream, 413, None, r#"{"ok":false,"error":"Payload too large"}"#).await;
        }
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
    }

    let header_str = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = header_str.lines();
    let Some(req_line) = lines.next() else {
        return Ok(());
    };
    let mut req_parts = req_line.split_whitespace();
    let method = req_parts.next().unwrap_or("");
    let raw_path = req_parts.next().unwrap_or("/");
    let path = raw_path.split('?').next().unwrap_or("/");

    let mut content_len = 0usize;
    let mut session_cookie: Option<String> = None;
    let mut csrf_header: Option<String> = None;

    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim();
            if key == "content-length" {
                content_len = val.parse::<usize>().unwrap_or(0);
            } else if key == "x-csrf-token" {
                csrf_header = Some(val.to_string());
            } else if key == "cookie" {
                for pair in val.split(';') {
                    if let Some((ck, cv)) = pair.trim().split_once('=') {
                        if ck.trim() == "ddneo_admin_session" {
                            session_cookie = Some(cv.trim().to_string());
                        }
                    }
                }
            }
        }
    }

    if content_len > MAX_HTTP_REQ_BYTES {
        return write_json_response(stream, 413, None, r#"{"ok":false,"error":"Body too large"}"#).await;
    }
    while buf.len() < header_end + content_len {
        let n = match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
        };
        buf.extend_from_slice(&chunk[..n]);
    }
    let body_slice = &buf[header_end..buf.len().min(header_end + content_len)];

    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => {
            write_raw_response(
                stream,
                200,
                "text/html; charset=utf-8",
                None,
                ADMIN_HTML.as_bytes(),
            )
            .await
        }
        ("GET", "/api/auth_status") => {
            let csrf = auth.verify_session(session_cookie.as_deref());
            let srv_title = auth
                .server_title
                .lock()
                .map(|s| s.clone())
                .unwrap_or_default();
            let body = serde_json::json!({
                "authenticated": csrf.is_some(),
                "username": auth.username,
                "session_name": srv_title,
                "csrf_token": csrf.unwrap_or_default(),
            });
            write_json_response(stream, 200, None, &body.to_string()).await
        }
        ("POST", "/api/login") => {
            let Ok(req) = serde_json::from_slice::<LoginReq>(body_slice) else {
                return write_json_response(
                    stream,
                    400,
                    None,
                    r#"{"ok":false,"error":"Ungültige JSON-Anfrage."}"#,
                )
                .await;
            };
            match auth.attempt_login(peer_ip, &req.username, &req.password) {
                Ok((sess_tok, csrf_tok)) => {
                    let cookie = format!(
                        "ddneo_admin_session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
                        sess_tok, SESSION_TTL_SECS
                    );
                    let body = serde_json::json!({
                        "ok": true,
                        "csrf_token": csrf_tok,
                    });
                    write_json_response(stream, 200, Some(&cookie), &body.to_string()).await
                }
                Err((code, msg)) => {
                    let body = serde_json::json!({ "ok": false, "error": msg });
                    write_json_response(stream, code, None, &body.to_string()).await
                }
            }
        }
        ("POST", "/api/logout") => {
            auth.logout(session_cookie.as_deref());
            let clear_cookie =
                "ddneo_admin_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0";
            write_json_response(stream, 200, Some(clear_cookie), r#"{"ok":true}"#).await
        }
        ("GET", "/api/dashboard") => {
            if auth.verify_session(session_cookie.as_deref()).is_none() {
                return write_json_response(
                    stream,
                    401,
                    None,
                    r#"{"ok":false,"error":"Nicht angemeldet."}"#,
                )
                .await;
            }
            let rx = dispatch(AdminCommand::GetDashboard);
            match tokio::time::timeout(Duration::from_secs(4), rx).await {
                Ok(Ok(Ok(rep))) => {
                    if let Ok(mut st) = auth.server_title.lock() {
                        *st = rep.state.session_name.clone();
                    }
                    let txt = serde_json::to_string(&rep.state).unwrap_or_else(|_| "{}".to_string());
                    write_json_response(stream, 200, None, &txt).await
                }
                _ => {
                    write_json_response(
                        stream,
                        500,
                        None,
                        r#"{"ok":false,"error":"Server-Hub antwortet nicht."}"#,
                    )
                    .await
                }
            }
        }
        ("POST", "/api/action") => {
            let Some(expected_csrf) = auth.verify_session(session_cookie.as_deref()) else {
                return write_json_response(
                    stream,
                    401,
                    None,
                    r#"{"ok":false,"error":"Sitzung abgelaufen — bitte neu anmelden."}"#,
                )
                .await;
            };
            if csrf_header.as_deref().map_or(true, |h| !constant_time_str_eq(h, &expected_csrf)) {
                return write_json_response(
                    stream,
                    403,
                    None,
                    r#"{"ok":false,"error":"Ungültiges CSRF-Token."}"#,
                )
                .await;
            }
            let cmd = match serde_json::from_slice::<AdminCommand>(body_slice) {
                Ok(c) => c,
                Err(e) => {
                    let body = serde_json::json!({
                        "ok": false,
                        "error": format!("Ungültiger Admin-Befehl: {}", e)
                    });
                    return write_json_response(stream, 400, None, &body.to_string()).await;
                }
            };
            let rx = dispatch(cmd);
            match tokio::time::timeout(Duration::from_secs(6), rx).await {
                Ok(Ok(Ok(rep))) => {
                    if let Ok(mut st) = auth.server_title.lock() {
                        *st = rep.state.session_name.clone();
                    }
                    let txt = serde_json::to_string(&rep).unwrap_or_else(|_| "{}".to_string());
                    write_json_response(stream, 200, None, &txt).await
                }
                Ok(Ok(Err(err_msg))) => {
                    let body = serde_json::json!({ "ok": false, "error": err_msg });
                    write_json_response(stream, 400, None, &body.to_string()).await
                }
                _ => {
                    write_json_response(
                        stream,
                        500,
                        None,
                        r#"{"ok":false,"error":"Zeitüberschreitung bei Admin-Befehl."}"#,
                    )
                    .await
                }
            }
        }
        _ => write_json_response(stream, 404, None, r#"{"ok":false,"error":"Not found"}"#).await,
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

async fn write_json_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    set_cookie: Option<&str>,
    json_body: &str,
) -> std::io::Result<()> {
    write_raw_response(
        stream,
        status,
        "application/json; charset=utf-8",
        set_cookie,
        json_body.as_bytes(),
    )
    .await
}

async fn write_raw_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    content_type: &str,
    set_cookie: Option<&str>,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        _ => "Internal Server Error",
    };
    let cookie_hdr = set_cookie
        .map(|c| format!("Set-Cookie: {}\r\n", c))
        .unwrap_or_default();
    let headers = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Frame-Options: DENY\r\n{}Connection: close\r\n\r\n",
        status,
        reason,
        content_type,
        body.len(),
        cookie_hdr
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}
