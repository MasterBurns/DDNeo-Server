pub mod admin;

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const DEFAULT_SERVER_PORT: u16 = 27777;
pub const LAN_DISCOVERY_PORT: u16 = 27778;
pub const DEFAULT_ADMIN_HTTP_PORT: u16 = 27779;
pub const DEFAULT_EMBEDDED_MAX_PLAYERS: u8 = 4;
pub const DEFAULT_DEDICATED_MAX_PLAYERS: u8 = 12;
pub const PROTOCOL_VERSION: u32 = 8;
pub const LAN_DISCOVER_MAGIC: &[u8] = b"DDNEO_DISCOVER_V8";
pub const SERVER_CHUNK_MERC_SIZE: f64 = 1500.0;
pub const AUTH_ACTION_HELLO: &str = "HELLO";
pub const AUTH_ACTION_DELETE_CHAR: &str = "DELETE_CHARACTER";

/// Converts a 32-byte array to lowercase 64-char hex without external crate overhead.
pub fn bytes32_to_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Parses a 64-char hex string back into a 32-byte array.
pub fn hex_to_bytes32(hex: &str) -> Option<[u8; 32]> {
    let clean = hex.trim();
    if clean.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = clean.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (bytes[i * 2] as char).to_digit(16)? as u8;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16)? as u8;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

pub fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1)
}

pub fn pubkey_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

/// Derives a canonical non-zero 64-bit `player_uid` from an Ed25519 public key.
pub fn derive_uid_from_pubkey(pubkey: &[u8; 32]) -> u64 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"DDNEO_UID_V1:");
    hasher.update(pubkey);
    let digest = hasher.finalize();
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(raw) | 1
}

/// Human-readable short fingerprint (`ED25519-XXXX-XXXX-XXXX`) shown in the Character Manager UI.
pub fn format_pubkey_fingerprint(pubkey: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"DDNEO_FP_V1:");
    hasher.update(pubkey);
    let d = hasher.finalize();
    format!(
        "ED25519-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}",
        d[0], d[1], d[2], d[3], d[4], d[5]
    )
}

fn build_auth_digest(
    action: &str,
    player_uid: u64,
    timestamp_ms: u64,
    pubkey: &[u8; 32],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"DDNEO_AUTH_V7:");
    hasher.update(action.as_bytes());
    hasher.update([0u8]);
    hasher.update(player_uid.to_le_bytes());
    hasher.update(timestamp_ms.to_le_bytes());
    hasher.update(pubkey);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Signs a server action (`HELLO` or `DELETE_CHARACTER`) with the player's 32-byte Ed25519 seed.
/// Returns `(pubkey, sig_r, sig_s)`.
pub fn sign_auth_action(
    seed: &[u8; 32],
    action: &str,
    player_uid: u64,
    timestamp_ms: u64,
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    use ed25519_dalek::{Signer, SigningKey};
    let sk = SigningKey::from_bytes(seed);
    let pk = sk.verifying_key().to_bytes();
    let digest = build_auth_digest(action, player_uid, timestamp_ms, &pk);
    let sig_bytes = sk.sign(&digest).to_bytes();
    let mut sig_r = [0u8; 32];
    let mut sig_s = [0u8; 32];
    sig_r.copy_from_slice(&sig_bytes[..32]);
    sig_s.copy_from_slice(&sig_bytes[32..]);
    (pk, sig_r, sig_s)
}

/// Verifies an Ed25519 signature over `(action, player_uid, timestamp_ms, pubkey)`.
pub fn verify_auth_action(
    pubkey: &[u8; 32],
    action: &str,
    player_uid: u64,
    timestamp_ms: u64,
    sig_r: &[u8; 32],
    sig_s: &[u8; 32],
) -> Result<(), String> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    if *pubkey == [0u8; 32] || timestamp_ms == 0 {
        return Err("Fehlende Spielersignatur (ungültiger öffentlicher Schlüssel).".to_string());
    }
    let now_ms = current_unix_ms();
    if now_ms.abs_diff(timestamp_ms) > 24 * 3_600 * 1_000 {
        return Err(
            "Signatur-Zeitstempel abgelaufen (bitte Systemuhr prüfen).".to_string(),
        );
    }
    let vk = VerifyingKey::from_bytes(pubkey)
        .map_err(|_| "Ungültiger Ed25519 Public-Key.".to_string())?;
    let mut sig64 = [0u8; 64];
    sig64[..32].copy_from_slice(sig_r);
    sig64[32..].copy_from_slice(sig_s);
    let sig = Signature::from_bytes(&sig64);
    let digest = build_auth_digest(action, player_uid, timestamp_ms, pubkey);
    vk.verify(&digest, &sig)
        .map_err(|_| "Ed25519-Signaturprüfung fehlgeschlagen!".to_string())
}

const EARTH_RADIUS_M: f64 = 6_378_137.0;
const LOCAL_INTEREST_RADIUS_M: f64 = 1_850.0;

#[inline]
pub fn merc_to_lat_lon_deg(mx: f64, my: f64) -> (f64, f64) {
    let lon = (mx / EARTH_RADIUS_M).to_degrees();
    let lat = (2.0 * (my / EARTH_RADIUS_M).exp().atan() - std::f64::consts::FRAC_PI_2).to_degrees();
    (lat, lon)
}

#[inline]
pub fn lat_lon_deg_to_merc(lat: f64, lon: f64) -> (f64, f64) {
    let clamped_lat = lat.clamp(-85.05112878, 85.05112878);
    let lat_rad = clamped_lat.to_radians();
    let lon_rad = lon.to_radians();
    let mx = EARTH_RADIUS_M * lon_rad;
    let my = EARTH_RADIUS_M * (std::f64::consts::FRAC_PI_4 + lat_rad * 0.5).tan().ln();
    (mx, my)
}

/// Applies the authoritative server World Tier (`0..=50`) and fine Level Offset (`-20..=200`)
/// to any deterministic Rift / Enemy base level without irreversible drift.
#[inline]
pub fn apply_world_difficulty_to_level(base_level: u32, world_tier: i32, level_offset: i32) -> u32 {
    let b = base_level.max(1);
    let tiered: i32 = if world_tier <= 0 {
        ((b + 1) / 2).max(1) as i32
    } else if world_tier == 1 {
        b as i32
    } else {
        (b as i32).saturating_add((world_tier - 1).saturating_mul(3))
    };
    tiered.saturating_add(level_offset).clamp(1, 999) as u32
}

#[inline]
pub fn compute_rift_floors_from_level(level: u32, id: u64) -> u32 {
    3 + ((id as u32) % 2) + (level / 12).min(7)
}

/// Planet-scale canonical position.
/// Overworld coordinates use `f64` Web-Mercator so players in Japan and America have zero `f32` precision loss,
/// while aligning millimeter-exact when meeting side-by-side anywhere on Earth.
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub enum NetWorldPos {
    Overworld {
        merc_x: f64,
        merc_y: f64,
    },
    BuildingInterior {
        building_id: u64,
        x: f32,
        y: f32,
    },
    Dungeon {
        seed: u64,
        floor: u32,
        max_floors: u32,
        base_level: u32,
        x: f32,
        y: f32,
    },
}

impl Default for NetWorldPos {
    fn default() -> Self {
        Self::Overworld {
            merc_x: 0.0,
            merc_y: 0.0,
        }
    }
}

impl NetWorldPos {
    pub fn gps_opt(&self) -> Option<(f64, f64)> {
        match *self {
            Self::Overworld { merc_x, merc_y } => Some(merc_to_lat_lon_deg(merc_x, merc_y)),
            _ => None,
        }
    }

    pub fn is_within_local_bubble(&self, other: &Self) -> bool {
        match (*self, *other) {
            (
                Self::Overworld {
                    merc_x: ax,
                    merc_y: ay,
                },
                Self::Overworld {
                    merc_x: bx,
                    merc_y: by,
                },
            ) => {
                let (lat, _) = merc_to_lat_lon_deg(ax, ay);
                let scale = lat.clamp(-80.0, 80.0).to_radians().cos().max(0.15);
                let dx = (ax - bx) * scale;
                let dy = (ay - by) * scale;
                (dx * dx + dy * dy).sqrt() <= LOCAL_INTEREST_RADIUS_M
            }
            (
                Self::BuildingInterior {
                    building_id: a, ..
                },
                Self::BuildingInterior {
                    building_id: b, ..
                },
            ) => a == b,
            (
                Self::Dungeon {
                    seed: sa,
                    floor: fa,
                    ..
                },
                Self::Dungeon {
                    seed: sb,
                    floor: fb,
                    ..
                },
            ) => sa == sb && fa == fb,
            _ => false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
pub enum PlayerGuildRole {
    #[default]
    Founder,
    Member,
}

impl PlayerGuildRole {
    pub fn label_de(&self) -> &'static str {
        match self {
            PlayerGuildRole::Founder => "Gründer",
            PlayerGuildRole::Member => "Koop-Mitglied",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
pub enum PlayerGuildStance {
    #[default]
    Friendly,
    Hostile,
}

impl PlayerGuildStance {
    pub fn label_de(&self) -> &'static str {
        match self {
            PlayerGuildStance::Friendly => "Freundlich (Kein PvP)",
            PlayerGuildStance::Hostile => "Feindlich / Krieg (PvP aktiv)",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetGuildPlayerMember {
    pub uid: u64,
    pub name: String,
    pub role: PlayerGuildRole,
    pub level: u32,
    pub online: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetGuildInvite {
    pub guild_id: u64,
    pub guild_name: String,
    pub inviter_name: String,
}

/// Engine-agnostic claimed base envelope persisted by the Dedicated Server and re-projected by clients.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireClaimedBase {
    pub guild_id: Option<u64>,
    pub owner_uid: u64,
    pub building_id: u64,
    pub name: String,
    pub module_count: u32,
    pub origin_merc_x: f64,
    pub origin_merc_y: f64,
    pub origin_meter_scale: f64,
    pub door_merc_x: f64,
    pub door_merc_y: f64,
    pub base_bincode: Vec<u8>,
}

/// Engine-agnostic vehicle envelope persisted by the Dedicated Server and synced at 20 Hz when driven.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireVehicle {
    pub vehicle_id: u64,
    pub label_de: String,
    pub max_passengers: u8,
    pub guild_id: Option<u64>,
    pub owner_uid: u64,
    pub merc_x: f64,
    pub merc_y: f64,
    pub heading: f32,
    pub fuel_liters: f32,
    pub battery_pct: f32,
    pub body_pct: f32,
    pub tires_pct: f32,
    pub driver_uid: Option<u64>,
    pub passengers: Vec<u64>,
    pub vehicle_bincode: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WirePlayerGuild {
    pub guild_id: u64,
    pub name: String,
    pub founder_uid: u64,
    pub founder_name: String,
    pub members: Vec<NetGuildPlayerMember>,
    pub pending_invites: Vec<u64>,
    pub stances: HashMap<u64, PlayerGuildStance>,
    pub bases: Vec<WireClaimedBase>,
    pub npc_guild_bincode: Vec<u8>,
    pub completed_research: Vec<String>,
    pub active_research_bincode: Option<Vec<u8>>,
    pub demolished_buildings: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireSharedGroundLoot {
    pub loot_id: u64,
    pub seed: u64,
    pub floor: u32,
    pub x: f32,
    pub y: f32,
    pub item_bincode: Vec<u8>,
}

/// Canonical planet-scale Overworld Rift descriptor (`f64` Web-Mercator) synchronized across
/// all connected clients so Linux/Windows players ALWAYS see the exact same Rifts & levels,
/// even if only one client has compiled the regional OSM `.pbf` data locally.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WireOverworldRift {
    pub id: u64,
    pub merc_x: f64,
    pub merc_y: f64,
    pub theme: String,
    pub color_rgba: [f32; 4],
    pub base_level: u32,
    pub level: u32,
    pub max_floors: u32,
}

/// Complete online character profile stored centrally on the Server (`saves/server_world.bin`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireServerCharacter {
    pub player_uid: u64,
    pub player_name: String,
    pub level: u32,
    pub role_id: u8,
    pub appearance_bytes: [u8; 24],
    pub last_merc_x: f64,
    pub last_merc_y: f64,
    pub character_bincode: Vec<u8>,
}

/// Lightweight pre-flight summary of a player's server-saved character so the Main Menu OSM Map
/// can show the player's exact last server location BEFORE connecting.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerCharacterSummary {
    pub player_name: String,
    pub level: u32,
    pub role_id: u8,
    pub appearance_bytes: [u8; 24],
    pub last_merc_x: f64,
    pub last_merc_y: f64,
}

/// Public summary of every registered character on this Server (online & offline) so all players
/// have a shared view of the server's hunters, levels, classes, appearances, and guilds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetCharacterDirectoryEntry {
    pub uid: u64,
    pub name: String,
    pub level: u32,
    pub role_id: u8,
    pub appearance_bytes: [u8; 24],
    pub guild_id: Option<u64>,
    pub guild_name: String,
    pub online: bool,
    pub last_merc_x: f64,
    pub last_merc_y: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetPlayerSnapshot {
    pub uid: u64,
    pub name: String,
    pub level: u32,
    pub role_id: u8,
    pub guild_id: Option<u64>,
    pub guild_name: String,
    pub guild_role: PlayerGuildRole,
    pub appearance_bytes: [u8; 24],
    pub net_pos: NetWorldPos,
    pub vel: [f32; 2],
    pub aim_dir: [f32; 2],
    pub hp: f32,
    pub max_hp: f32,
    pub driving_vehicle_id: Option<u64>,
    pub riding_vehicle_id: Option<u64>,
    pub attack_pulse: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LanBeaconReply {
    pub protocol_version: u32,
    pub session_name: String,
    pub host_name: String,
    pub tcp_port: u16,
    pub cur_players: u8,
    pub max_players: u8,
    pub has_password: bool,
    pub is_dedicated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NetClientMsg {
    ProbeServer {
        protocol_version: u32,
        player_uid: u64,
    },
    DeleteServerCharacter {
        protocol_version: u32,
        player_uid: u64,
        password: String,
        pubkey: [u8; 32],
        auth_timestamp_ms: u64,
        sig_r: [u8; 32],
        sig_s: [u8; 32],
    },
    Hello {
        protocol_version: u32,
        player_uid: u64,
        name: String,
        password: String,
        level: u32,
        role_id: u8,
        appearance_bytes: [u8; 24],
        net_pos: NetWorldPos,
        reset_character: bool,
        pubkey: [u8; 32],
        auth_timestamp_ms: u64,
        sig_r: [u8; 32],
        sig_s: [u8; 32],
    },
    FastState {
        net_pos: NetWorldPos,
        vel: [f32; 2],
        aim_dir: [f32; 2],
        hp: f32,
        max_hp: f32,
        level: u32,
        role_id: u8,
        appearance_bytes: [u8; 24],
        driving_vehicle_id: Option<u64>,
        riding_vehicle_id: Option<u64>,
        attack_pulse: u8,
        driven_vehicle: Option<WireVehicle>,
    },
    SyncCharacter(WireServerCharacter),
    FoundPlayerGuild {
        name: String,
        initial_bases: Vec<WireClaimedBase>,
        initial_vehicles: Vec<WireVehicle>,
        npc_guild_bincode: Vec<u8>,
        completed_research: Vec<String>,
        active_research_bincode: Option<Vec<u8>>,
    },
    InvitePlayerToGuild {
        target_uid: u64,
    },
    AcceptGuildInvite {
        guild_id: u64,
    },
    LeaveOrDisbandGuild,
    SetGuildStance {
        target_guild_id: u64,
        stance: PlayerGuildStance,
    },
    SyncGuildAssets {
        bases: Vec<WireClaimedBase>,
        vehicles: Vec<WireVehicle>,
        npc_guild_bincode: Vec<u8>,
        completed_research: Vec<String>,
        active_research_bincode: Option<Vec<u8>>,
    },
    RequestDemolishBuilding {
        building_id: u64,
    },
    RequestAbandonBase {
        building_id: u64,
    },
    BoardVehicle {
        vehicle_id: u64,
        want_driver: bool,
        fallback_vehicle: Option<WireVehicle>,
    },
    LeaveVehicle {
        vehicle_id: u64,
    },
    PvpDamage {
        target_uid: u64,
        raw_damage: f32,
        is_magic: bool,
    },
    EnterDungeon {
        seed: u64,
        floor: u32,
    },
    DungeonEnemyKilled {
        seed: u64,
        floor: u32,
        spawn_key: u64,
        enemy_pos: [f32; 2],
        enemy_level: u32,
        is_boss: bool,
        contested_item_blobs: Vec<Vec<u8>>,
    },
    ClaimSharedLoot {
        seed: u64,
        floor: u32,
        loot_id: u64,
    },
    PortalSealed {
        seed: u64,
        stabilized: bool,
    },
    ReportChunkRifts {
        chunk_x: i32,
        chunk_y: i32,
        from_real_osm: bool,
        rifts: Vec<WireOverworldRift>,
    },
    OverworldRiftEnemyKilled {
        portal_id: u64,
        spawn_idx: u32,
    },
    OverworldPortalCleared {
        portal_id: u64,
    },
    Chat {
        text: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NetServerMsg {
    ServerProbeReply {
        protocol_version: u32,
        server_name: String,
        cur_players: u8,
        max_players: u8,
        has_password: bool,
        is_dedicated: bool,
        existing_character: Option<ServerCharacterSummary>,
    },
    CharacterDeleteReply {
        ok: bool,
        deleted_name: String,
        message: String,
    },
    Welcome {
        server_name: String,
        max_players: u8,
        world_seed: u64,
        world_hour: f32,
        world_tier: i32,
        world_level_offset: i32,
        is_dedicated: bool,
        assigned_guild_id: Option<u64>,
        assigned_guild_role: PlayerGuildRole,
        sealed_portals: Vec<u64>,
        stabilized_portals: Vec<u64>,
        saved_character: Option<WireServerCharacter>,
    },
    Rejected {
        reason: String,
    },
    LocalBubbleTick {
        players: Vec<NetPlayerSnapshot>,
        vehicles: Vec<WireVehicle>,
    },
    WorldMacroSync {
        world_hour: f32,
        world_tier: i32,
        world_level_offset: i32,
        players: Vec<NetPlayerSnapshot>,
        character_directory: Vec<NetCharacterDirectoryEntry>,
        guilds: Vec<WirePlayerGuild>,
        all_vehicles: Vec<WireVehicle>,
    },
    AdminWorldReset {
        new_world_seed: u64,
        full_world_wipe: bool,
        reset_chunks: Vec<(i32, i32)>,
        unsealed_portals: Vec<u64>,
        restored_buildings: Vec<u64>,
        message: String,
    },
    AdminPlayerControl {
        target_merc_x: Option<f64>,
        target_merc_y: Option<f64>,
        force_overworld: bool,
        new_level: Option<u32>,
        message: String,
    },
    GuildInviteReceived(NetGuildInvite),
    GuildRoleUpdated {
        guild_id: Option<u64>,
        role: PlayerGuildRole,
        banner_msg: String,
    },
    PermissionDenied {
        reason: String,
    },
    VehicleSeatResult {
        vehicle_id: u64,
        as_driver: bool,
        as_passenger: bool,
        driver_uid: Option<u64>,
        passengers: Vec<u64>,
        message: Option<String>,
    },
    PvpHitTaken {
        attacker_uid: u64,
        attacker_name: String,
        raw_damage: f32,
        is_magic: bool,
    },
    DungeonFloorState {
        seed: u64,
        floor: u32,
        killed_keys: Vec<u64>,
        shared_loot: Vec<WireSharedGroundLoot>,
    },
    DungeonEnemyRemoved {
        seed: u64,
        floor: u32,
        spawn_key: u64,
        killer_uid: u64,
        enemy_pos: [f32; 2],
        enemy_level: u32,
        is_boss: bool,
        spawn_coop_instanced_drop: bool,
    },
    SharedLootSpawned(WireSharedGroundLoot),
    SharedLootClaimed {
        seed: u64,
        floor: u32,
        loot_id: u64,
        winner_uid: u64,
        granted_item_bincode: Option<Vec<u8>>,
    },
    PortalStateBroadcast {
        seed: u64,
        stabilized: bool,
    },
    ChunkRiftsSync {
        chunk_x: i32,
        chunk_y: i32,
        from_real_osm: bool,
        rifts: Vec<WireOverworldRift>,
        killed_enemies: Vec<(u64, Vec<u32>)>,
        dormant_portals: Vec<u64>,
    },
    OverworldRiftEnemyRemoved {
        portal_id: u64,
        spawn_idx: u32,
        killer_uid: u64,
    },
    OverworldPortalDormant {
        portal_id: u64,
    },
    BuildingDemolished {
        building_id: u64,
    },
    ChatBroadcast {
        sender: String,
        text: String,
        is_system: bool,
    },
}

// =====================================================================
// BINARY FRAMING HELPERS (4-byte little-endian length prefix + bincode)
// =====================================================================
pub async fn write_packet<T: Serialize>(
    stream: &mut tokio::net::tcp::OwnedWriteHalf,
    msg: &T,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let payload = bincode::serialize(msg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let len = payload.len() as u32;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&payload).await?;
    Ok(())
}

pub async fn read_packet<T: for<'de> Deserialize<'de>>(
    stream: &mut tokio::net::tcp::OwnedReadHalf,
) -> std::io::Result<T> {
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Frame exceeds 16 MiB safety cap",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    bincode::deserialize(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

// =====================================================================
// SERVER CONFIGURATION & ATOMIC PERSISTENCE
// =====================================================================
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind_ip")]
    pub bind_ip: String,
    #[serde(default = "default_tcp_port")]
    pub tcp_port: u16,
    #[serde(default = "default_dedicated_max")]
    pub max_players: u8,
    #[serde(default = "default_session_name")]
    pub session_name: String,
    #[serde(default = "default_host_name")]
    pub host_name: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub lan_discovery: bool,
    #[serde(default = "default_true")]
    pub is_dedicated: bool,
    #[serde(default = "default_true")]
    pub pause_when_empty: bool,
    #[serde(default = "default_save_interval")]
    pub save_interval_secs: u64,
    #[serde(default = "default_world_save_path")]
    pub world_save_path: Option<String>,
    #[serde(default = "default_status_json_path")]
    pub status_json_path: Option<String>,
    #[serde(default = "default_day_secs")]
    pub ingame_day_real_secs: f32,
    #[serde(default = "default_true")]
    pub admin_enabled: bool,
    #[serde(default = "default_bind_ip")]
    pub admin_bind_ip: String,
    #[serde(default = "default_admin_port")]
    pub admin_port: u16,
    #[serde(default = "default_admin_username")]
    pub admin_username: String,
    #[serde(default)]
    pub admin_password: String,
    #[serde(skip)]
    pub config_file_path: Option<String>,
}

fn default_bind_ip() -> String {
    "0.0.0.0".to_string()
}
fn default_tcp_port() -> u16 {
    DEFAULT_SERVER_PORT
}
fn default_admin_port() -> u16 {
    DEFAULT_ADMIN_HTTP_PORT
}
fn default_admin_username() -> String {
    "admin".to_string()
}
fn default_dedicated_max() -> u8 {
    DEFAULT_DEDICATED_MAX_PLAYERS
}
fn default_session_name() -> String {
    "DDNeo Dedicated Welt".to_string()
}
fn default_host_name() -> String {
    "Dedicated-Host".to_string()
}
fn default_true() -> bool {
    true
}
fn default_save_interval() -> u64 {
    30
}
fn default_world_save_path() -> Option<String> {
    Some("saves/server_world.bin".to_string())
}
fn default_status_json_path() -> Option<String> {
    Some("saves/server_status.json".to_string())
}
fn default_day_secs() -> f32 {
    1440.0
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_ip: default_bind_ip(),
            tcp_port: default_tcp_port(),
            max_players: default_dedicated_max(),
            session_name: default_session_name(),
            host_name: default_host_name(),
            password: String::new(),
            lan_discovery: false,
            is_dedicated: true,
            pause_when_empty: true,
            save_interval_secs: 30,
            world_save_path: default_world_save_path(),
            status_json_path: default_status_json_path(),
            ingame_day_real_secs: default_day_secs(),
            admin_enabled: false,
            admin_bind_ip: default_bind_ip(),
            admin_port: default_admin_port(),
            admin_username: default_admin_username(),
            admin_password: String::new(),
            config_file_path: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedServerWorldV2 {
    version: u32,
    world_seed: u64,
    world_hour: f32,
    next_guild_id: u64,
    next_loot_id: u64,
    characters: Vec<WireServerCharacter>,
    guilds: Vec<WirePlayerGuild>,
    vehicles: Vec<WireVehicle>,
    sealed_portals: Vec<u64>,
    stabilized_portals: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedServerWorld {
    version: u32,
    world_seed: u64,
    world_hour: f32,
    world_tier: i32,
    world_level_offset: i32,
    next_guild_id: u64,
    next_loot_id: u64,
    characters: Vec<WireServerCharacter>,
    guilds: Vec<WirePlayerGuild>,
    vehicles: Vec<WireVehicle>,
    sealed_portals: Vec<u64>,
    stabilized_portals: Vec<u64>,
}

fn deserialize_persisted_world(bytes: &[u8]) -> Result<PersistedServerWorld, String> {
    if bytes.len() >= 4 {
        let ver = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if ver == 2 {
            let v2 = bincode::deserialize::<PersistedServerWorldV2>(bytes)
                .map_err(|e| e.to_string())?;
            return Ok(PersistedServerWorld {
                version: 3,
                world_seed: v2.world_seed,
                world_hour: v2.world_hour,
                world_tier: 1,
                world_level_offset: 0,
                next_guild_id: v2.next_guild_id,
                next_loot_id: v2.next_loot_id,
                characters: v2.characters,
                guilds: v2.guilds,
                vehicles: v2.vehicles,
                sealed_portals: v2.sealed_portals,
                stabilized_portals: v2.stabilized_portals,
            });
        }
    }
    bincode::deserialize::<PersistedServerWorld>(bytes).map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct LiveServerStatusJson<'a> {
    session_name: &'a str,
    tcp_port: u16,
    online_players: usize,
    registered_characters: usize,
    max_players: u8,
    hibernating: bool,
    player_names: Vec<&'a str>,
    guild_count: usize,
    base_count: usize,
    vehicle_count: usize,
    sealed_portal_count: usize,
    world_seed: u64,
    world_hour: f32,
    uptime_secs: u64,
    last_updated_unix_secs: u64,
}

struct ConnectedPeer {
    uid: u64,
    tx: tokio::sync::mpsc::UnboundedSender<NetServerMsg>,
    kick_tx: Option<tokio::sync::oneshot::Sender<()>>,
    snap: NetPlayerSnapshot,
    awaiting_creation: bool,
    reset_on_creation: bool,
    peer_ip: String,
}

/// Inspects a persisted server world file (e.g. `saves/embedded_mp_world.bin`) without starting
/// the server so the Main Menu OSM Map can immediately display the host's last saved server position.
pub fn peek_saved_character_summary(save_path: &str, player_uid: u64) -> Option<ServerCharacterSummary> {
    let bytes = std::fs::read(save_path).ok()?;
    let saved = deserialize_persisted_world(&bytes).ok()?;
    let ch = saved.characters.into_iter().find(|c| c.player_uid == player_uid)?;
    Some(ServerCharacterSummary {
        player_name: ch.player_name,
        level: ch.level,
        role_id: ch.role_id,
        appearance_bytes: ch.appearance_bytes,
        last_merc_x: ch.last_merc_x,
        last_merc_y: ch.last_merc_y,
    })
}

/// Deletes a specific player's character (and founder guild / personal vehicles) directly inside a
/// local server world file (`saves/embedded_mp_world.bin`) when the Koop server is offline.
pub fn delete_local_character_in_world_file(
    save_path: &str,
    player_uid: u64,
) -> Result<Option<String>, String> {
    let path = Path::new(save_path);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let mut saved = deserialize_persisted_world(&bytes)?;

    let mut deleted_name = None;
    saved.characters.retain(|c| {
        if c.player_uid == player_uid {
            deleted_name = Some(c.player_name.clone());
            false
        } else {
            true
        }
    });
    if deleted_name.is_none() {
        return Ok(None);
    }

    let mut disbanded_guilds = HashSet::new();
    saved.guilds.retain_mut(|g| {
        if g.founder_uid == player_uid {
            disbanded_guilds.insert(g.guild_id);
            false
        } else {
            g.members.retain(|m| m.uid != player_uid);
            g.pending_invites.retain(|&u| u != player_uid);
            true
        }
    });
    for g in &mut saved.guilds {
        for d_gid in &disbanded_guilds {
            g.stances.remove(d_gid);
        }
    }
    saved.vehicles.retain(|v| {
        let in_disbanded = v
            .guild_id
            .map_or(false, |gid| disbanded_guilds.contains(&gid));
        let personal_owned = v.owner_uid == player_uid && v.guild_id.is_none();
        !in_disbanded && !personal_owned
    });

    let out_bytes = bincode::serialize(&saved).map_err(|e| e.to_string())?;
    let tmp_path = format!("{}.tmp", save_path);
    std::fs::write(&tmp_path, &out_bytes).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp_path, path).map_err(|e| e.to_string())?;
    Ok(deleted_name)
}

#[derive(Default)]
struct LiveDungeonInstance {
    killed_by_floor: HashMap<u32, HashSet<u64>>,
    loot_by_floor: HashMap<u32, Vec<WireSharedGroundLoot>>,
}

struct ServerWorldHub {
    config: ServerConfig,
    bound_port: u16,
    started_at: Instant,
    world_seed: u64,
    world_hour: f32,
    world_tier: i32,
    world_level_offset: i32,
    peers: HashMap<u64, ConnectedPeer>,
    characters: HashMap<u64, WireServerCharacter>,
    registered_pubkeys: HashMap<u64, [u8; 32]>,
    player_meta: HashMap<u64, admin::PlayerAdminMeta>,
    bans: Vec<admin::BanEntry>,
    next_ban_id: u64,
    recent_events: VecDeque<admin::AdminLogEntry>,
    guilds: HashMap<u64, WirePlayerGuild>,
    vehicles: HashMap<u64, WireVehicle>,
    dungeons: HashMap<u64, LiveDungeonInstance>,
    sealed_portals: HashSet<u64>,
    stabilized_portals: HashSet<u64>,
    chunk_rifts: HashMap<(i32, i32), (bool, Vec<WireOverworldRift>)>,
    overworld_rift_kills: HashMap<u64, HashSet<u32>>,
    dormant_overworld_portals: HashSet<u64>,
    next_guild_id: u64,
    next_loot_id: u64,
    dirty: bool,
    last_save_at: Instant,
}

impl ServerWorldHub {
    fn new(config: ServerConfig, bound_port: u16) -> Self {
        let mut hub = Self {
            config,
            bound_port,
            started_at: Instant::now(),
            world_seed: rand::random::<u64>() | 1,
            world_hour: 14.0,
            world_tier: 1,
            world_level_offset: 0,
            peers: HashMap::new(),
            characters: HashMap::new(),
            registered_pubkeys: HashMap::new(),
            player_meta: HashMap::new(),
            bans: Vec::new(),
            next_ban_id: 1,
            recent_events: VecDeque::new(),
            guilds: HashMap::new(),
            vehicles: HashMap::new(),
            dungeons: HashMap::new(),
            sealed_portals: HashSet::new(),
            stabilized_portals: HashSet::new(),
            chunk_rifts: HashMap::new(),
            overworld_rift_kills: HashMap::new(),
            dormant_overworld_portals: HashSet::new(),
            next_guild_id: 1,
            next_loot_id: 1,
            dirty: false,
            last_save_at: Instant::now(),
        };
        hub.load_from_disk_if_present();
        hub.log_event(format!(
            "Server '{}' gestartet auf Port {} (Seed {}, Weltstufe {}).",
            hub.config.session_name, hub.bound_port, hub.world_seed, hub.world_tier
        ));
        hub.write_status_json();
        hub
    }

    fn log_event(&mut self, text: String) {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let hh = (secs / 3600) % 24;
        let mm = (secs / 60) % 60;
        let ss = secs % 60;
        if self.recent_events.len() >= 180 {
            self.recent_events.pop_front();
        }
        self.recent_events.push_back(admin::AdminLogEntry {
            time: format!("{:02}:{:02}:{:02} UTC", hh, mm, ss),
            text,
        });
    }

    fn load_from_disk_if_present(&mut self) {
        let Some(ref path_str) = self.config.world_save_path else {
            return;
        };
        let keys_path_str = format!("{}.keys.json", path_str);
        if let Ok(keys_txt) = std::fs::read_to_string(&keys_path_str) {
            if let Ok(raw_map) = serde_json::from_str::<HashMap<u64, String>>(&keys_txt) {
                for (uid, hex_pk) in raw_map {
                    if let Some(pk) = hex_to_bytes32(&hex_pk) {
                        self.registered_pubkeys.insert(uid, pk);
                    }
                }
            }
        }
        let bans_path_str = format!("{}.bans.json", path_str);
        if let Ok(bans_txt) = std::fs::read_to_string(&bans_path_str) {
            if let Ok(list) = serde_json::from_str::<Vec<admin::BanEntry>>(&bans_txt) {
                for b in &list {
                    self.next_ban_id = self.next_ban_id.max(b.ban_id + 1);
                }
                self.bans = list;
            }
        }
        let meta_path_str = format!("{}.meta.json", path_str);
        if let Ok(meta_txt) = std::fs::read_to_string(&meta_path_str) {
            if let Ok(map) = serde_json::from_str::<HashMap<u64, admin::PlayerAdminMeta>>(&meta_txt)
            {
                self.player_meta = map;
            }
        }
        let path = Path::new(path_str);
        if !path.exists() {
            self.dirty = true;
            self.save_if_needed(true);
            return;
        }
        match std::fs::read(path) {
            Ok(bytes) => match deserialize_persisted_world(&bytes) {
                Ok(saved) => {
                    self.world_seed = if saved.world_seed == 0 {
                        rand::random::<u64>() | 1
                    } else {
                        saved.world_seed
                    };
                    self.world_hour = saved.world_hour.rem_euclid(24.0);
                    self.world_tier = saved.world_tier.clamp(0, 50);
                    self.world_level_offset = saved.world_level_offset.clamp(-20, 200);
                    self.next_guild_id = saved.next_guild_id.max(1);
                    self.next_loot_id = saved.next_loot_id.max(1);
                    for ch in saved.characters {
                        self.characters.insert(ch.player_uid, ch);
                    }
                    for mut g in saved.guilds {
                        for m in &mut g.members {
                            m.online = false;
                        }
                        self.next_guild_id = self.next_guild_id.max(g.guild_id + 1);
                        self.guilds.insert(g.guild_id, g);
                    }
                    for mut v in saved.vehicles {
                        v.driver_uid = None;
                        v.passengers.clear();
                        self.vehicles.insert(v.vehicle_id, v);
                    }
                    self.sealed_portals = saved.sealed_portals.into_iter().collect();
                    self.stabilized_portals = saved.stabilized_portals.into_iter().collect();
                    if self.config.is_dedicated {
                        println!(
                            "[DDNeo-Server] Weltstatus geladen aus '{}': {} Charaktere ({} Schlüssel, {} Sperren), {} Gilden, {} Fahrzeuge, Weltstufe {} (Seed {}).",
                            path_str,
                            self.characters.len(),
                            self.registered_pubkeys.len(),
                            self.bans.len(),
                            self.guilds.len(),
                            self.vehicles.len(),
                            self.world_tier,
                            self.world_seed
                        );
                    }
                }
                Err(e) => {
                    eprintln!(
                        "[DDNeo-Server] Warnung: Konnte '{}' nicht dekodieren ({}) — starte neue Welt.",
                        path_str, e
                    );
                }
            },
            Err(e) => {
                eprintln!(
                    "[DDNeo-Server] Warnung: Konnte '{}' nicht lesen ({}).",
                    path_str, e
                );
            }
        }
    }

    fn save_bans_and_meta(&self) {
        let Some(ref path_str) = self.config.world_save_path else {
            return;
        };
        if let Ok(bans_json) = serde_json::to_string_pretty(&self.bans) {
            let bp = format!("{}.bans.json", path_str);
            let btmp = format!("{}.bans.json.tmp", path_str);
            if std::fs::write(&btmp, bans_json).is_ok() {
                let _ = std::fs::rename(&btmp, &bp);
            }
        }
        if let Ok(meta_json) = serde_json::to_string_pretty(&self.player_meta) {
            let mp = format!("{}.meta.json", path_str);
            let mtmp = format!("{}.meta.json.tmp", path_str);
            if std::fs::write(&mtmp, meta_json).is_ok() {
                let _ = std::fs::rename(&mtmp, &mp);
            }
        }
    }

    fn save_if_needed(&mut self, force: bool) {
        let interval = Duration::from_secs(self.config.save_interval_secs.max(5));
        if !force && (!self.dirty || self.last_save_at.elapsed() < interval) {
            return;
        }
        let Some(ref path_str) = self.config.world_save_path else {
            self.dirty = false;
            return;
        };
        let path = Path::new(path_str);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let snap = PersistedServerWorld {
            version: 3,
            world_seed: self.world_seed,
            world_hour: self.world_hour,
            world_tier: self.world_tier,
            world_level_offset: self.world_level_offset,
            next_guild_id: self.next_guild_id,
            next_loot_id: self.next_loot_id,
            characters: self.characters.values().cloned().collect(),
            guilds: self.guilds.values().cloned().collect(),
            vehicles: self.vehicles.values().cloned().collect(),
            sealed_portals: self.sealed_portals.iter().copied().collect(),
            stabilized_portals: self.stabilized_portals.iter().copied().collect(),
        };
        if let Ok(bytes) = bincode::serialize(&snap) {
            let tmp_path = format!("{}.tmp", path_str);
            if std::fs::write(&tmp_path, &bytes).is_ok() {
                let _ = std::fs::rename(&tmp_path, path);
                self.dirty = false;
                self.last_save_at = Instant::now();
            }
        }
        let keys_map: HashMap<u64, String> = self
            .registered_pubkeys
            .iter()
            .map(|(&uid, pk)| (uid, bytes32_to_hex(pk)))
            .collect();
        if let Ok(keys_json) = serde_json::to_string_pretty(&keys_map) {
            let keys_path = format!("{}.keys.json", path_str);
            let keys_tmp = format!("{}.keys.json.tmp", path_str);
            if std::fs::write(&keys_tmp, keys_json).is_ok() {
                let _ = std::fs::rename(&keys_tmp, &keys_path);
            }
        }
        self.save_bans_and_meta();
        self.write_status_json();
    }

    fn verify_and_bind_uid(
        &mut self,
        player_uid: u64,
        pubkey: &[u8; 32],
        action: &str,
        auth_timestamp_ms: u64,
        sig_r: &[u8; 32],
        sig_s: &[u8; 32],
    ) -> Result<(), String> {
        verify_auth_action(
            pubkey,
            action,
            player_uid,
            auth_timestamp_ms,
            sig_r,
            sig_s,
        )?;
        if let Some(bound_pk) = self.registered_pubkeys.get(&player_uid) {
            if bound_pk != pubkey {
                return Err(
                    "Kryptografische Signatur stimmt nicht mit dem Besitzer dieser Spieler-ID überein!"
                        .to_string(),
                );
            }
        } else {
            self.registered_pubkeys.insert(player_uid, *pubkey);
            self.dirty = true;
        }
        Ok(())
    }

    fn write_status_json(&self) {
        let Some(ref st_path) = self.config.status_json_path else {
            return;
        };
        let path = Path::new(st_path);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let base_count: usize = self.guilds.values().map(|g| g.bases.len()).sum();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let status = LiveServerStatusJson {
            session_name: &self.config.session_name,
            tcp_port: self.bound_port,
            online_players: self.peers.len(),
            registered_characters: self.characters.len(),
            max_players: self.config.max_players,
            hibernating: self.peers.is_empty() && self.config.pause_when_empty,
            player_names: self.peers.values().map(|p| p.snap.name.as_str()).collect(),
            guild_count: self.guilds.len(),
            base_count,
            vehicle_count: self.vehicles.len(),
            sealed_portal_count: self.sealed_portals.len(),
            world_seed: self.world_seed,
            world_hour: self.world_hour,
            uptime_secs: self.started_at.elapsed().as_secs(),
            last_updated_unix_secs: now_unix,
        };
        if let Ok(txt) = serde_json::to_string_pretty(&status) {
            let tmp = format!("{}.tmp", st_path);
            if std::fs::write(&tmp, txt).is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
        }
    }

    fn find_player_guild(&self, uid: u64) -> Option<(u64, PlayerGuildRole, String)> {
        for g in self.guilds.values() {
            if let Some(m) = g.members.iter().find(|m| m.uid == uid) {
                return Some((g.guild_id, m.role, g.name.clone()));
            }
        }
        None
    }

    fn are_guilds_at_war(&self, ga: Option<u64>, gb: Option<u64>) -> bool {
        let (Some(a), Some(b)) = (ga, gb) else {
            return false;
        };
        if a == b {
            return false;
        }
        let a_war = self
            .guilds
            .get(&a)
            .and_then(|g| g.stances.get(&b))
            .copied()
            == Some(PlayerGuildStance::Hostile);
        let b_war = self
            .guilds
            .get(&b)
            .and_then(|g| g.stances.get(&a))
            .copied()
            == Some(PlayerGuildStance::Hostile);
        a_war || b_war
    }

    fn broadcast_all(&self, msg: &NetServerMsg) {
        for p in self.peers.values() {
            let _ = p.tx.send(msg.clone());
        }
    }

    fn release_player_vehicle_seats(&mut self, uid: u64) {
        for nv in self.vehicles.values_mut() {
            if nv.driver_uid == Some(uid) {
                nv.driver_uid = None;
                self.dirty = true;
            }
            let before = nv.passengers.len();
            nv.passengers.retain(|&p| p != uid);
            if nv.passengers.len() != before {
                self.dirty = true;
            }
        }
    }

    fn purge_character_for_reset(&mut self, uid: u64) {
        self.release_player_vehicle_seats(uid);
        self.characters.remove(&uid);

        if let Some((gid, role, gname)) = self.find_player_guild(uid) {
            if role == PlayerGuildRole::Founder {
                let member_uids: Vec<u64> = self
                    .guilds
                    .get(&gid)
                    .map(|g| g.members.iter().map(|m| m.uid).collect())
                    .unwrap_or_default();
                self.guilds.remove(&gid);
                self.vehicles.retain(|_, v| v.guild_id != Some(gid));
                for og in self.guilds.values_mut() {
                    og.stances.remove(&gid);
                }
                for m_uid in member_uids {
                    if m_uid == uid {
                        continue;
                    }
                    if let Some(p) = self.peers.get_mut(&m_uid) {
                        p.snap.guild_id = None;
                        p.snap.guild_name.clear();
                        p.snap.guild_role = PlayerGuildRole::Founder;
                        let _ = p.tx.send(NetServerMsg::GuildRoleUpdated {
                            guild_id: None,
                            role: PlayerGuildRole::Founder,
                            banner_msg: format!(
                                "Die Gilde '{}' wurde durch Charakter-Neustart des Gründers aufgelöst.",
                                gname
                            ),
                        });
                    }
                }
                self.broadcast_all(&NetServerMsg::ChatBroadcast {
                    sender: "Server".to_string(),
                    text: format!(
                        "Die Gilde '{}' wurde durch Charakter-Neustart des Gründers aufgelöst.",
                        gname
                    ),
                    is_system: true,
                });
            } else if let Some(g) = self.guilds.get_mut(&gid) {
                g.members.retain(|m| m.uid != uid);
            }
        }

        self.vehicles
            .retain(|_, v| !(v.owner_uid == uid && v.guild_id.is_none()));
        for g in self.guilds.values_mut() {
            g.pending_invites.retain(|&u| u != uid);
        }
        if let Some(p) = self.peers.get_mut(&uid) {
            p.snap.guild_id = None;
            p.snap.guild_name.clear();
            p.snap.guild_role = PlayerGuildRole::Founder;
        }
        self.dirty = true;
    }

    fn handle_disconnect(&mut self, uid: u64) {
        self.release_player_vehicle_seats(uid);
        if let Some(peer) = self.peers.remove(&uid) {
            if peer.awaiting_creation {
                return;
            }
            for g in self.guilds.values_mut() {
                for m in &mut g.members {
                    if m.uid == uid {
                        m.online = false;
                    }
                }
            }
            if self.config.is_dedicated {
                println!(
                    "[DDNeo-Server] Spieler getrennt: '{}' ({}/{} online)",
                    peer.snap.name,
                    self.peers.values().filter(|p| !p.awaiting_creation).count(),
                    self.config.max_players
                );
            }
            self.broadcast_all(&NetServerMsg::ChatBroadcast {
                sender: "Server".to_string(),
                text: format!("{} hat die Sitzung verlassen.", peer.snap.name),
                is_system: true,
            });
            self.publish_macro_sync();
            self.save_if_needed(true);
        }
    }

    fn handle_msg(&mut self, uid: u64, msg: NetClientMsg) {
        match msg {
            NetClientMsg::ProbeServer { .. }
            | NetClientMsg::DeleteServerCharacter { .. }
            | NetClientMsg::Hello { .. } => {}
            NetClientMsg::FastState {
                net_pos,
                vel,
                aim_dir,
                hp,
                max_hp,
                level,
                role_id,
                appearance_bytes,
                driving_vehicle_id,
                riding_vehicle_id,
                attack_pulse,
                driven_vehicle,
            } => {
                let ginfo = self.find_player_guild(uid);
                if let Some(peer) = self.peers.get_mut(&uid) {
                    peer.snap.net_pos = net_pos;
                    peer.snap.vel = vel;
                    peer.snap.aim_dir = aim_dir;
                    peer.snap.hp = hp;
                    peer.snap.max_hp = max_hp;
                    peer.snap.level = level;
                    peer.snap.role_id = role_id;
                    peer.snap.appearance_bytes = appearance_bytes;
                    peer.snap.driving_vehicle_id = driving_vehicle_id;
                    peer.snap.riding_vehicle_id = riding_vehicle_id;
                    peer.snap.attack_pulse = attack_pulse;
                    if let Some((gid, grole, gname)) = &ginfo {
                        peer.snap.guild_id = Some(*gid);
                        peer.snap.guild_role = *grole;
                        peer.snap.guild_name = gname.clone();
                    } else {
                        peer.snap.guild_id = None;
                        peer.snap.guild_role = PlayerGuildRole::Founder;
                        peer.snap.guild_name.clear();
                    }
                }
                if let Some((gid, _, _)) = ginfo {
                    if let Some(g) = self.guilds.get_mut(&gid) {
                        if let Some(m) = g.members.iter_mut().find(|m| m.uid == uid) {
                            if m.level != level {
                                m.level = level;
                                self.dirty = true;
                            }
                            m.online = true;
                        }
                    }
                }
                if let Some(mut dv) = driven_vehicle {
                    let vid = dv.vehicle_id;
                    let allow = self
                        .vehicles
                        .get(&vid)
                        .map_or(true, |cur| cur.driver_uid.is_none() || cur.driver_uid == Some(uid));
                    if allow {
                        if let Some(existing) = self.vehicles.get(&vid) {
                            dv.passengers = existing.passengers.clone();
                        }
                        dv.driver_uid = Some(uid);
                        self.vehicles.insert(vid, dv);
                        self.dirty = true;
                    }
                }
                if let NetWorldPos::Overworld { merc_x, merc_y } = net_pos {
                    if let Some(ch) = self.characters.get_mut(&uid) {
                        ch.last_merc_x = merc_x;
                        ch.last_merc_y = merc_y;
                        ch.level = level;
                        ch.role_id = role_id;
                        ch.appearance_bytes = appearance_bytes;
                    }
                }
            }
            NetClientMsg::SyncCharacter(mut ch) => {
                let clean_name = ch.player_name.trim().to_string();
                if clean_name.is_empty() {
                    return;
                }
                ch.player_name = clean_name.clone();
                ch.player_uid = uid;
                let should_reset_old = self
                    .peers
                    .get_mut(&uid)
                    .map(|p| {
                        let r = p.reset_on_creation;
                        p.reset_on_creation = false;
                        r
                    })
                    .unwrap_or(false);
                if should_reset_old {
                    self.purge_character_for_reset(uid);
                }
                let is_brand_new = !self.characters.contains_key(&uid);
                let directory_changed = self
                    .characters
                    .get(&uid)
                    .map_or(true, |prev| {
                        prev.level != ch.level
                            || prev.player_name != ch.player_name
                            || prev.role_id != ch.role_id
                    });
                let mut completed_creation = false;
                if let Some(peer) = self.peers.get_mut(&uid) {
                    if peer.awaiting_creation {
                        peer.awaiting_creation = false;
                        peer.snap.net_pos = NetWorldPos::Overworld {
                            merc_x: ch.last_merc_x,
                            merc_y: ch.last_merc_y,
                        };
                        completed_creation = true;
                    }
                    peer.snap.name = ch.player_name.clone();
                    peer.snap.level = ch.level;
                    peer.snap.role_id = ch.role_id;
                    peer.snap.appearance_bytes = ch.appearance_bytes;
                }
                if let Some((gid, _, _)) = self.find_player_guild(uid) {
                    if let Some(g) = self.guilds.get_mut(&gid) {
                        if let Some(m) = g.members.iter_mut().find(|m| m.uid == uid) {
                            m.name = ch.player_name.clone();
                            m.level = ch.level;
                        }
                    }
                }
                self.characters.insert(uid, ch);
                self.dirty = true;
                if completed_creation {
                    if self.config.is_dedicated {
                        println!(
                            "[DDNeo-Server] Neuer Charakter erstellt & verbunden: '{}' (UID {}, {}/{} online)",
                            clean_name,
                            uid,
                            self.peers.values().filter(|p| !p.awaiting_creation).count(),
                            self.config.max_players
                        );
                    }
                    self.broadcast_all(&NetServerMsg::ChatBroadcast {
                        sender: "Server".to_string(),
                        text: format!("{} ist der Welt beigetreten!", clean_name),
                        is_system: true,
                    });
                }
                if is_brand_new || completed_creation {
                    self.save_if_needed(true);
                }
                if directory_changed || completed_creation {
                    self.publish_macro_sync();
                }
            }
            NetClientMsg::FoundPlayerGuild {
                name,
                mut initial_bases,
                initial_vehicles,
                npc_guild_bincode,
                completed_research,
                active_research_bincode,
            } => {
                if self.find_player_guild(uid).is_some() {
                    return;
                }
                let Some(peer) = self.peers.get(&uid) else {
                    return;
                };
                let gid = self.next_guild_id;
                self.next_guild_id += 1;
                let clean_name = if name.trim().is_empty() {
                    format!("Gilde von {}", peer.snap.name)
                } else {
                    name.trim().to_string()
                };
                for b in &mut initial_bases {
                    b.guild_id = Some(gid);
                }
                for mut v in initial_vehicles {
                    v.guild_id = Some(gid);
                    self.vehicles.entry(v.vehicle_id).or_insert(v);
                }
                let founder_name = peer.snap.name.clone();
                let founder_lvl = peer.snap.level;
                let guild = WirePlayerGuild {
                    guild_id: gid,
                    name: clean_name.clone(),
                    founder_uid: uid,
                    founder_name: founder_name.clone(),
                    members: vec![NetGuildPlayerMember {
                        uid,
                        name: founder_name,
                        role: PlayerGuildRole::Founder,
                        level: founder_lvl,
                        online: true,
                    }],
                    pending_invites: Vec::new(),
                    stances: HashMap::new(),
                    bases: initial_bases,
                    npc_guild_bincode,
                    completed_research,
                    active_research_bincode,
                    demolished_buildings: Vec::new(),
                };
                self.guilds.insert(gid, guild);
                self.dirty = true;
                if let Some(p) = self.peers.get_mut(&uid) {
                    p.snap.guild_id = Some(gid);
                    p.snap.guild_name = clean_name.clone();
                    p.snap.guild_role = PlayerGuildRole::Founder;
                    let _ = p.tx.send(NetServerMsg::GuildRoleUpdated {
                        guild_id: Some(gid),
                        role: PlayerGuildRole::Founder,
                        banner_msg: format!("Spieler-Gilde '{}' gegründet!", clean_name),
                    });
                }
                self.publish_macro_sync();
            }
            NetClientMsg::InvitePlayerToGuild { target_uid } => {
                let Some((gid, _, gname)) = self.find_player_guild(uid) else {
                    return;
                };
                let inviter_name = self
                    .peers
                    .get(&uid)
                    .map(|p| p.snap.name.clone())
                    .unwrap_or_else(|| "Gildenleiter".to_string());
                if let Some(g) = self.guilds.get_mut(&gid) {
                    if !g.pending_invites.contains(&target_uid) {
                        g.pending_invites.push(target_uid);
                        self.dirty = true;
                    }
                }
                if let Some(target_peer) = self.peers.get(&target_uid) {
                    let _ = target_peer.tx.send(NetServerMsg::GuildInviteReceived(
                        NetGuildInvite {
                            guild_id: gid,
                            guild_name: gname,
                            inviter_name,
                        },
                    ));
                }
            }
            NetClientMsg::AcceptGuildInvite { guild_id } => {
                let Some(peer) = self.peers.get(&uid) else {
                    return;
                };
                let pname = peer.snap.name.clone();
                let plvl = peer.snap.level;

                if let Some((old_gid, old_role, _)) = self.find_player_guild(uid) {
                    if old_gid == guild_id {
                        return;
                    }
                    if old_role == PlayerGuildRole::Founder {
                        self.guilds.remove(&old_gid);
                    } else if let Some(og) = self.guilds.get_mut(&old_gid) {
                        og.members.retain(|m| m.uid != uid);
                    }
                }

                let mut joined_name = None;
                if let Some(g) = self.guilds.get_mut(&guild_id) {
                    g.pending_invites.retain(|&u| u != uid);
                    if !g.members.iter().any(|m| m.uid == uid) {
                        g.members.push(NetGuildPlayerMember {
                            uid,
                            name: pname.clone(),
                            role: PlayerGuildRole::Member,
                            level: plvl,
                            online: true,
                        });
                    }
                    joined_name = Some(g.name.clone());
                }

                if let Some(gname) = joined_name {
                    self.dirty = true;
                    if let Some(p) = self.peers.get_mut(&uid) {
                        p.snap.guild_id = Some(guild_id);
                        p.snap.guild_name = gname.clone();
                        p.snap.guild_role = PlayerGuildRole::Member;
                        let _ = p.tx.send(NetServerMsg::GuildRoleUpdated {
                            guild_id: Some(guild_id),
                            role: PlayerGuildRole::Member,
                            banner_msg: format!(
                                "Koop-Gilde '{}' beigetreten! Außenposten & Bauwerke freigeschaltet.",
                                gname
                            ),
                        });
                    }
                    self.broadcast_all(&NetServerMsg::ChatBroadcast {
                        sender: "Gilde".to_string(),
                        text: format!("{} ist der Gilde '{}' beigetreten!", pname, gname),
                        is_system: true,
                    });
                    self.publish_macro_sync();
                }
            }
            NetClientMsg::LeaveOrDisbandGuild => {
                let Some((gid, role, gname)) = self.find_player_guild(uid) else {
                    return;
                };
                self.dirty = true;
                if role == PlayerGuildRole::Founder {
                    let member_uids: Vec<u64> = self
                        .guilds
                        .get(&gid)
                        .map(|g| g.members.iter().map(|m| m.uid).collect())
                        .unwrap_or_default();
                    self.guilds.remove(&gid);
                    for m_uid in member_uids {
                        if let Some(p) = self.peers.get_mut(&m_uid) {
                            p.snap.guild_id = None;
                            p.snap.guild_name.clear();
                            p.snap.guild_role = PlayerGuildRole::Founder;
                            let _ = p.tx.send(NetServerMsg::GuildRoleUpdated {
                                guild_id: None,
                                role: PlayerGuildRole::Founder,
                                banner_msg: format!(
                                    "Die Gilde '{}' wurde vom Gründer aufgelöst.",
                                    gname
                                ),
                            });
                        }
                    }
                } else {
                    if let Some(g) = self.guilds.get_mut(&gid) {
                        g.members.retain(|m| m.uid != uid);
                    }
                    if let Some(p) = self.peers.get_mut(&uid) {
                        p.snap.guild_id = None;
                        p.snap.guild_name.clear();
                        p.snap.guild_role = PlayerGuildRole::Founder;
                        let _ = p.tx.send(NetServerMsg::GuildRoleUpdated {
                            guild_id: None,
                            role: PlayerGuildRole::Founder,
                            banner_msg: format!("Du hast die Gilde '{}' verlassen.", gname),
                        });
                    }
                }
                self.publish_macro_sync();
            }
            NetClientMsg::SetGuildStance {
                target_guild_id,
                stance,
            } => {
                let Some((gid, role, my_gname)) = self.find_player_guild(uid) else {
                    return;
                };
                if gid == target_guild_id {
                    return;
                }
                if role != PlayerGuildRole::Founder {
                    if let Some(p) = self.peers.get(&uid) {
                        let _ = p.tx.send(NetServerMsg::PermissionDenied {
                            reason: "Nur der Gildengründer kann Krieg erklären oder Frieden schließen!"
                                .to_string(),
                        });
                    }
                    return;
                }
                let target_name = self
                    .guilds
                    .get(&target_guild_id)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| "Unbekannte Gilde".to_string());
                if let Some(g) = self.guilds.get_mut(&gid) {
                    g.stances.insert(target_guild_id, stance);
                    self.dirty = true;
                }
                let text = match stance {
                    PlayerGuildStance::Hostile => format!(
                        "KRIEGSERKLÄRUNG: '{}' hat '{}' als FEINDLICH eingestuft — PvP & umkämpfte Dungeon-Beute aktiv!",
                        my_gname, target_name
                    ),
                    PlayerGuildStance::Friendly => format!(
                        "Diplomatie: '{}' stuft '{}' auf FREUNDLICH ein.",
                        my_gname, target_name
                    ),
                };
                self.broadcast_all(&NetServerMsg::ChatBroadcast {
                    sender: "Diplomatie".to_string(),
                    text,
                    is_system: true,
                });
                self.publish_macro_sync();
            }
            NetClientMsg::SyncGuildAssets {
                mut bases,
                vehicles,
                npc_guild_bincode,
                completed_research,
                active_research_bincode,
            } => {
                let Some((gid, role, _)) = self.find_player_guild(uid) else {
                    for v in vehicles {
                        let vid = v.vehicle_id;
                        if !self.vehicles.contains_key(&vid)
                            || self.vehicles[&vid].driver_uid.is_none()
                        {
                            self.vehicles.insert(vid, v);
                            self.dirty = true;
                        }
                    }
                    return;
                };
                if let Some(g) = self.guilds.get_mut(&gid) {
                    for b in &mut bases {
                        b.guild_id = Some(gid);
                    }
                    if role == PlayerGuildRole::Founder {
                        g.bases = bases;
                    } else {
                        // Co-op Member rule: CAN add outposts, annexes, stash items & modules;
                        // CANNOT delete/abandon existing bases or shrink built station count!
                        for nb in bases {
                            if let Some(existing) = g
                                .bases
                                .iter_mut()
                                .find(|eb| eb.building_id == nb.building_id)
                            {
                                if nb.module_count >= existing.module_count {
                                    *existing = nb;
                                }
                            } else {
                                g.bases.push(nb);
                            }
                        }
                    }
                    g.npc_guild_bincode = npc_guild_bincode;
                    for tech in completed_research {
                        if !g.completed_research.contains(&tech) {
                            g.completed_research.push(tech);
                        }
                    }
                    g.active_research_bincode = active_research_bincode;
                    self.dirty = true;
                }
                for mut v in vehicles {
                    v.guild_id = Some(gid);
                    let vid = v.vehicle_id;
                    if let Some(cur) = self.vehicles.get(&vid) {
                        v.driver_uid = cur.driver_uid;
                        v.passengers = cur.passengers.clone();
                        if cur.driver_uid.is_some() && cur.driver_uid != Some(uid) {
                            continue;
                        }
                    }
                    self.vehicles.insert(vid, v);
                    self.dirty = true;
                }
                self.publish_macro_sync();
            }
            NetClientMsg::RequestDemolishBuilding { building_id } => {
                if let Some((gid, role, _)) = self.find_player_guild(uid) {
                    if role != PlayerGuildRole::Founder {
                        if let Some(p) = self.peers.get(&uid) {
                            let _ = p.tx.send(NetServerMsg::PermissionDenied {
                                reason: "Nur der Gildengründer darf Gebäude abreißen!".to_string(),
                            });
                        }
                        return;
                    }
                    if let Some(g) = self.guilds.get_mut(&gid) {
                        if !g.demolished_buildings.contains(&building_id) {
                            g.demolished_buildings.push(building_id);
                            self.dirty = true;
                        }
                    }
                }
                self.broadcast_all(&NetServerMsg::BuildingDemolished { building_id });
            }
            NetClientMsg::RequestAbandonBase { building_id } => {
                if let Some((gid, role, _)) = self.find_player_guild(uid) {
                    if role != PlayerGuildRole::Founder {
                        if let Some(p) = self.peers.get(&uid) {
                            let _ = p.tx.send(NetServerMsg::PermissionDenied {
                                reason: "Nur der Gildengründer darf Stützpunkte aufgeben!"
                                    .to_string(),
                            });
                        }
                        return;
                    }
                    if let Some(g) = self.guilds.get_mut(&gid) {
                        g.bases.retain(|b| b.building_id != building_id);
                        self.dirty = true;
                    }
                    self.publish_macro_sync();
                }
            }
            NetClientMsg::BoardVehicle {
                vehicle_id,
                want_driver,
                fallback_vehicle,
            } => {
                self.release_player_vehicle_seats(uid);
                if !self.vehicles.contains_key(&vehicle_id) {
                    if let Some(fv) = fallback_vehicle {
                        self.vehicles.insert(vehicle_id, fv);
                        self.dirty = true;
                    }
                }
                let mut reply = NetServerMsg::VehicleSeatResult {
                    vehicle_id,
                    as_driver: false,
                    as_passenger: false,
                    driver_uid: None,
                    passengers: Vec::new(),
                    message: Some("Fahrzeug nicht verfügbar.".to_string()),
                };
                if let Some(nv) = self.vehicles.get_mut(&vehicle_id) {
                    let max_pass = nv.max_passengers as usize;
                    if want_driver && nv.driver_uid.is_none() {
                        nv.driver_uid = Some(uid);
                        self.dirty = true;
                        reply = NetServerMsg::VehicleSeatResult {
                            vehicle_id,
                            as_driver: true,
                            as_passenger: false,
                            driver_uid: nv.driver_uid,
                            passengers: nv.passengers.clone(),
                            message: None,
                        };
                    } else if nv.passengers.len() < max_pass {
                        nv.passengers.push(uid);
                        self.dirty = true;
                        reply = NetServerMsg::VehicleSeatResult {
                            vehicle_id,
                            as_driver: false,
                            as_passenger: true,
                            driver_uid: nv.driver_uid,
                            passengers: nv.passengers.clone(),
                            message: Some(format!(
                                "Als Beifahrer eingestiegen (Platz {}/{}).",
                                nv.passengers.len(),
                                max_pass
                            )),
                        };
                    } else {
                        reply = NetServerMsg::VehicleSeatResult {
                            vehicle_id,
                            as_driver: false,
                            as_passenger: false,
                            driver_uid: nv.driver_uid,
                            passengers: nv.passengers.clone(),
                            message: Some(if max_pass == 0 {
                                format!("{} hat keine Beifahrerplätze!", nv.label_de)
                            } else {
                                format!("Alle {} Beifahrerplätze belegt!", max_pass)
                            }),
                        };
                    }
                }
                if let Some(p) = self.peers.get(&uid) {
                    let _ = p.tx.send(reply);
                }
            }
            NetClientMsg::LeaveVehicle { vehicle_id } => {
                self.release_player_vehicle_seats(uid);
                let (d_uid, pass) = self
                    .vehicles
                    .get(&vehicle_id)
                    .map(|nv| (nv.driver_uid, nv.passengers.clone()))
                    .unwrap_or((None, Vec::new()));
                if let Some(p) = self.peers.get(&uid) {
                    let _ = p.tx.send(NetServerMsg::VehicleSeatResult {
                        vehicle_id,
                        as_driver: false,
                        as_passenger: false,
                        driver_uid: d_uid,
                        passengers: pass,
                        message: None,
                    });
                }
            }
            NetClientMsg::PvpDamage {
                target_uid,
                raw_damage,
                is_magic,
            } => {
                if uid == target_uid || raw_damage <= 0.0 {
                    return;
                }
                let att_gid = self.find_player_guild(uid).map(|(g, _, _)| g);
                let tgt_gid = self.find_player_guild(target_uid).map(|(g, _, _)| g);
                if !self.are_guilds_at_war(att_gid, tgt_gid) {
                    return;
                }
                let (Some(att), Some(tgt)) = (self.peers.get(&uid), self.peers.get(&target_uid))
                else {
                    return;
                };
                let _ = tgt.tx.send(NetServerMsg::PvpHitTaken {
                    attacker_uid: uid,
                    attacker_name: att.snap.name.clone(),
                    raw_damage,
                    is_magic,
                });
            }
            NetClientMsg::EnterDungeon { seed, floor } => {
                let inst = self.dungeons.entry(seed).or_default();
                let killed: Vec<u64> = inst
                    .killed_by_floor
                    .get(&floor)
                    .map(|s| s.iter().copied().collect())
                    .unwrap_or_default();
                let shared_loot = inst
                    .loot_by_floor
                    .get(&floor)
                    .cloned()
                    .unwrap_or_default();
                if let Some(p) = self.peers.get(&uid) {
                    let _ = p.tx.send(NetServerMsg::DungeonFloorState {
                        seed,
                        floor,
                        killed_keys: killed,
                        shared_loot,
                    });
                }
            }
            NetClientMsg::DungeonEnemyKilled {
                seed,
                floor,
                spawn_key,
                enemy_pos,
                enemy_level,
                is_boss,
                contested_item_blobs,
            } => {
                {
                    let inst = self.dungeons.entry(seed).or_default();
                    let killed_set = inst.killed_by_floor.entry(floor).or_default();
                    if spawn_key != 0 && !killed_set.insert(spawn_key) {
                        return;
                    }
                }

                let killer_guild = self.find_player_guild(uid).map(|(g, _, _)| g);
                let mut contested_war = false;
                for other in self.peers.values() {
                    if other.uid != uid {
                        if let NetWorldPos::Dungeon { seed: o_seed, .. } = other.snap.net_pos {
                            let other_guild = self.find_player_guild(other.uid).map(|(g, _, _)| g);
                            if o_seed == seed && self.are_guilds_at_war(killer_guild, other_guild) {
                                contested_war = true;
                                break;
                            }
                        }
                    }
                }

                let spawn_coop_instanced = !contested_war && contested_item_blobs.is_empty();
                let mut spawned_shared = Vec::new();
                if contested_war || !contested_item_blobs.is_empty() {
                    let inst = self.dungeons.entry(seed).or_default();
                    let floor_loot = inst.loot_by_floor.entry(floor).or_default();
                    for (idx, item_bincode) in contested_item_blobs.into_iter().enumerate() {
                        let lid = self.next_loot_id;
                        self.next_loot_id += 1;
                        let angle = (idx as f32) * 1.6;
                        let sl = WireSharedGroundLoot {
                            loot_id: lid,
                            seed,
                            floor,
                            x: enemy_pos[0] + angle.cos() * 0.55,
                            y: enemy_pos[1] + angle.sin() * 0.55,
                            item_bincode,
                        };
                        floor_loot.push(sl.clone());
                        spawned_shared.push(sl);
                    }
                }

                for peer in self.peers.values() {
                    if let NetWorldPos::Dungeon {
                        seed: p_seed,
                        floor: p_floor,
                        ..
                    } = peer.snap.net_pos
                    {
                        if p_seed == seed && p_floor == floor {
                            let peer_gid = self.find_player_guild(peer.uid).map(|(g, _, _)| g);
                            let _ = peer.tx.send(NetServerMsg::DungeonEnemyRemoved {
                                seed,
                                floor,
                                spawn_key,
                                killer_uid: uid,
                                enemy_pos,
                                enemy_level,
                                is_boss,
                                spawn_coop_instanced_drop: spawn_coop_instanced
                                    && peer.uid != uid
                                    && !self.are_guilds_at_war(killer_guild, peer_gid),
                            });
                            for sl in &spawned_shared {
                                let _ = peer.tx.send(NetServerMsg::SharedLootSpawned(sl.clone()));
                            }
                        }
                    }
                }
            }
            NetClientMsg::ClaimSharedLoot {
                seed,
                floor,
                loot_id,
            } => {
                let mut claimed_blob = None;
                if let Some(inst) = self.dungeons.get_mut(&seed) {
                    if let Some(list) = inst.loot_by_floor.get_mut(&floor) {
                        if let Some(pos) = list.iter().position(|l| l.loot_id == loot_id) {
                            claimed_blob = Some(list.remove(pos).item_bincode);
                        }
                    }
                }
                if let Some(blob) = claimed_blob {
                    for peer in self.peers.values() {
                        let granted = if peer.uid == uid {
                            Some(blob.clone())
                        } else {
                            None
                        };
                        let _ = peer.tx.send(NetServerMsg::SharedLootClaimed {
                            seed,
                            floor,
                            loot_id,
                            winner_uid: uid,
                            granted_item_bincode: granted,
                        });
                    }
                }
            }
            NetClientMsg::PortalSealed { seed, stabilized } => {
                if stabilized {
                    self.completed_portal_remove_and_stabilize(seed);
                } else {
                    self.stabilized_portals.remove(&seed);
                    self.sealed_portals.insert(seed);
                    self.dungeons.remove(&seed);
                }
                self.overworld_rift_kills.remove(&seed);
                self.dormant_overworld_portals.remove(&seed);
                self.dirty = true;
                self.broadcast_all(&NetServerMsg::PortalStateBroadcast { seed, stabilized });
            }
            NetClientMsg::ReportChunkRifts {
                chunk_x,
                chunk_y,
                from_real_osm,
                mut rifts,
            } => {
                if rifts.len() > 8 {
                    rifts.truncate(8);
                }
                for r in &mut rifts {
                    if r.base_level == 0 {
                        r.base_level = r.level.max(1);
                    }
                    r.level = apply_world_difficulty_to_level(
                        r.base_level,
                        self.world_tier,
                        self.world_level_offset,
                    );
                    r.max_floors = compute_rift_floors_from_level(r.level, r.id);
                }
                let key = (chunk_x, chunk_y);
                let should_adopt = match self.chunk_rifts.get(&key) {
                    None => true,
                    Some((existing_osm, _)) => !*existing_osm && from_real_osm,
                };
                if should_adopt {
                    if self.chunk_rifts.len() >= 4096 && !self.chunk_rifts.contains_key(&key) {
                        if let Some(&evict_k) =
                            self.chunk_rifts.iter().find(|(_, (osm, _))| !*osm).map(|(k, _)| k)
                        {
                            self.chunk_rifts.remove(&evict_k);
                        }
                    }
                    self.chunk_rifts.insert(key, (from_real_osm, rifts));
                    if let Some(sync_msg) = self.build_chunk_rifts_sync_msg(chunk_x, chunk_y) {
                        self.broadcast_all(&sync_msg);
                    }
                } else if let Some(sync_msg) = self.build_chunk_rifts_sync_msg(chunk_x, chunk_y) {
                    if let Some(p) = self.peers.get(&uid) {
                        let _ = p.tx.send(sync_msg);
                    }
                }
            }
            NetClientMsg::OverworldRiftEnemyKilled {
                portal_id,
                spawn_idx,
            } => {
                if spawn_idx > 128 {
                    return;
                }
                let set = self.overworld_rift_kills.entry(portal_id).or_default();
                if set.insert(spawn_idx) {
                    self.broadcast_all(&NetServerMsg::OverworldRiftEnemyRemoved {
                        portal_id,
                        spawn_idx,
                        killer_uid: uid,
                    });
                }
            }
            NetClientMsg::OverworldPortalCleared { portal_id } => {
                if self.dormant_overworld_portals.insert(portal_id) {
                    self.broadcast_all(&NetServerMsg::OverworldPortalDormant { portal_id });
                }
            }
            NetClientMsg::Chat { text } => {
                let clean = text.trim();
                if clean.is_empty() {
                    return;
                }
                let sender = self
                    .peers
                    .get(&uid)
                    .map(|p| p.snap.name.clone())
                    .unwrap_or_else(|| "Jäger".to_string());
                let clipped: String = clean.chars().take(240).collect();
                self.log_event(format!("[Chat] {}: {}", sender, clipped));
                self.broadcast_all(&NetServerMsg::ChatBroadcast {
                    sender,
                    text: clipped,
                    is_system: false,
                });
            }
        }
    }

    fn completed_portal_remove_and_stabilize(&mut self, seed: u64) {
        self.sealed_portals.remove(&seed);
        self.stabilized_portals.insert(seed);
        self.dungeons.remove(&seed);
        self.overworld_rift_kills.remove(&seed);
        self.dormant_overworld_portals.remove(&seed);
    }

    fn build_chunk_rifts_sync_msg(&self, chunk_x: i32, chunk_y: i32) -> Option<NetServerMsg> {
        let (from_real_osm, rifts) = self.chunk_rifts.get(&(chunk_x, chunk_y))?;
        let mut killed_enemies = Vec::new();
        let mut dormant_portals = Vec::new();
        for r in rifts {
            if let Some(kills) = self.overworld_rift_kills.get(&r.id) {
                if !kills.is_empty() {
                    let mut v: Vec<u32> = kills.iter().copied().collect();
                    v.sort_unstable();
                    killed_enemies.push((r.id, v));
                }
            }
            if self.dormant_overworld_portals.contains(&r.id) {
                dormant_portals.push(r.id);
            }
        }
        Some(NetServerMsg::ChunkRiftsSync {
            chunk_x,
            chunk_y,
            from_real_osm: *from_real_osm,
            rifts: rifts.clone(),
            killed_enemies,
            dormant_portals,
        })
    }

    fn publish_local_bubbles(&self) {
        if self.peers.is_empty() || (self.peers.len() == 1 && self.vehicles.is_empty()) {
            return;
        }
        let all_snaps: Vec<&NetPlayerSnapshot> = self
            .peers
            .values()
            .filter(|p| !p.awaiting_creation)
            .map(|p| &p.snap)
            .collect();
        let all_vehs: Vec<&WireVehicle> = self.vehicles.values().collect();

        for peer in self.peers.values().filter(|p| !p.awaiting_creation) {
            let nearby_players: Vec<NetPlayerSnapshot> = all_snaps
                .iter()
                .filter(|s| s.uid != peer.uid && peer.snap.net_pos.is_within_local_bubble(&s.net_pos))
                .map(|s| (*s).clone())
                .collect();

            let nearby_vehs: Vec<WireVehicle> = all_vehs
                .iter()
                .filter(|v| {
                    let v_pos = NetWorldPos::Overworld {
                        merc_x: v.merc_x,
                        merc_y: v.merc_y,
                    };
                    peer.snap.net_pos.is_within_local_bubble(&v_pos)
                })
                .map(|v| (*v).clone())
                .collect();

            let _ = peer.tx.send(NetServerMsg::LocalBubbleTick {
                players: nearby_players,
                vehicles: nearby_vehs,
            });
        }
    }

    fn publish_macro_sync(&self) {
        if self.peers.is_empty() {
            return;
        }
        let players: Vec<NetPlayerSnapshot> = self
            .peers
            .values()
            .filter(|p| !p.awaiting_creation)
            .map(|p| p.snap.clone())
            .collect();
        let mut character_directory: Vec<NetCharacterDirectoryEntry> = self
            .characters
            .values()
            .map(|ch| {
                let ginfo = self.find_player_guild(ch.player_uid);
                let is_online = self
                    .peers
                    .get(&ch.player_uid)
                    .map_or(false, |p| !p.awaiting_creation);
                NetCharacterDirectoryEntry {
                    uid: ch.player_uid,
                    name: ch.player_name.clone(),
                    level: ch.level,
                    role_id: ch.role_id,
                    appearance_bytes: ch.appearance_bytes,
                    guild_id: ginfo.as_ref().map(|(id, _, _)| *id),
                    guild_name: ginfo.map(|(_, _, n)| n).unwrap_or_default(),
                    online: is_online,
                    last_merc_x: ch.last_merc_x,
                    last_merc_y: ch.last_merc_y,
                }
            })
            .collect();
        // Also include any newly connected peers who haven't pushed their first SyncCharacter yet
        for p in self.peers.values().filter(|p| !p.awaiting_creation) {
            if !self.characters.contains_key(&p.uid) {
                let (mx, my) = match p.snap.net_pos {
                    NetWorldPos::Overworld { merc_x, merc_y } => (merc_x, merc_y),
                    _ => (0.0, 0.0),
                };
                character_directory.push(NetCharacterDirectoryEntry {
                    uid: p.uid,
                    name: p.snap.name.clone(),
                    level: p.snap.level,
                    role_id: p.snap.role_id,
                    appearance_bytes: p.snap.appearance_bytes,
                    guild_id: p.snap.guild_id,
                    guild_name: p.snap.guild_name.clone(),
                    online: true,
                    last_merc_x: mx,
                    last_merc_y: my,
                });
            }
        }
        character_directory.sort_by(|a, b| b.online.cmp(&a.online).then_with(|| b.level.cmp(&a.level)));

        let guilds: Vec<WirePlayerGuild> = self.guilds.values().cloned().collect();
        let all_vehicles: Vec<WireVehicle> = self.vehicles.values().cloned().collect();
        let msg = NetServerMsg::WorldMacroSync {
            world_hour: self.world_hour,
            world_tier: self.world_tier,
            world_level_offset: self.world_level_offset,
            players,
            character_directory,
            guilds,
            all_vehicles,
        };
        for peer in self.peers.values() {
            let _ = peer.tx.send(msg.clone());
        }
    }

    fn step_macro_second(&mut self) {
        if !self.peers.is_empty() || !self.config.pause_when_empty {
            let day_secs = self.config.ingame_day_real_secs.max(60.0);
            self.world_hour = (self.world_hour + (24.0 / day_secs)).rem_euclid(24.0);
        }
        self.publish_macro_sync();
        self.save_if_needed(false);
    }

    fn check_ban_reason(
        &self,
        player_uid: u64,
        pubkey: &[u8; 32],
        peer_ip: &str,
    ) -> Option<String> {
        let pk_hex = if *pubkey == [0u8; 32] {
            String::new()
        } else {
            bytes32_to_hex(pubkey)
        };
        let fp = if *pubkey == [0u8; 32] {
            String::new()
        } else {
            format_pubkey_fingerprint(pubkey)
        };
        for b in &self.bans {
            let match_pk = !pk_hex.is_empty()
                && !b.pubkey_hex.is_empty()
                && b.pubkey_hex.eq_ignore_ascii_case(&pk_hex);
            let match_fp = !fp.is_empty()
                && !b.device_fingerprint.is_empty()
                && b.device_fingerprint.eq_ignore_ascii_case(&fp);
            let match_uid = b.player_uid == Some(player_uid);
            let match_ip = !peer_ip.is_empty()
                && b.ip_address
                    .as_deref()
                    .map_or(false, |bip| !bip.is_empty() && bip == peer_ip);
            if match_pk || match_fp || match_uid || match_ip {
                let id_lbl = if !fp.is_empty() {
                    fp
                } else {
                    format!("UID {}", player_uid)
                };
                return Some(format!(
                    "Dein Gerät ({}) ist auf diesem Server gesperrt. Grund: {}",
                    id_lbl,
                    if b.reason.is_empty() {
                        "Vom Administrator gesperrt"
                    } else {
                        &b.reason
                    }
                ));
            }
        }
        None
    }

    fn kick_peer_immediately(
        &mut self,
        uid: u64,
        reason: &str,
        online_count: &Arc<AtomicUsize>,
    ) -> bool {
        self.release_player_vehicle_seats(uid);
        if let Some(mut peer) = self.peers.remove(&uid) {
            for g in self.guilds.values_mut() {
                for m in &mut g.members {
                    if m.uid == uid {
                        m.online = false;
                    }
                }
            }
            let _ = peer.tx.send(NetServerMsg::Rejected {
                reason: reason.to_string(),
            });
            drop(peer.tx);
            if let Some(ktx) = peer.kick_tx.take() {
                let _ = ktx.send(());
            }
            online_count.store(self.peers.len(), Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    fn recalculate_all_cached_rifts(&mut self) {
        let tier = self.world_tier;
        let offset = self.world_level_offset;
        for (_, rifts) in self.chunk_rifts.values_mut() {
            for r in rifts.iter_mut() {
                if r.base_level == 0 {
                    r.base_level = r.level.max(1);
                }
                r.level = apply_world_difficulty_to_level(r.base_level, tier, offset);
                r.max_floors = compute_rift_floors_from_level(r.level, r.id);
            }
        }
        let coords: Vec<(i32, i32)> = self.chunk_rifts.keys().copied().collect();
        for (cx, cy) in coords {
            if let Some(sync_msg) = self.build_chunk_rifts_sync_msg(cx, cy) {
                self.broadcast_all(&sync_msg);
            }
        }
    }

    fn backup_dir_path(&self) -> Option<std::path::PathBuf> {
        let path_str = self.config.world_save_path.as_ref()?;
        let p = Path::new(path_str);
        let parent = p
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        Some(parent.join("backups"))
    }

    fn create_world_backup(&mut self, label: &str) -> Result<String, String> {
        self.dirty = true;
        self.save_if_needed(true);
        let Some(ref src_str) = self.config.world_save_path else {
            return Err("Kein 'world_save_path' konfiguriert.".to_string());
        };
        let bdir = self
            .backup_dir_path()
            .ok_or_else(|| "Kein Backup-Pfad verfügbar.".to_string())?;
        std::fs::create_dir_all(&bdir).map_err(|e| e.to_string())?;
        let unix_s = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let safe_lbl: String = label
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .take(24)
            .collect();
        let fname = if safe_lbl.is_empty() {
            format!("world_snapshot_{}.bin", unix_s)
        } else {
            format!("world_snapshot_{}_{}.bin", unix_s, safe_lbl)
        };
        let dst = bdir.join(&fname);
        std::fs::copy(src_str, &dst).map_err(|e| format!("Backup fehlgeschlagen: {}", e))?;
        Ok(fname)
    }

    fn list_world_backups(&self) -> Vec<admin::AdminBackupRow> {
        let Some(bdir) = self.backup_dir_path() else {
            return Vec::new();
        };
        let Ok(rd) = std::fs::read_dir(bdir) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for ent in rd.flatten() {
            let fname = ent.file_name().to_string_lossy().to_string();
            if !fname.ends_with(".bin") {
                continue;
            }
            if let Ok(md) = ent.metadata() {
                let mtime = md
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                out.push(admin::AdminBackupRow {
                    filename: fname,
                    size_bytes: md.len(),
                    modified_unix: mtime,
                });
            }
        }
        out.sort_by(|a, b| b.modified_unix.cmp(&a.modified_unix));
        out
    }

    fn build_admin_dashboard(&self) -> admin::AdminDashboardState {
        let role_label_of = |rid: u8| -> &'static str {
            match rid {
                0 => "Tank",
                1 => "Fernkampf",
                2 => "Nahkampf",
                3 => "Heiler",
                4 => "Magier",
                _ => "Jäger",
            }
        };

        let mut all_uids: HashSet<u64> = self.characters.keys().copied().collect();
        for (&uid, p) in &self.peers {
            if !p.awaiting_creation {
                all_uids.insert(uid);
            }
        }

        let mut characters = Vec::with_capacity(all_uids.len());
        for uid in all_uids {
            let peer_opt = self.peers.get(&uid).filter(|p| !p.awaiting_creation);
            let ch_opt = self.characters.get(&uid);
            let name = peer_opt
                .map(|p| p.snap.name.clone())
                .or_else(|| ch_opt.map(|c| c.player_name.clone()))
                .unwrap_or_else(|| format!("UID {}", uid));
            let level = peer_opt
                .map(|p| p.snap.level)
                .or_else(|| ch_opt.map(|c| c.level))
                .unwrap_or(1);
            let role_id = peer_opt
                .map(|p| p.snap.role_id)
                .or_else(|| ch_opt.map(|c| c.role_id))
                .unwrap_or(0);

            let (mx, my, dim_txt) = if let Some(p) = peer_opt {
                match p.snap.net_pos {
                    NetWorldPos::Overworld { merc_x, merc_y } => {
                        (merc_x, merc_y, "Oberwelt".to_string())
                    }
                    NetWorldPos::BuildingInterior { building_id, .. } => {
                        let (fb_x, fb_y) = ch_opt
                            .map(|c| (c.last_merc_x, c.last_merc_y))
                            .unwrap_or((0.0, 0.0));
                        (fb_x, fb_y, format!("Gebäude #{}", building_id))
                    }
                    NetWorldPos::Dungeon {
                        seed,
                        floor,
                        max_floors,
                        ..
                    } => {
                        let (fb_x, fb_y) = ch_opt
                            .map(|c| (c.last_merc_x, c.last_merc_y))
                            .unwrap_or((0.0, 0.0));
                        let d_lbl = if (seed & 0xFFFF_FF00_0000_0000) == 0xDD4E_E000_0000_0000 {
                            "Initialisierungs-Riss (Pfadprüfung)".to_string()
                        } else {
                            format!("Riss-Dungeon #{} (Etage {}/{})", seed, floor, max_floors)
                        };
                        (fb_x, fb_y, d_lbl)
                    }
                }
            } else if let Some(c) = ch_opt {
                (c.last_merc_x, c.last_merc_y, "Oberwelt (Gespeichert)".to_string())
            } else {
                (0.0, 0.0, "Unbekannt".to_string())
            };

            let (lat, lon) = merc_to_lat_lon_deg(mx, my);
            let ginfo = self.find_player_guild(uid);
            let pk_opt = self.registered_pubkeys.get(&uid);
            let pubkey_hex = pk_opt.map(bytes32_to_hex).unwrap_or_default();
            let meta = self.player_meta.get(&uid);
            let device_fingerprint = pk_opt
                .map(format_pubkey_fingerprint)
                .or_else(|| meta.map(|m| m.device_fingerprint.clone()))
                .unwrap_or_default();
            let last_ip = peer_opt
                .map(|p| p.peer_ip.clone())
                .or_else(|| meta.map(|m| m.last_ip.clone()))
                .unwrap_or_default();
            let last_seen_unix = if peer_opt.is_some() {
                current_unix_ms() / 1000
            } else {
                meta.map(|m| m.last_seen_unix_secs).unwrap_or(0)
            };

            characters.push(admin::AdminCharacterRow {
                uid,
                name,
                level,
                role_label: role_label_of(role_id).to_string(),
                online: peer_opt.is_some(),
                guild_name: ginfo.as_ref().map(|(_, _, n)| n.clone()).unwrap_or_default(),
                guild_role: ginfo
                    .as_ref()
                    .map(|(_, r, _)| r.label_de().to_string())
                    .unwrap_or_default(),
                dimension: dim_txt,
                lat,
                lon,
                device_fingerprint,
                pubkey_hex,
                last_ip,
                last_seen_unix,
            });
        }
        characters.sort_by(|a, b| b.online.cmp(&a.online).then_with(|| b.level.cmp(&a.level)));

        let mut guilds: Vec<admin::AdminGuildRow> = self
            .guilds
            .values()
            .map(|g| {
                let hostile_wars = g
                    .stances
                    .values()
                    .filter(|&&s| s == PlayerGuildStance::Hostile)
                    .count();
                let bases = g
                    .bases
                    .iter()
                    .map(|b| {
                        let (lat, lon) = merc_to_lat_lon_deg(b.door_merc_x, b.door_merc_y);
                        admin::AdminBaseRow {
                            building_id: b.building_id,
                            name: b.name.clone(),
                            module_count: b.module_count,
                            lat,
                            lon,
                        }
                    })
                    .collect();
                admin::AdminGuildRow {
                    guild_id: g.guild_id,
                    name: g.name.clone(),
                    founder_name: g.founder_name.clone(),
                    member_count: g.members.len(),
                    hostile_wars,
                    bases,
                }
            })
            .collect();
        guilds.sort_by_key(|g| g.guild_id);

        let mut vehicles: Vec<admin::AdminVehicleRow> = self
            .vehicles
            .values()
            .map(|v| {
                let (lat, lon) = merc_to_lat_lon_deg(v.merc_x, v.merc_y);
                let owner_label = if let Some(gid) = v.guild_id {
                    self.guilds
                        .get(&gid)
                        .map(|g| format!("Gilde '{}'", g.name))
                        .unwrap_or_else(|| format!("Gilde #{}", gid))
                } else {
                    self.characters
                        .get(&v.owner_uid)
                        .map(|c| format!("Spieler '{}'", c.player_name))
                        .unwrap_or_else(|| format!("UID {}", v.owner_uid))
                };
                admin::AdminVehicleRow {
                    vehicle_id: v.vehicle_id,
                    label_de: v.label_de.clone(),
                    owner_label,
                    fuel_liters: v.fuel_liters,
                    body_pct: v.body_pct,
                    tires_pct: v.tires_pct,
                    driver_uid: v.driver_uid,
                    passenger_count: v.passengers.len(),
                    lat,
                    lon,
                }
            })
            .collect();
        vehicles.sort_by_key(|v| v.vehicle_id);

        let mut rifts_preview = Vec::new();
        for (_, rifts) in self.chunk_rifts.values() {
            for r in rifts {
                if self.sealed_portals.contains(&r.id) {
                    continue;
                }
                let (lat, lon) = merc_to_lat_lon_deg(r.merc_x, r.merc_y);
                rifts_preview.push(admin::AdminRiftPin {
                    id: r.id,
                    level: r.level,
                    theme: r.theme.clone(),
                    lat,
                    lon,
                });
                if rifts_preview.len() >= 250 {
                    break;
                }
            }
            if rifts_preview.len() >= 250 {
                break;
            }
        }

        let active_online = self.peers.values().filter(|p| !p.awaiting_creation).count();
        admin::AdminDashboardState {
            session_name: self.config.session_name.clone(),
            tcp_port: self.bound_port,
            online_players: active_online,
            max_players: self.config.max_players,
            server_password: self.config.password.clone(),
            pause_when_empty: self.config.pause_when_empty,
            hibernating: self.peers.is_empty() && self.config.pause_when_empty,
            world_seed: self.world_seed,
            world_hour: self.world_hour,
            ingame_day_real_secs: self.config.ingame_day_real_secs,
            world_tier: self.world_tier,
            world_level_offset: self.world_level_offset,
            sample_min_rift_level: apply_world_difficulty_to_level(
                2,
                self.world_tier,
                self.world_level_offset,
            ),
            sample_max_rift_level: apply_world_difficulty_to_level(
                14,
                self.world_tier,
                self.world_level_offset,
            ),
            cached_rift_chunks: self.chunk_rifts.len(),
            sealed_portal_count: self.sealed_portals.len(),
            uptime_secs: self.started_at.elapsed().as_secs(),
            characters,
            bans: self.bans.clone(),
            guilds,
            vehicles,
            rifts_preview,
            backups: self.list_world_backups(),
            recent_events: self.recent_events.iter().cloned().collect(),
        }
    }

    fn execute_admin_command(
        &mut self,
        cmd: admin::AdminCommand,
        online_count: &Arc<AtomicUsize>,
    ) -> Result<admin::AdminActionReply, String> {
        use admin::AdminCommand;
        let msg = match cmd {
            AdminCommand::GetDashboard => String::new(),
            AdminCommand::ForceSave => {
                self.dirty = true;
                self.save_if_needed(true);
                self.log_event("[Admin] Manuelle Weltspeicherung ausgeführt.".to_string());
                "Weltstatus wurde sofort auf die Festplatte gespeichert.".to_string()
            }
            AdminCommand::SetWorldDifficulty {
                world_tier,
                world_level_offset,
            } => {
                self.world_tier = world_tier.clamp(0, 50);
                self.world_level_offset = world_level_offset.clamp(-20, 200);
                self.dirty = true;
                self.recalculate_all_cached_rifts();
                self.publish_macro_sync();
                self.save_if_needed(true);
                let announce = format!(
                    "Weltstufe wurde vom Administrator auf Stufe {}{} angepasst!",
                    self.world_tier,
                    if self.world_level_offset != 0 {
                        format!(" (Offset {:+})", self.world_level_offset)
                    } else {
                        String::new()
                    }
                );
                self.log_event(format!("[Admin] {}", announce));
                self.broadcast_all(&NetServerMsg::ChatBroadcast {
                    sender: "Admin".to_string(),
                    text: announce.clone(),
                    is_system: true,
                });
                announce
            }
            AdminCommand::SetWorldTime {
                world_hour,
                ingame_day_real_secs,
            } => {
                self.world_hour = world_hour.rem_euclid(24.0);
                if let Some(ds) = ingame_day_real_secs {
                    self.config.ingame_day_real_secs = ds.clamp(60.0, 86_400.0);
                    if let Some(ref cfg_p) = self.config.config_file_path {
                        if let Ok(pretty) = serde_json::to_string_pretty(&self.config) {
                            let _ = std::fs::write(cfg_p, pretty);
                        }
                    }
                }
                self.dirty = true;
                self.publish_macro_sync();
                self.save_if_needed(true);
                let m = format!(
                    "Weltzeit auf {:02}:{:02} Uhr gesetzt.",
                    self.world_hour as u32,
                    ((self.world_hour.fract()) * 60.0) as u32
                );
                self.log_event(format!("[Admin] {}", m));
                m
            }
            AdminCommand::UpdateServerSettings {
                session_name,
                max_players,
                password,
                pause_when_empty,
            } => {
                if !session_name.trim().is_empty() {
                    self.config.session_name = session_name.trim().to_string();
                }
                self.config.max_players = max_players.clamp(2, 64);
                self.config.password = password;
                self.config.pause_when_empty = pause_when_empty;
                if let Some(ref cfg_p) = self.config.config_file_path {
                    if let Ok(pretty) = serde_json::to_string_pretty(&self.config) {
                        let _ = std::fs::write(cfg_p, pretty);
                    }
                }
                self.write_status_json();
                self.log_event(format!(
                    "[Admin] Servereinstellungen aktualisiert ('{}', max. {} Spieler).",
                    self.config.session_name, self.config.max_players
                ));
                "Servereinstellungen live übernommen und gespeichert.".to_string()
            }
            AdminCommand::BroadcastMessage { text } => {
                let clean: String = text.trim().chars().take(280).collect();
                if clean.is_empty() {
                    return Err("Nachricht darf nicht leer sein.".to_string());
                }
                self.log_event(format!("[Admin-Durchsage] {}", clean));
                self.broadcast_all(&NetServerMsg::ChatBroadcast {
                    sender: "Administrator".to_string(),
                    text: clean,
                    is_system: true,
                });
                "System-Durchsage an alle Spieler gesendet.".to_string()
            }
            AdminCommand::KickPlayer { player_uid, reason } => {
                let why = if reason.trim().is_empty() {
                    "Vom Server-Administrator getrennt."
                } else {
                    reason.trim()
                };
                if self.kick_peer_immediately(player_uid, why, online_count) {
                    self.publish_macro_sync();
                    self.write_status_json();
                    self.log_event(format!(
                        "[Admin] Spieler UID {} gekickt ({}).",
                        player_uid, why
                    ));
                    format!("Spieler (UID {}) wurde getrennt.", player_uid)
                } else {
                    "Spieler ist aktuell nicht online.".to_string()
                }
            }
            AdminCommand::BanDevice {
                player_uid,
                mut pubkey_hex,
                mut device_fingerprint,
                mut ip_address,
                mut player_name,
                reason,
                delete_character,
            } => {
                if let Some(uid) = player_uid {
                    if pubkey_hex.is_empty() {
                        if let Some(pk) = self.registered_pubkeys.get(&uid) {
                            pubkey_hex = bytes32_to_hex(pk);
                            device_fingerprint = format_pubkey_fingerprint(pk);
                        }
                    }
                    if player_name.is_empty() {
                        if let Some(ch) = self.characters.get(&uid) {
                            player_name = ch.player_name.clone();
                        }
                    }
                    if ip_address.is_none() {
                        ip_address = self
                            .peers
                            .get(&uid)
                            .map(|p| p.peer_ip.clone())
                            .or_else(|| self.player_meta.get(&uid).map(|m| m.last_ip.clone()))
                            .filter(|s| !s.is_empty());
                    }
                }
                if device_fingerprint.is_empty() && !pubkey_hex.is_empty() {
                    if let Some(pk) = hex_to_bytes32(&pubkey_hex) {
                        device_fingerprint = format_pubkey_fingerprint(&pk);
                    }
                }
                if pubkey_hex.is_empty()
                    && device_fingerprint.is_empty()
                    && player_uid.is_none()
                    && ip_address.is_none()
                {
                    return Err("Keine gültige Device-ID, UID oder IP zum Sperren angegeben.".to_string());
                }

                let ban_id = self.next_ban_id;
                self.next_ban_id += 1;
                let clean_reason = if reason.trim().is_empty() {
                    "Vom Administrator gesperrt".to_string()
                } else {
                    reason.trim().to_string()
                };
                let entry = admin::BanEntry {
                    ban_id,
                    device_fingerprint: device_fingerprint.clone(),
                    pubkey_hex: pubkey_hex.to_lowercase(),
                    player_uid,
                    ip_address,
                    player_name: player_name.clone(),
                    reason: clean_reason.clone(),
                    banned_at_unix_secs: current_unix_ms() / 1000,
                };
                self.bans.push(entry);

                // Immediately kick any connected session matching this Device-ID / UID / IP!
                let matching_online: Vec<u64> = self
                    .peers
                    .iter()
                    .filter_map(|(&uid, peer)| {
                        let pk = self.registered_pubkeys.get(&uid).copied().unwrap_or([0u8; 32]);
                        if self.check_ban_reason(uid, &pk, &peer.peer_ip).is_some() {
                            Some(uid)
                        } else {
                            None
                        }
                    })
                    .collect();
                for kuid in matching_online {
                    let msg = format!(
                        "Dein Gerät wurde vom Administrator gesperrt: {}",
                        clean_reason
                    );
                    self.kick_peer_immediately(kuid, &msg, online_count);
                }

                if delete_character {
                    if let Some(uid) = player_uid {
                        self.purge_character_for_reset(uid);
                    }
                }
                self.dirty = true;
                self.save_if_needed(true);
                self.publish_macro_sync();
                let label = if !device_fingerprint.is_empty() {
                    device_fingerprint
                } else {
                    player_name.clone()
                };
                self.log_event(format!(
                    "[Admin] Gerät/Spieler '{}' gesperrt (Ban #{}, Grund: {}).",
                    label, ban_id, clean_reason
                ));
                format!("Sperre #{} für '{}' aktiviert.", ban_id, label)
            }
            AdminCommand::UnbanDevice { ban_id } => {
                let before = self.bans.len();
                self.bans.retain(|b| b.ban_id != ban_id);
                if self.bans.len() == before {
                    return Err("Sperreintrag nicht gefunden.".to_string());
                }
                self.save_bans_and_meta();
                self.log_event(format!("[Admin] Gerätesperre #{} aufgehoben.", ban_id));
                format!("Sperre #{} wurde aufgehoben.", ban_id)
            }
            AdminCommand::TeleportOrUnstuckPlayer {
                player_uid,
                lat,
                lon,
                unstuck_to_overworld,
            } => {
                let target_merc = match (lat, lon) {
                    (Some(la), Some(lo)) => {
                        let (mx, my) = lat_lon_deg_to_merc(la, lo);
                        Some((mx, my, la, lo))
                    }
                    _ => None,
                };

                let mut updated = false;
                if let Some(ch) = self.characters.get_mut(&player_uid) {
                    if let Some((mx, my, la, lo)) = target_merc {
                        ch.last_merc_x = mx;
                        ch.last_merc_y = my;
                        if let Ok(mut jv) =
                            serde_json::from_slice::<serde_json::Value>(&ch.character_bincode)
                        {
                            if let Some(obj) = jv.as_object_mut() {
                                obj.insert("last_lat".to_string(), serde_json::json!(la));
                                obj.insert("last_lon".to_string(), serde_json::json!(lo));
                                obj.insert("saved_pos_x".to_string(), serde_json::json!(0.0));
                                obj.insert("saved_pos_y".to_string(), serde_json::json!(0.0));
                                obj.insert("has_saved_pos".to_string(), serde_json::json!(true));
                            }
                            if let Ok(new_bytes) = serde_json::to_vec(&jv) {
                                ch.character_bincode = new_bytes;
                            }
                        }
                    }
                    updated = true;
                }

                self.release_player_vehicle_seats(player_uid);
                if let Some(peer) = self.peers.get_mut(&player_uid) {
                    let (dest_mx, dest_my) = if let Some((mx, my, _, _)) = target_merc {
                        (mx, my)
                    } else if let Some(ch) = self.characters.get(&player_uid) {
                        (ch.last_merc_x, ch.last_merc_y)
                    } else if let NetWorldPos::Overworld { merc_x, merc_y } = peer.snap.net_pos {
                        (merc_x, merc_y)
                    } else {
                        lat_lon_deg_to_merc(52.5200, 13.4050)
                    };
                    peer.snap.net_pos = NetWorldPos::Overworld {
                        merc_x: dest_mx,
                        merc_y: dest_my,
                    };
                    peer.snap.driving_vehicle_id = None;
                    peer.snap.riding_vehicle_id = None;
                    let note = if target_merc.is_some() {
                        "Du wurdest vom Server-Administrator teleportiert.".to_string()
                    } else {
                        "Du wurdest vom Server-Administrator auf die Oberwelt gerettet (Unstuck)."
                            .to_string()
                    };
                    let _ = peer.tx.send(NetServerMsg::AdminPlayerControl {
                        target_merc_x: Some(dest_mx),
                        target_merc_y: Some(dest_my),
                        force_overworld: unstuck_to_overworld || target_merc.is_some(),
                        new_level: None,
                        message: note,
                    });
                    updated = true;
                }

                if !updated {
                    return Err("Spieler/Charakter nicht gefunden.".to_string());
                }
                self.dirty = true;
                self.save_if_needed(true);
                self.publish_macro_sync();
                let m = if let Some((_, _, la, lo)) = target_merc {
                    format!(
                        "Spieler UID {} nach ({:.4}°, {:.4}°) versetzt.",
                        player_uid, la, lo
                    )
                } else {
                    format!("Spieler UID {} auf sichere Oberwelt gerettet.", player_uid)
                };
                self.log_event(format!("[Admin] {}", m));
                m
            }
            AdminCommand::SetCharacterLevel {
                player_uid,
                new_level,
            } => {
                let lvl = new_level.clamp(1, 500);
                let mut found_name = None;
                if let Some(ch) = self.characters.get_mut(&player_uid) {
                    ch.level = lvl;
                    found_name = Some(ch.player_name.clone());
                    if let Ok(mut jv) =
                        serde_json::from_slice::<serde_json::Value>(&ch.character_bincode)
                    {
                        if let Some(obj) = jv.as_object_mut() {
                            obj.insert("level".to_string(), serde_json::json!(lvl));
                        }
                        if let Ok(new_bytes) = serde_json::to_vec(&jv) {
                            ch.character_bincode = new_bytes;
                        }
                    }
                }
                if let Some(peer) = self.peers.get_mut(&player_uid) {
                    peer.snap.level = lvl;
                    if found_name.is_none() {
                        found_name = Some(peer.snap.name.clone());
                    }
                    let _ = peer.tx.send(NetServerMsg::AdminPlayerControl {
                        target_merc_x: None,
                        target_merc_y: None,
                        force_overworld: false,
                        new_level: Some(lvl),
                        message: format!(
                            "Deine Charakterstufe wurde vom Administrator auf Stufe {} gesetzt.",
                            lvl
                        ),
                    });
                }
                let Some(cname) = found_name else {
                    return Err("Charakter nicht gefunden.".to_string());
                };
                for g in self.guilds.values_mut() {
                    for m in &mut g.members {
                        if m.uid == player_uid {
                            m.level = lvl;
                        }
                    }
                }
                self.dirty = true;
                self.save_if_needed(true);
                self.publish_macro_sync();
                let m = format!("Stufe von '{}' auf Stufe {} gesetzt.", cname, lvl);
                self.log_event(format!("[Admin] {}", m));
                m
            }
            AdminCommand::DeleteCharacter { player_uid } => {
                let cname = self
                    .characters
                    .get(&player_uid)
                    .map(|c| c.player_name.clone())
                    .unwrap_or_else(|| format!("UID {}", player_uid));
                self.kick_peer_immediately(
                    player_uid,
                    "Dein Charakter wurde vom Server-Administrator gelöscht.",
                    online_count,
                );
                self.purge_character_for_reset(player_uid);
                self.save_if_needed(true);
                self.publish_macro_sync();
                let m = format!("Charakter '{}' (UID {}) gelöscht.", cname, player_uid);
                self.log_event(format!("[Admin] {}", m));
                m
            }
            AdminCommand::ResetArea {
                lat,
                lon,
                radius_km,
                reset_rifts,
                restore_buildings,
                remove_vehicles,
                remove_bases,
            } => {
                let r_km = radius_km.clamp(0.2, 100.0);
                let (center_mx, center_my) = lat_lon_deg_to_merc(lat, lon);
                let meter_scale = lat.clamp(-80.0, 80.0).to_radians().cos().max(0.15);
                let radius_m = r_km * 1000.0;
                let merc_rad = radius_m / meter_scale;
                let in_radius = |mx: f64, my: f64| -> bool {
                    ((mx - center_mx) * meter_scale).hypot((my - center_my) * meter_scale)
                        <= radius_m
                };

                let cx_min = ((center_mx - merc_rad) / SERVER_CHUNK_MERC_SIZE).floor() as i32;
                let cx_max = ((center_mx + merc_rad) / SERVER_CHUNK_MERC_SIZE).floor() as i32;
                let cy_min = ((center_my - merc_rad) / SERVER_CHUNK_MERC_SIZE).floor() as i32;
                let cy_max = ((center_my + merc_rad) / SERVER_CHUNK_MERC_SIZE).floor() as i32;

                let mut reset_chunks = Vec::new();
                let mut unsealed_portals = Vec::new();
                let mut restored_buildings = Vec::new();

                if reset_rifts {
                    for cx in cx_min..=cx_max {
                        for cy in cy_min..=cy_max {
                            if let Some((_, rifts)) = self.chunk_rifts.remove(&(cx, cy)) {
                                for r in rifts {
                                    self.sealed_portals.remove(&r.id);
                                    self.stabilized_portals.remove(&r.id);
                                    self.dungeons.remove(&r.id);
                                    self.overworld_rift_kills.remove(&r.id);
                                    self.dormant_overworld_portals.remove(&r.id);
                                    unsealed_portals.push(r.id);
                                }
                            }
                            if reset_chunks.len() < 4096 {
                                reset_chunks.push((cx, cy));
                            }
                        }
                    }
                }

                if restore_buildings {
                    for g in self.guilds.values_mut() {
                        for &bid in &g.demolished_buildings {
                            restored_buildings.push(bid);
                        }
                        g.demolished_buildings.clear();
                    }
                }

                let mut removed_vehs = 0usize;
                if remove_vehicles {
                    let before = self.vehicles.len();
                    self.vehicles.retain(|_, v| {
                        v.driver_uid.is_some()
                            || !v.passengers.is_empty()
                            || !in_radius(v.merc_x, v.merc_y)
                    });
                    removed_vehs = before.saturating_sub(self.vehicles.len());
                }

                let mut removed_bases = 0usize;
                if remove_bases {
                    for g in self.guilds.values_mut() {
                        let before = g.bases.len();
                        g.bases.retain(|b| !in_radius(b.door_merc_x, b.door_merc_y));
                        removed_bases += before.saturating_sub(g.bases.len());
                    }
                }

                self.dirty = true;
                self.save_if_needed(true);
                let summary = format!(
                    "Bereich ({:.3}°, {:.3}°, {:.1} km) zurückgesetzt ({} Sektoren, {} Risse erneuert, {} Fahrzeuge & {} Basen entfernt).",
                    lat,
                    lon,
                    r_km,
                    reset_chunks.len(),
                    unsealed_portals.len(),
                    removed_vehs,
                    removed_bases
                );
                self.log_event(format!("[Admin] {}", summary));
                self.broadcast_all(&NetServerMsg::AdminWorldReset {
                    new_world_seed: self.world_seed,
                    full_world_wipe: false,
                    reset_chunks,
                    unsealed_portals,
                    restored_buildings,
                    message: summary.clone(),
                });
                self.publish_macro_sync();
                summary
            }
            AdminCommand::ResetAllRiftsGlobal => {
                let prev_sealed = self.sealed_portals.len() + self.stabilized_portals.len();
                let all_unsealed: Vec<u64> = self
                    .sealed_portals
                    .iter()
                    .chain(self.stabilized_portals.iter())
                    .copied()
                    .collect();
                let reset_chunks: Vec<(i32, i32)> = self.chunk_rifts.keys().copied().collect();
                self.sealed_portals.clear();
                self.stabilized_portals.clear();
                self.dungeons.clear();
                self.chunk_rifts.clear();
                self.overworld_rift_kills.clear();
                self.dormant_overworld_portals.clear();
                self.dirty = true;
                self.save_if_needed(true);
                let m = format!(
                    "Alle Risse & Dungeons weltweit zurückgesetzt ({} versiegelte Portale wieder geöffnet).",
                    prev_sealed
                );
                self.log_event(format!("[Admin] {}", m));
                self.broadcast_all(&NetServerMsg::AdminWorldReset {
                    new_world_seed: self.world_seed,
                    full_world_wipe: true,
                    reset_chunks,
                    unsealed_portals: all_unsealed,
                    restored_buildings: Vec::new(),
                    message: m.clone(),
                });
                m
            }
            AdminCommand::RegenerateWorld {
                new_seed,
                keep_characters,
            } => {
                let _ = self.create_world_backup("pre_world_regen");
                self.world_seed = new_seed.filter(|&s| s != 0).unwrap_or_else(|| rand::random::<u64>() | 1);
                self.world_hour = 14.0;
                self.sealed_portals.clear();
                self.stabilized_portals.clear();
                self.dungeons.clear();
                self.chunk_rifts.clear();
                self.overworld_rift_kills.clear();
                self.dormant_overworld_portals.clear();
                self.guilds.clear();
                self.vehicles.clear();
                self.next_guild_id = 1;
                self.next_loot_id = 1;

                if !keep_characters {
                    self.characters.clear();
                } else {
                    for ch in self.characters.values_mut() {
                        if let Ok(mut jv) =
                            serde_json::from_slice::<serde_json::Value>(&ch.character_bincode)
                        {
                            if let Some(obj) = jv.as_object_mut() {
                                obj.insert(
                                    "world_seed".to_string(),
                                    serde_json::json!(self.world_seed),
                                );
                                obj.remove("bases");
                                obj.remove("guild");
                            }
                            if let Ok(new_bytes) = serde_json::to_vec(&jv) {
                                ch.character_bincode = new_bytes;
                            }
                        }
                    }
                }

                let online_uids: Vec<u64> = self.peers.keys().copied().collect();
                for uid in online_uids {
                    self.kick_peer_immediately(
                        uid,
                        "Die Serverwelt wurde vom Administrator neu generiert — bitte neu verbinden!",
                        online_count,
                    );
                }
                self.dirty = true;
                self.save_if_needed(true);
                let m = format!(
                    "Welt neu generiert (Neuer Seed: {}, Charaktere behalten: {}). Automatisches Backup wurde angelegt.",
                    self.world_seed,
                    if keep_characters { "Ja" } else { "Nein" }
                );
                self.log_event(format!("[Admin] {}", m));
                m
            }
            AdminCommand::RepairAndRefuelVehicle { vehicle_id } => {
                let Some(v) = self.vehicles.get_mut(&vehicle_id) else {
                    return Err("Fahrzeug nicht gefunden.".to_string());
                };
                v.body_pct = 100.0;
                v.tires_pct = 100.0;
                v.battery_pct = 100.0;
                v.fuel_liters = v.fuel_liters.max(65.0);
                if let Ok(mut jv) = serde_json::from_slice::<serde_json::Value>(&v.vehicle_bincode)
                {
                    if let Some(obj) = jv.as_object_mut() {
                        obj.insert("body_pct".to_string(), serde_json::json!(100.0));
                        obj.insert("tires_pct".to_string(), serde_json::json!(100.0));
                        obj.insert("battery_pct".to_string(), serde_json::json!(100.0));
                        obj.insert("fuel_liters".to_string(), serde_json::json!(v.fuel_liters));
                    }
                    if let Ok(nb) = serde_json::to_vec(&jv) {
                        v.vehicle_bincode = nb;
                    }
                }
                let lbl = v.label_de.clone();
                self.dirty = true;
                self.save_if_needed(true);
                self.publish_macro_sync();
                format!("Fahrzeug '{}' (#{}) vollgetankt & auf 100% repariert.", lbl, vehicle_id)
            }
            AdminCommand::UnlockVehicleSeats { vehicle_id } => {
                let Some(v) = self.vehicles.get_mut(&vehicle_id) else {
                    return Err("Fahrzeug nicht gefunden.".to_string());
                };
                v.driver_uid = None;
                v.passengers.clear();
                self.dirty = true;
                self.publish_macro_sync();
                format!("Sitze von Fahrzeug #{} freigegeben.", vehicle_id)
            }
            AdminCommand::DeleteVehicle { vehicle_id } => {
                if self.vehicles.remove(&vehicle_id).is_none() {
                    return Err("Fahrzeug nicht gefunden.".to_string());
                }
                self.dirty = true;
                self.save_if_needed(true);
                self.publish_macro_sync();
                format!("Fahrzeug #{} gelöscht.", vehicle_id)
            }
            AdminCommand::DeleteBase {
                guild_id,
                building_id,
            } => {
                let Some(g) = self.guilds.get_mut(&guild_id) else {
                    return Err("Gilde nicht gefunden.".to_string());
                };
                let before = g.bases.len();
                g.bases.retain(|b| b.building_id != building_id);
                if g.bases.len() == before {
                    return Err("Basis nicht gefunden.".to_string());
                }
                self.dirty = true;
                self.save_if_needed(true);
                self.publish_macro_sync();
                format!("Basis (Gebäude #{}) entfernt.", building_id)
            }
            AdminCommand::DisbandGuild { guild_id } => {
                let Some(g) = self.guilds.remove(&guild_id) else {
                    return Err("Gilde nicht gefunden.".to_string());
                };
                self.vehicles.retain(|_, v| v.guild_id != Some(guild_id));
                for og in self.guilds.values_mut() {
                    og.stances.remove(&guild_id);
                }
                for m in &g.members {
                    if let Some(p) = self.peers.get_mut(&m.uid) {
                        p.snap.guild_id = None;
                        p.snap.guild_name.clear();
                        p.snap.guild_role = PlayerGuildRole::Founder;
                        let _ = p.tx.send(NetServerMsg::GuildRoleUpdated {
                            guild_id: None,
                            role: PlayerGuildRole::Founder,
                            banner_msg: format!(
                                "Die Gilde '{}' wurde vom Server-Administrator aufgelöst.",
                                g.name
                            ),
                        });
                    }
                }
                self.dirty = true;
                self.save_if_needed(true);
                self.publish_macro_sync();
                self.log_event(format!("[Admin] Gilde '{}' aufgelöst.", g.name));
                format!("Gilde '{}' wurde aufgelöst.", g.name)
            }
            AdminCommand::ForceGlobalGuildPeace => {
                for g in self.guilds.values_mut() {
                    for st in g.stances.values_mut() {
                        *st = PlayerGuildStance::Friendly;
                    }
                }
                self.dirty = true;
                self.save_if_needed(true);
                self.publish_macro_sync();
                self.broadcast_all(&NetServerMsg::ChatBroadcast {
                    sender: "Admin".to_string(),
                    text: "Alle Gilden-Konflikte wurden vom Administrator auf Friedlich gesetzt."
                        .to_string(),
                    is_system: true,
                });
                "Frieden zwischen allen Spieler-Gilden wiederhergestellt.".to_string()
            }
            AdminCommand::CreateBackup { label } => {
                let fname = self.create_world_backup(&label)?;
                self.log_event(format!("[Admin] Weltspeicher-Backup '{}' angelegt.", fname));
                format!("Backup '{}' erfolgreich erstellt.", fname)
            }
            AdminCommand::RestoreBackup { filename } => {
                if filename.contains('/') || filename.contains('\\') || filename.contains("..") || !filename.ends_with(".bin") {
                    return Err("Ungültiger Backup-Dateiname.".to_string());
                }
                let bdir = self
                    .backup_dir_path()
                    .ok_or_else(|| "Kein Backup-Ordner verfügbar.".to_string())?;
                let src = bdir.join(&filename);
                if !src.exists() {
                    return Err("Backup-Datei existiert nicht.".to_string());
                }
                let Some(ref dst_str) = self.config.world_save_path.clone() else {
                    return Err("Kein Weltspeicherpfad konfiguriert.".to_string());
                };
                let online_uids: Vec<u64> = self.peers.keys().copied().collect();
                for uid in online_uids {
                    self.kick_peer_immediately(
                        uid,
                        "Serverwelt wird aus einem Admin-Backup wiederhergestellt — bitte gleich neu verbinden.",
                        online_count,
                    );
                }
                std::fs::copy(&src, dst_str)
                    .map_err(|e| format!("Wiederherstellung fehlgeschlagen: {}", e))?;
                self.characters.clear();
                self.guilds.clear();
                self.vehicles.clear();
                self.sealed_portals.clear();
                self.stabilized_portals.clear();
                self.dungeons.clear();
                self.chunk_rifts.clear();
                self.overworld_rift_kills.clear();
                self.dormant_overworld_portals.clear();
                self.load_from_disk_if_present();
                self.write_status_json();
                self.log_event(format!("[Admin] Backup '{}' wiederhergestellt.", filename));
                format!("Welt erfolgreich auf Backup '{}' zurückgesetzt!", filename)
            }
        };

        Ok(admin::AdminActionReply {
            ok: true,
            message: msg,
            state: self.build_admin_dashboard(),
        })
    }
}

enum HubEvent {
    ProbeQuery {
        player_uid: u64,
        reply_tx: tokio::sync::oneshot::Sender<NetServerMsg>,
    },
    DeleteCharacterQuery {
        req: NetClientMsg,
        peer_ip: String,
        reply_tx: tokio::sync::oneshot::Sender<NetServerMsg>,
    },
    PeerConnected {
        hello: NetClientMsg,
        peer_ip: String,
        tx: tokio::sync::mpsc::UnboundedSender<NetServerMsg>,
        kick_tx: tokio::sync::oneshot::Sender<()>,
        accept_tx: tokio::sync::oneshot::Sender<bool>,
    },
    PeerPacket {
        uid: u64,
        msg: NetClientMsg,
    },
    PeerDisconnected {
        uid: u64,
    },
    AdminRequest {
        cmd: admin::AdminCommand,
        reply_tx: tokio::sync::oneshot::Sender<Result<admin::AdminActionReply, String>>,
    },
    Shutdown,
}

/// Runs the authoritative DDNeo server loop on an active Tokio runtime until `stop_flag` is set.
/// If `config.admin_enabled` is true and no pre-bound `admin_listener` was supplied, binds the
/// Admin Web Control Panel automatically on `config.admin_bind_ip:config.admin_port`.
pub async fn run_server_on_listener(
    listener: tokio::net::TcpListener,
    config: ServerConfig,
    stop_flag: Arc<AtomicBool>,
    online_count: Arc<AtomicUsize>,
) {
    let mut admin_listener_opt = None;
    if config.admin_enabled {
        let admin_bind = format!("{}:{}", config.admin_bind_ip, config.admin_port);
        match tokio::net::TcpListener::bind(&admin_bind).await {
            Ok(al) => {
                admin_listener_opt = Some(al);
            }
            Err(e) => {
                eprintln!(
                    "[DDNeo-Server] Warnung: Admin-Webinterface konnte {} nicht binden: {}",
                    admin_bind, e
                );
            }
        }
    }
    run_server_with_admin_listener(listener, admin_listener_opt, config, stop_flag, online_count)
        .await;
}

pub async fn run_server_with_admin_listener(
    listener: tokio::net::TcpListener,
    admin_listener: Option<tokio::net::TcpListener>,
    config: ServerConfig,
    stop_flag: Arc<AtomicBool>,
    online_count: Arc<AtomicUsize>,
) {
    let bound_port = listener.local_addr().map(|a| a.port()).unwrap_or(config.tcp_port);

    if config.lan_discovery {
        let lan_stop = Arc::clone(&stop_flag);
        let lan_count = Arc::clone(&online_count);
        let lan_cfg = config.clone();
        tokio::spawn(async move {
            if let Ok(sock) = tokio::net::UdpSocket::bind(("0.0.0.0", LAN_DISCOVERY_PORT)).await {
                let mut buf = [0u8; 256];
                while !lan_stop.load(Ordering::Relaxed) {
                    if let Ok(Ok((n, src))) =
                        tokio::time::timeout(Duration::from_millis(400), sock.recv_from(&mut buf))
                            .await
                    {
                        if &buf[..n] == LAN_DISCOVER_MAGIC {
                            let reply = LanBeaconReply {
                                protocol_version: PROTOCOL_VERSION,
                                session_name: lan_cfg.session_name.clone(),
                                host_name: lan_cfg.host_name.clone(),
                                tcp_port: bound_port,
                                cur_players: lan_count.load(Ordering::Relaxed) as u8,
                                max_players: lan_cfg.max_players,
                                has_password: !lan_cfg.password.is_empty(),
                                is_dedicated: lan_cfg.is_dedicated,
                            };
                            if let Ok(bytes) = bincode::serialize(&reply) {
                                let _ = sock.send_to(&bytes, src).await;
                            }
                        }
                    }
                }
            }
        });
    }

    let (hub_tx, mut hub_rx) = tokio::sync::mpsc::unbounded_channel::<HubEvent>();
    let mut hub = ServerWorldHub::new(config.clone(), bound_port);

    if let Some(adm_listener) = admin_listener {
        let adm_tx = hub_tx.clone();
        let adm_stop = Arc::clone(&stop_flag);
        let auth = Arc::new(admin::AdminAuthStore::new(
            config.admin_username.clone(),
            config.admin_password.clone(),
            config.session_name.clone(),
        ));
        let dispatch: admin::AdminDispatchFn = Arc::new(move |cmd| {
            let (rtx, rrx) = tokio::sync::oneshot::channel();
            let _ = adm_tx.send(HubEvent::AdminRequest { cmd, reply_tx: rtx });
            rrx
        });
        tokio::spawn(async move {
            admin::run_admin_http_server(adm_listener, auth, dispatch, adm_stop).await;
        });
    }

    let accept_hub_tx = hub_tx.clone();
    let accept_stop = Arc::clone(&stop_flag);
    tokio::spawn(async move {
        while !accept_stop.load(Ordering::Relaxed) {
            let Ok(Ok((stream, peer_addr))) =
                tokio::time::timeout(Duration::from_millis(300), listener.accept()).await
            else {
                continue;
            };
            let peer_ip = peer_addr.ip().to_string();
            let _ = stream.set_nodelay(true);
            let h_tx = accept_hub_tx.clone();
            let p_stop = Arc::clone(&accept_stop);
            tokio::spawn(async move {
                let (mut rd, mut wr) = stream.into_split();
                let Ok(Ok(first_msg)) =
                    tokio::time::timeout(Duration::from_secs(5), read_packet::<NetClientMsg>(&mut rd))
                        .await
                else {
                    return;
                };
                if let NetClientMsg::ProbeServer {
                    protocol_version: _,
                    player_uid,
                } = first_msg
                {
                    let (rep_tx, rep_rx) = tokio::sync::oneshot::channel::<NetServerMsg>();
                    if h_tx
                        .send(HubEvent::ProbeQuery {
                            player_uid,
                            reply_tx: rep_tx,
                        })
                        .is_ok()
                    {
                        if let Ok(reply) = rep_rx.await {
                            let _ = write_packet(&mut wr, &reply).await;
                            let _ = tokio::io::AsyncWriteExt::flush(&mut wr).await;
                        }
                    }
                    return;
                }
                if matches!(first_msg, NetClientMsg::DeleteServerCharacter { .. }) {
                    let (rep_tx, rep_rx) = tokio::sync::oneshot::channel::<NetServerMsg>();
                    if h_tx
                        .send(HubEvent::DeleteCharacterQuery {
                            req: first_msg,
                            peer_ip,
                            reply_tx: rep_tx,
                        })
                        .is_ok()
                    {
                        if let Ok(reply) = rep_rx.await {
                            let _ = write_packet(&mut wr, &reply).await;
                            let _ = tokio::io::AsyncWriteExt::flush(&mut wr).await;
                        }
                    }
                    return;
                }
                let NetClientMsg::Hello { player_uid, .. } = &first_msg else {
                    return;
                };
                let uid = *player_uid;
                let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<NetServerMsg>();
                let (kick_tx, mut kick_rx) = tokio::sync::oneshot::channel::<()>();
                let (acc_tx, acc_rx) = tokio::sync::oneshot::channel::<bool>();
                if h_tx
                    .send(HubEvent::PeerConnected {
                        hello: first_msg,
                        peer_ip,
                        tx: out_tx,
                        kick_tx,
                        accept_tx: acc_tx,
                    })
                    .is_err()
                {
                    return;
                }
                let accepted = acc_rx.await.unwrap_or(false);

                let wr_stop = Arc::clone(&p_stop);
                let writer = tokio::spawn(async move {
                    while let Some(msg) = out_rx.recv().await {
                        if write_packet(&mut wr, &msg).await.is_err() {
                            break;
                        }
                        if wr_stop.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                });

                if accepted {
                    let mut kicked = false;
                    while !p_stop.load(Ordering::Relaxed) {
                        tokio::select! {
                            res = read_packet::<NetClientMsg>(&mut rd) => {
                                match res {
                                    Ok(pkt) => {
                                        if h_tx.send(HubEvent::PeerPacket { uid, msg: pkt }).is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                            _ = &mut kick_rx => {
                                kicked = true;
                                break;
                            }
                        }
                    }
                    if !kicked {
                        let _ = h_tx.send(HubEvent::PeerDisconnected { uid });
                    }
                }
                let _ = writer.await;
            });
        }
        let _ = accept_hub_tx.send(HubEvent::Shutdown);
    });

    let mut fast_tick = tokio::time::interval(Duration::from_millis(50)); // 20 Hz when active
    fast_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut macro_tick = tokio::time::interval(Duration::from_millis(1000)); // 1 Hz when active
    macro_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    while !stop_flag.load(Ordering::Relaxed) {
        let hibernating = hub.peers.is_empty() && hub.config.pause_when_empty;

        if hibernating {
            // 0% CPU Hibernation Mode on 1–2 Core VPS: sleep completely until a TCP client connects or stop_flag triggers!
            match tokio::time::timeout(Duration::from_secs(2), hub_rx.recv()).await {
                Ok(Some(ev)) => {
                    if !process_hub_event(&mut hub, ev, &online_count) {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    if stop_flag.load(Ordering::Relaxed) {
                        break;
                    }
                }
            }
        } else {
            tokio::select! {
                Some(ev) = hub_rx.recv() => {
                    if !process_hub_event(&mut hub, ev, &online_count) {
                        break;
                    }
                }
                _ = fast_tick.tick(), if !hub.peers.is_empty() => {
                    hub.publish_local_bubbles();
                }
                _ = macro_tick.tick() => {
                    hub.step_macro_second();
                }
            }
        }
    }

    hub.save_if_needed(true);
    if config.is_dedicated {
        println!("[DDNeo-Server] Weltstatus sauber gespeichert. Server beendet.");
    }
}

fn process_hub_event(
    hub: &mut ServerWorldHub,
    ev: HubEvent,
    online_count: &Arc<AtomicUsize>,
) -> bool {
    match ev {
        HubEvent::Shutdown => return false,
        HubEvent::ProbeQuery {
            player_uid,
            reply_tx,
        } => {
            let existing_character = hub.characters.get(&player_uid).map(|ch| {
                ServerCharacterSummary {
                    player_name: ch.player_name.clone(),
                    level: ch.level,
                    role_id: ch.role_id,
                    appearance_bytes: ch.appearance_bytes,
                    last_merc_x: ch.last_merc_x,
                    last_merc_y: ch.last_merc_y,
                }
            });
            let active_online = hub
                .peers
                .values()
                .filter(|p| !p.awaiting_creation)
                .count()
                .min(255) as u8;
            let _ = reply_tx.send(NetServerMsg::ServerProbeReply {
                protocol_version: PROTOCOL_VERSION,
                server_name: hub.config.session_name.clone(),
                cur_players: active_online,
                max_players: hub.config.max_players,
                has_password: !hub.config.password.is_empty(),
                is_dedicated: hub.config.is_dedicated,
                existing_character,
            });
        }
        HubEvent::DeleteCharacterQuery {
            req,
            peer_ip,
            reply_tx,
        } => {
            if let NetClientMsg::DeleteServerCharacter {
                protocol_version,
                player_uid,
                password,
                pubkey,
                auth_timestamp_ms,
                sig_r,
                sig_s,
            } = req
            {
                if protocol_version != PROTOCOL_VERSION {
                    let _ = reply_tx.send(NetServerMsg::CharacterDeleteReply {
                        ok: false,
                        deleted_name: String::new(),
                        message: format!(
                            "Protokoll-Version inkompatibel (Server v{}, Client v{})",
                            PROTOCOL_VERSION, protocol_version
                        ),
                    });
                    return true;
                }
                if let Some(ban_msg) = hub.check_ban_reason(player_uid, &pubkey, &peer_ip) {
                    let _ = reply_tx.send(NetServerMsg::CharacterDeleteReply {
                        ok: false,
                        deleted_name: String::new(),
                        message: ban_msg,
                    });
                    return true;
                }
                if !hub.config.password.is_empty() && password != hub.config.password {
                    let _ = reply_tx.send(NetServerMsg::CharacterDeleteReply {
                        ok: false,
                        deleted_name: String::new(),
                        message: "Falsches Server-Passwort!".to_string(),
                    });
                    return true;
                }
                if let Err(err) = hub.verify_and_bind_uid(
                    player_uid,
                    &pubkey,
                    AUTH_ACTION_DELETE_CHAR,
                    auth_timestamp_ms,
                    &sig_r,
                    &sig_s,
                ) {
                    let _ = reply_tx.send(NetServerMsg::CharacterDeleteReply {
                        ok: false,
                        deleted_name: String::new(),
                        message: err,
                    });
                    return true;
                }
                let Some(deleted_name) = hub
                    .characters
                    .get(&player_uid)
                    .map(|c| c.player_name.clone())
                else {
                    let _ = reply_tx.send(NetServerMsg::CharacterDeleteReply {
                        ok: false,
                        deleted_name: String::new(),
                        message: "Kein gespeicherter Charakter auf diesem Server gefunden."
                            .to_string(),
                    });
                    return true;
                };
                if hub.peers.contains_key(&player_uid) {
                    hub.handle_disconnect(player_uid);
                    online_count.store(hub.peers.len(), Ordering::Relaxed);
                }
                hub.purge_character_for_reset(player_uid);
                hub.save_if_needed(true);
                hub.publish_macro_sync();
                hub.log_event(format!(
                    "Charakter '{}' (UID {}) per Spielersignatur gelöscht.",
                    deleted_name, player_uid
                ));
                if hub.config.is_dedicated {
                    println!(
                        "[DDNeo-Server] Charakter '{}' (UID {}) per Ed25519-Signatur gelöscht.",
                        deleted_name, player_uid
                    );
                }
                let _ = reply_tx.send(NetServerMsg::CharacterDeleteReply {
                    ok: true,
                    deleted_name: deleted_name.clone(),
                    message: format!(
                        "Charakter '{}' wurde erfolgreich auf Server '{}' gelöscht.",
                        deleted_name, hub.config.session_name
                    ),
                });
            }
        }
        HubEvent::PeerConnected {
            hello,
            peer_ip,
            tx,
            kick_tx,
            accept_tx,
        } => {
            if let NetClientMsg::Hello {
                protocol_version,
                player_uid,
                name,
                password,
                level: _,
                role_id,
                appearance_bytes,
                net_pos,
                reset_character,
                pubkey,
                auth_timestamp_ms,
                sig_r,
                sig_s,
            } = hello
            {
                if protocol_version != PROTOCOL_VERSION {
                    let _ = tx.send(NetServerMsg::Rejected {
                        reason: format!(
                            "Protokoll-Version inkompatibel (Server v{}, Client v{})",
                            PROTOCOL_VERSION, protocol_version
                        ),
                    });
                    let _ = accept_tx.send(false);
                    return true;
                }
                if let Some(ban_msg) = hub.check_ban_reason(player_uid, &pubkey, &peer_ip) {
                    hub.log_event(format!(
                        "[Sperre] Verbindungsversuch von UID {} ({}) abgelehnt.",
                        player_uid, peer_ip
                    ));
                    let _ = tx.send(NetServerMsg::Rejected { reason: ban_msg });
                    let _ = accept_tx.send(false);
                    return true;
                }
                if !hub.config.password.is_empty() && password != hub.config.password {
                    let _ = tx.send(NetServerMsg::Rejected {
                        reason: "Falsches Server-Passwort!".to_string(),
                    });
                    let _ = accept_tx.send(false);
                    return true;
                }
                if let Err(err) = hub.verify_and_bind_uid(
                    player_uid,
                    &pubkey,
                    AUTH_ACTION_HELLO,
                    auth_timestamp_ms,
                    &sig_r,
                    &sig_s,
                ) {
                    let _ = tx.send(NetServerMsg::Rejected { reason: err });
                    let _ = accept_tx.send(false);
                    return true;
                }
                let is_reconnect = hub.peers.contains_key(&player_uid);
                if !is_reconnect && hub.peers.len() >= hub.config.max_players as usize {
                    let _ = tx.send(NetServerMsg::Rejected {
                        reason: format!(
                            "Server voll ({}/{} Spieler)!",
                            hub.peers.len(),
                            hub.config.max_players
                        ),
                    });
                    let _ = accept_tx.send(false);
                    return true;
                }

                hub.player_meta.insert(
                    player_uid,
                    admin::PlayerAdminMeta {
                        last_ip: peer_ip.clone(),
                        last_seen_unix_secs: current_unix_ms() / 1000,
                        device_fingerprint: format_pubkey_fingerprint(&pubkey),
                    },
                );

                let existing_guild = if reset_character {
                    None
                } else {
                    hub.find_player_guild(player_uid)
                };
                let (gid, grole, gname) = existing_guild
                    .map(|(id, r, n)| (Some(id), r, n))
                    .unwrap_or((None, PlayerGuildRole::Founder, String::new()));

                let saved_char = if reset_character {
                    None
                } else {
                    hub.characters.get(&player_uid).cloned()
                };
                let awaiting_creation =
                    reset_character || (saved_char.is_none() && name.trim().is_empty());
                let (eff_name, eff_lvl, eff_role, eff_app, eff_pos) =
                    if let Some(ref sc) = saved_char {
                        (
                            sc.player_name.clone(),
                            sc.level,
                            sc.role_id,
                            sc.appearance_bytes,
                            NetWorldPos::Overworld {
                                merc_x: sc.last_merc_x,
                                merc_y: sc.last_merc_y,
                            },
                        )
                    } else {
                        (name.trim().to_string(), 1, role_id, appearance_bytes, net_pos)
                    };

                if !awaiting_creation {
                    if let Some(id) = gid {
                        if let Some(g) = hub.guilds.get_mut(&id) {
                            for m in &mut g.members {
                                if m.uid == player_uid {
                                    m.online = true;
                                    m.name = eff_name.clone();
                                    m.level = eff_lvl;
                                }
                            }
                        }
                    }
                }

                let snap = NetPlayerSnapshot {
                    uid: player_uid,
                    name: eff_name.clone(),
                    level: eff_lvl,
                    role_id: eff_role,
                    guild_id: gid,
                    guild_name: gname,
                    guild_role: grole,
                    appearance_bytes: eff_app,
                    net_pos: eff_pos,
                    vel: [0.0, 0.0],
                    aim_dir: [1.0, 0.0],
                    hp: 100.0,
                    max_hp: 100.0,
                    driving_vehicle_id: None,
                    riding_vehicle_id: None,
                    attack_pulse: 0,
                };

                let _ = tx.send(NetServerMsg::Welcome {
                    server_name: hub.config.session_name.clone(),
                    max_players: hub.config.max_players,
                    world_seed: hub.world_seed,
                    world_hour: hub.world_hour,
                    world_tier: hub.world_tier,
                    world_level_offset: hub.world_level_offset,
                    is_dedicated: hub.config.is_dedicated,
                    assigned_guild_id: gid,
                    assigned_guild_role: grole,
                    sealed_portals: hub.sealed_portals.iter().copied().collect(),
                    stabilized_portals: hub.stabilized_portals.iter().copied().collect(),
                    saved_character: saved_char,
                });

                // Immediately push all server-authoritative Overworld chunk Rifts so newly joining
                // clients (even without local OSM region data) see identical Rifts & monster kills!
                for &(cx, cy) in hub.chunk_rifts.keys() {
                    if let Some(sync_msg) = hub.build_chunk_rifts_sync_msg(cx, cy) {
                        let _ = tx.send(sync_msg);
                    }
                }

                hub.peers.insert(
                    player_uid,
                    ConnectedPeer {
                        uid: player_uid,
                        tx,
                        kick_tx: Some(kick_tx),
                        snap,
                        awaiting_creation,
                        reset_on_creation: reset_character,
                        peer_ip,
                    },
                );
                online_count.store(hub.peers.len(), Ordering::Relaxed);
                let _ = accept_tx.send(true);

                if !awaiting_creation {
                    hub.log_event(format!(
                        "Spieler '{}' (UID {}) beigetreten.",
                        eff_name, player_uid
                    ));
                    if hub.config.is_dedicated {
                        println!(
                            "[DDNeo-Server] Spieler verbunden: '{}' (UID {}, {}/{} online)",
                            eff_name,
                            player_uid,
                            hub.peers.values().filter(|p| !p.awaiting_creation).count(),
                            hub.config.max_players
                        );
                    }
                    hub.broadcast_all(&NetServerMsg::ChatBroadcast {
                        sender: "Server".to_string(),
                        text: format!("{} ist der Welt beigetreten!", eff_name),
                        is_system: true,
                    });
                }
                hub.publish_macro_sync();
                hub.write_status_json();
            }
        }
        HubEvent::PeerPacket { uid, msg } => {
            hub.handle_msg(uid, msg);
        }
        HubEvent::PeerDisconnected { uid } => {
            if let Some(m) = hub.player_meta.get_mut(&uid) {
                m.last_seen_unix_secs = current_unix_ms() / 1000;
            }
            hub.handle_disconnect(uid);
            online_count.store(hub.peers.len(), Ordering::Relaxed);
        }
        HubEvent::AdminRequest { cmd, reply_tx } => {
            let res = hub.execute_admin_command(cmd, online_count);
            let _ = reply_tx.send(res);
        }
    }
    true
}

// =====================================================================
// BACKGROUND SERVER HANDLE (Used by In-Game Host & Unit Tests)
// =====================================================================
pub struct RunningServerHandle {
    pub bound_addr: SocketAddr,
    pub admin_bound_addr: Option<SocketAddr>,
    pub max_players: u8,
    pub session_name: String,
    stop_flag: Arc<AtomicBool>,
    online_count: Arc<AtomicUsize>,
    join_handle: Option<std::thread::JoinHandle<()>>,
}

impl RunningServerHandle {
    pub fn start(config: ServerConfig) -> Result<Self, String> {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let online_count = Arc::new(AtomicUsize::new(0));
        let (addr_tx, addr_rx) =
            std::sync::mpsc::channel::<Result<(SocketAddr, Option<SocketAddr>), String>>();

        let stop_clone = Arc::clone(&stop_flag);
        let count_clone = Arc::clone(&online_count);
        let cfg_clone = config.clone();

        let jh = std::thread::Builder::new()
            .name("ddneo-mp-server".to_string())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = addr_tx.send(Err(format!("Tokio-Runtime Fehler: {}", e)));
                        return;
                    }
                };

                rt.block_on(async move {
                    let bind_str = format!("{}:{}", cfg_clone.bind_ip, cfg_clone.tcp_port);
                    let listener = match tokio::net::TcpListener::bind(&bind_str).await {
                        Ok(l) => l,
                        Err(e) => {
                            let _ = addr_tx.send(Err(format!(
                                "Port {} konnte nicht gebunden werden: {}",
                                bind_str, e
                            )));
                            return;
                        }
                    };
                    let local_addr = match listener.local_addr() {
                        Ok(a) => a,
                        Err(e) => {
                            let _ = addr_tx.send(Err(e.to_string()));
                            return;
                        }
                    };

                    let mut admin_listener_opt = None;
                    let mut admin_addr_opt = None;
                    if cfg_clone.admin_enabled {
                        let adm_str =
                            format!("{}:{}", cfg_clone.admin_bind_ip, cfg_clone.admin_port);
                        if let Ok(al) = tokio::net::TcpListener::bind(&adm_str).await {
                            admin_addr_opt = al.local_addr().ok();
                            admin_listener_opt = Some(al);
                        }
                    }

                    let _ = addr_tx.send(Ok((local_addr, admin_addr_opt)));
                    run_server_with_admin_listener(
                        listener,
                        admin_listener_opt,
                        cfg_clone,
                        stop_clone,
                        count_clone,
                    )
                    .await;
                });
            })
            .map_err(|e| e.to_string())?;

        let (bound_addr, admin_bound_addr) = addr_rx
            .recv_timeout(Duration::from_secs(4))
            .map_err(|_| "Timeout beim Starten des Servers".to_string())??;

        Ok(Self {
            bound_addr,
            admin_bound_addr,
            max_players: config.max_players,
            session_name: config.session_name,
            stop_flag,
            online_count,
            join_handle: Some(jh),
        })
    }

    pub fn online_players(&self) -> usize {
        self.online_count.load(Ordering::Relaxed)
    }

    pub fn shutdown(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(jh) = self.join_handle.take() {
            let _ = jh.join();
        }
    }
}

impl Drop for RunningServerHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dedicated_server_persists_world_across_restart_and_hibernates_cleanly() {
        let tmp_dir = std::env::temp_dir().join(format!("ddneo_srv_test_{}", rand::random::<u32>()));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let world_file = tmp_dir.join("server_world.bin");
        let status_file = tmp_dir.join("server_status.json");

        let cfg = ServerConfig {
            bind_ip: "127.0.0.1".to_string(),
            tcp_port: 0,
            max_players: 12,
            session_name: "VPS-Persistenz-Test".to_string(),
            host_name: "LinuxVPS".to_string(),
            password: String::new(),
            lan_discovery: false,
            is_dedicated: true,
            pause_when_empty: true,
            save_interval_secs: 5,
            world_save_path: Some(world_file.to_string_lossy().to_string()),
            status_json_path: Some(status_file.to_string_lossy().to_string()),
            ingame_day_real_secs: 1440.0,
            ..Default::default()
        };

        let owner_seed = [0x42u8; 32];
        let attacker_seed = [0x99u8; 32];

        // 1. Start Dedicated Server #1, connect a player with Ed25519 signature, found a guild + seal portal 999, then shut down!
        let first_seed;
        {
            let mut srv1 = RunningServerHandle::start(cfg.clone()).expect("Server 1 bind");
            let addr = srv1.bound_addr;

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            first_seed = rt.block_on(async {
                let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
                let (mut rd, mut wr) = stream.into_split();
                let ts = current_unix_ms();
                let (pubkey, sig_r, sig_s) =
                    sign_auth_action(&owner_seed, AUTH_ACTION_HELLO, 555, ts);
                write_packet(
                    &mut wr,
                    &NetClientMsg::Hello {
                        protocol_version: PROTOCOL_VERSION,
                        player_uid: 555,
                        name: "VpsFounder".to_string(),
                        password: String::new(),
                        level: 14,
                        role_id: 0,
                        appearance_bytes: [7u8; 24],
                        net_pos: NetWorldPos::Overworld {
                            merc_x: 1_492_000.0,
                            merc_y: 6_894_000.0,
                        },
                        reset_character: false,
                        pubkey,
                        auth_timestamp_ms: ts,
                        sig_r,
                        sig_s,
                    },
                )
                .await
                .unwrap();

                let welcome = read_packet::<NetServerMsg>(&mut rd).await.unwrap();
                let seed = match welcome {
                    NetServerMsg::Welcome {
                        world_seed,
                        is_dedicated,
                        saved_character,
                        ..
                    } => {
                        assert!(is_dedicated);
                        assert!(
                            saved_character.is_none(),
                            "Brand-new player on server must NOT inherit offline character"
                        );
                        world_seed
                    }
                    other => panic!("Expected Welcome, got {:?}", other),
                };

                write_packet(
                    &mut wr,
                    &NetClientMsg::SyncCharacter(WireServerCharacter {
                        player_uid: 555,
                        player_name: "VpsFounder".to_string(),
                        level: 7,
                        role_id: 2,
                        appearance_bytes: [7u8; 24],
                        last_merc_x: 1_492_050.0,
                        last_merc_y: 6_894_080.0,
                        character_bincode: vec![42, 99, 101],
                    }),
                )
                .await
                .unwrap();

                write_packet(
                    &mut wr,
                    &NetClientMsg::FoundPlayerGuild {
                        name: "Eiserne Wacht".to_string(),
                        initial_bases: vec![WireClaimedBase {
                            guild_id: None,
                            owner_uid: 555,
                            building_id: 42001,
                            name: "Hauptquartier".to_string(),
                            module_count: 3,
                            origin_merc_x: 1_492_000.0,
                            origin_merc_y: 6_894_000.0,
                            origin_meter_scale: 0.61,
                            door_merc_x: 1_492_010.0,
                            door_merc_y: 6_894_020.0,
                            base_bincode: vec![1, 2, 3, 4],
                        }],
                        initial_vehicles: Vec::new(),
                        npc_guild_bincode: vec![9, 9],
                        completed_research: vec!["power_grid_tech".to_string()],
                        active_research_bincode: None,
                    },
                )
                .await
                .unwrap();

                write_packet(
                    &mut wr,
                    &NetClientMsg::PortalSealed {
                        seed: 999,
                        stabilized: false,
                    },
                )
                .await
                .unwrap();

                tokio::time::sleep(Duration::from_millis(80)).await;
                seed
            });

            srv1.shutdown();
        }

        assert!(world_file.exists(), "server_world.bin must exist after shutdown");
        assert!(status_file.exists(), "server_status.json must exist");

        // 2. Reboot Dedicated Server #2 -> verify guild, base, seed, sealed portal, spoof protection & signed character deletion!
        {
            let mut srv2 = RunningServerHandle::start(cfg).expect("Server 2 bind");
            let addr = srv2.bound_addr;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                // 2a. Attacker with different Ed25519 key attempting to hijack UID 555 MUST be rejected!
                {
                    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
                    let (mut rd, mut wr) = stream.into_split();
                    let ts = current_unix_ms();
                    let (atk_pk, atk_r, atk_s) =
                        sign_auth_action(&attacker_seed, AUTH_ACTION_HELLO, 555, ts);
                    write_packet(
                        &mut wr,
                        &NetClientMsg::Hello {
                            protocol_version: PROTOCOL_VERSION,
                            player_uid: 555,
                            name: "Spoofer".to_string(),
                            password: String::new(),
                            level: 99,
                            role_id: 0,
                            appearance_bytes: [0u8; 24],
                            net_pos: NetWorldPos::default(),
                            reset_character: false,
                            pubkey: atk_pk,
                            auth_timestamp_ms: ts,
                            sig_r: atk_r,
                            sig_s: atk_s,
                        },
                    )
                    .await
                    .unwrap();
                    let rej = read_packet::<NetServerMsg>(&mut rd).await.unwrap();
                    assert!(
                        matches!(rej, NetServerMsg::Rejected { .. }),
                        "Spoofed Hello with wrong Ed25519 key must be rejected!"
                    );
                }

                // 2b. Attacker attempting signed DeleteServerCharacter on UID 555 MUST fail!
                {
                    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
                    let (mut rd, mut wr) = stream.into_split();
                    let ts = current_unix_ms();
                    let (atk_pk, atk_r, atk_s) =
                        sign_auth_action(&attacker_seed, AUTH_ACTION_DELETE_CHAR, 555, ts);
                    write_packet(
                        &mut wr,
                        &NetClientMsg::DeleteServerCharacter {
                            protocol_version: PROTOCOL_VERSION,
                            player_uid: 555,
                            password: String::new(),
                            pubkey: atk_pk,
                            auth_timestamp_ms: ts,
                            sig_r: atk_r,
                            sig_s: atk_s,
                        },
                    )
                    .await
                    .unwrap();
                    let rep = read_packet::<NetServerMsg>(&mut rd).await.unwrap();
                    match rep {
                        NetServerMsg::CharacterDeleteReply { ok, .. } => {
                            assert!(!ok, "Spoofed DeleteServerCharacter must be rejected!");
                        }
                        other => panic!("Expected CharacterDeleteReply, got {:?}", other),
                    }
                }

                // 2c. Legitimate owner reconnects -> receives full persisted character & guild!
                {
                    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
                    let (mut rd, mut wr) = stream.into_split();
                    let ts = current_unix_ms();
                    let (pubkey, sig_r, sig_s) =
                        sign_auth_action(&owner_seed, AUTH_ACTION_HELLO, 555, ts);
                    write_packet(
                        &mut wr,
                        &NetClientMsg::Hello {
                            protocol_version: PROTOCOL_VERSION,
                            player_uid: 555,
                            name: "VpsFounder".to_string(),
                            password: String::new(),
                            level: 14,
                            role_id: 0,
                            appearance_bytes: [7u8; 24],
                            net_pos: NetWorldPos::Overworld {
                                merc_x: 1_492_000.0,
                                merc_y: 6_894_000.0,
                            },
                            reset_character: false,
                            pubkey,
                            auth_timestamp_ms: ts,
                            sig_r,
                            sig_s,
                        },
                    )
                    .await
                    .unwrap();

                    let welcome = read_packet::<NetServerMsg>(&mut rd).await.unwrap();
                    match welcome {
                        NetServerMsg::Welcome {
                            world_seed,
                            assigned_guild_id,
                            assigned_guild_role,
                            sealed_portals,
                            saved_character,
                            ..
                        } => {
                            assert_eq!(world_seed, first_seed, "World seed must persist across VPS reboot");
                            assert_eq!(assigned_guild_id, Some(1), "Guild membership must persist");
                            assert_eq!(assigned_guild_role, PlayerGuildRole::Founder);
                            assert!(sealed_portals.contains(&999), "Sealed portals must persist");
                            let sc = saved_character
                                .expect("Server-stored online character must be returned on reconnect");
                            assert_eq!(sc.level, 7);
                            assert_eq!(sc.character_bincode, vec![42, 99, 101]);
                        }
                        other => panic!("Expected Welcome on reboot, got {:?}", other),
                    }
                }

                // 2d. Legitimate owner sends signed DeleteServerCharacter from Character Manager -> character & guild purged!
                {
                    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
                    let (mut rd, mut wr) = stream.into_split();
                    let ts = current_unix_ms();
                    let (pubkey, sig_r, sig_s) =
                        sign_auth_action(&owner_seed, AUTH_ACTION_DELETE_CHAR, 555, ts);
                    write_packet(
                        &mut wr,
                        &NetClientMsg::DeleteServerCharacter {
                            protocol_version: PROTOCOL_VERSION,
                            player_uid: 555,
                            password: String::new(),
                            pubkey,
                            auth_timestamp_ms: ts,
                            sig_r,
                            sig_s,
                        },
                    )
                    .await
                    .unwrap();
                    let rep = read_packet::<NetServerMsg>(&mut rd).await.unwrap();
                    match rep {
                        NetServerMsg::CharacterDeleteReply {
                            ok, deleted_name, ..
                        } => {
                            assert!(ok, "Valid owner signature must delete character");
                            assert_eq!(deleted_name, "VpsFounder");
                        }
                        other => panic!("Expected CharacterDeleteReply, got {:?}", other),
                    }
                }

                // 2e. ProbeServer confirms character 555 is now None!
                {
                    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
                    let (mut rd, mut wr) = stream.into_split();
                    write_packet(
                        &mut wr,
                        &NetClientMsg::ProbeServer {
                            protocol_version: PROTOCOL_VERSION,
                            player_uid: 555,
                        },
                    )
                    .await
                    .unwrap();
                    let probe = read_packet::<NetServerMsg>(&mut rd).await.unwrap();
                    match probe {
                        NetServerMsg::ServerProbeReply {
                            existing_character, ..
                        } => {
                            assert!(
                                existing_character.is_none(),
                                "Deleted server character must no longer appear in ProbeServer"
                            );
                        }
                        other => panic!("Expected ServerProbeReply, got {:?}", other),
                    }
                }
            });
            srv2.shutdown();
        }

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_admin_web_panel_login_device_ban_world_tier_area_reset_and_backups() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let tmp_dir =
            std::env::temp_dir().join(format!("ddneo_adm_test_{}", rand::random::<u32>()));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let world_file = tmp_dir.join("server_world.bin");
        let status_file = tmp_dir.join("server_status.json");

        let cfg = ServerConfig {
            bind_ip: "127.0.0.1".to_string(),
            tcp_port: 0,
            session_name: "AdminWebTest".to_string(),
            world_save_path: Some(world_file.to_string_lossy().to_string()),
            status_json_path: Some(status_file.to_string_lossy().to_string()),
            admin_enabled: true,
            admin_bind_ip: "127.0.0.1".to_string(),
            admin_port: 0,
            admin_username: "burns_admin".to_string(),
            admin_password: "SuperSecretConfigPass!".to_string(),
            ..Default::default()
        };

        let mut srv = RunningServerHandle::start(cfg).expect("Start server with admin HTTP");
        let game_addr = srv.bound_addr;
        let adm_addr = srv.admin_bound_addr.expect("Admin HTTP port must bind");

        async fn raw_http(
            addr: SocketAddr,
            method: &str,
            path: &str,
            cookie: Option<&str>,
            csrf: Option<&str>,
            body: Option<&str>,
        ) -> (u16, String, String) {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            let b = body.unwrap_or("");
            let mut req = format!(
                "{} {} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n",
                method,
                path,
                b.len()
            );
            if body.is_some() {
                req.push_str("Content-Type: application/json\r\n");
            }
            if let Some(c) = cookie {
                req.push_str(&format!("Cookie: ddneo_admin_session={}\r\n", c));
            }
            if let Some(t) = csrf {
                req.push_str(&format!("X-CSRF-Token: {}\r\n", t));
            }
            req.push_str("\r\n");
            req.push_str(b);
            s.write_all(req.as_bytes()).await.unwrap();
            let mut resp = Vec::new();
            s.read_to_end(&mut resp).await.unwrap();
            let txt = String::from_utf8_lossy(&resp).to_string();
            let (hdrs, body_out) = txt.split_once("\r\n\r\n").unwrap_or((&txt, ""));
            let code = hdrs
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|c| c.parse::<u16>().ok())
                .unwrap_or(500);
            let mut set_cookie_tok = String::new();
            for line in hdrs.lines() {
                if line.to_ascii_lowercase().starts_with("set-cookie:") {
                    if let Some(rest) = line.split("ddneo_admin_session=").nth(1) {
                        set_cookie_tok = rest.split(';').next().unwrap_or("").to_string();
                    }
                }
            }
            (code, set_cookie_tok, body_out.to_string())
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // 1. Unauthenticated dashboard request MUST return 401
            let (code, _, _) = raw_http(adm_addr, "GET", "/api/dashboard", None, None, None).await;
            assert_eq!(code, 401);

            // 2. Wrong password MUST return 401
            let (code_bad, _, _) = raw_http(
                adm_addr,
                "POST",
                "/api/login",
                None,
                None,
                Some(r#"{"username":"burns_admin","password":"wrong"}"#),
            )
            .await;
            assert_eq!(code_bad, 401);

            // 3. Correct config credentials succeed & issue session cookie + CSRF token
            let (code_ok, sess_cookie, login_json) = raw_http(
                adm_addr,
                "POST",
                "/api/login",
                None,
                None,
                Some(r#"{"username":"burns_admin","password":"SuperSecretConfigPass!"}"#),
            )
            .await;
            assert_eq!(code_ok, 200);
            assert!(!sess_cookie.is_empty());
            let lj: serde_json::Value = serde_json::from_str(&login_json).unwrap();
            let csrf = lj["csrf_token"].as_str().unwrap().to_string();

            // 4. Connect a player ('Griefer', UID 777) with hardware-anchored Ed25519 key
            let griefer_seed = [0x77u8; 32];
            let ts = current_unix_ms();
            let (g_pk, g_r, g_s) = sign_auth_action(&griefer_seed, AUTH_ACTION_HELLO, 777, ts);
            let g_fp = format_pubkey_fingerprint(&g_pk);

            let stream = tokio::net::TcpStream::connect(game_addr).await.unwrap();
            let (mut rd, mut wr) = stream.into_split();
            write_packet(
                &mut wr,
                &NetClientMsg::Hello {
                    protocol_version: PROTOCOL_VERSION,
                    player_uid: 777,
                    name: "Griefer".to_string(),
                    password: String::new(),
                    level: 1,
                    role_id: 0,
                    appearance_bytes: [1u8; 24],
                    net_pos: NetWorldPos::Overworld {
                        merc_x: 1_492_000.0,
                        merc_y: 6_894_000.0,
                    },
                    reset_character: false,
                    pubkey: g_pk,
                    auth_timestamp_ms: ts,
                    sig_r: g_r,
                    sig_s: g_s,
                },
            )
            .await
            .unwrap();
            let _welcome = read_packet::<NetServerMsg>(&mut rd).await.unwrap();

            // Report a base-level 6 rift in chunk (994, 4596)
            write_packet(
                &mut wr,
                &NetClientMsg::ReportChunkRifts {
                    chunk_x: 994,
                    chunk_y: 4596,
                    from_real_osm: true,
                    rifts: vec![WireOverworldRift {
                        id: 12345,
                        merc_x: 1_492_000.0,
                        merc_y: 6_894_000.0,
                        theme: "Feuer".to_string(),
                        color_rgba: [1.0, 0.2, 0.2, 1.0],
                        base_level: 6,
                        level: 6,
                        max_floors: 3,
                    }],
                },
            )
            .await
            .unwrap();
            tokio::time::sleep(Duration::from_millis(60)).await;

            // 5. Raise World Tier to 4 (+9 levels -> rift 12345 becomes level 15!) and lower to 0 (halved -> level 3!)
            let (c_tier, _, tier_body) = raw_http(
                adm_addr,
                "POST",
                "/api/action",
                Some(&sess_cookie),
                Some(&csrf),
                Some(r#"{"type":"SetWorldDifficulty","world_tier":4,"world_level_offset":0}"#),
            )
            .await;
            assert_eq!(c_tier, 200);
            let tj: serde_json::Value = serde_json::from_str(&tier_body).unwrap();
            assert_eq!(tj["state"]["world_tier"], 4);
            assert_eq!(tj["state"]["rifts_preview"][0]["level"], 15);

            // 6. Create backup before banning & resetting
            let (c_bk, _, bk_body) = raw_http(
                adm_addr,
                "POST",
                "/api/action",
                Some(&sess_cookie),
                Some(&csrf),
                Some(r#"{"type":"CreateBackup","label":"autotest"}"#),
            )
            .await;
            assert_eq!(c_bk, 200);
            let bkj: serde_json::Value = serde_json::from_str(&bk_body).unwrap();
            assert_eq!(bkj["state"]["backups"].as_array().unwrap().len(), 1);

            // 7. Ban Griefer by Device-ID! Verify live session is immediately kicked AND reconnect even with NEW UID/Name is blocked by Device-ID!
            let ban_req = serde_json::json!({
                "type": "BanDevice",
                "player_uid": 777,
                "pubkey_hex": "",
                "device_fingerprint": "",
                "ip_address": null,
                "player_name": "Griefer",
                "reason": "Griefing im Test",
                "delete_character": false
            })
            .to_string();
            let (c_ban, _, _) = raw_http(
                adm_addr,
                "POST",
                "/api/action",
                Some(&sess_cookie),
                Some(&csrf),
                Some(&ban_req),
            )
            .await;
            assert_eq!(c_ban, 200);

            // Attempt reconnect with SAME hardware Ed25519 key (`griefer_seed`), even pretending a different name/UID -> MUST BE REJECTED!
            let stream2 = tokio::net::TcpStream::connect(game_addr).await.unwrap();
            let (mut rd2, mut wr2) = stream2.into_split();
            let ts2 = current_unix_ms();
            let (g_pk2, g_r2, g_s2) = sign_auth_action(&griefer_seed, AUTH_ACTION_HELLO, 888, ts2);
            write_packet(
                &mut wr2,
                &NetClientMsg::Hello {
                    protocol_version: PROTOCOL_VERSION,
                    player_uid: 888,
                    name: "NeuerNameGleichesGeraet".to_string(),
                    password: String::new(),
                    level: 1,
                    role_id: 0,
                    appearance_bytes: [1u8; 24],
                    net_pos: NetWorldPos::default(),
                    reset_character: false,
                    pubkey: g_pk2,
                    auth_timestamp_ms: ts2,
                    sig_r: g_r2,
                    sig_s: g_s2,
                },
            )
            .await
            .unwrap();
            let rej = read_packet::<NetServerMsg>(&mut rd2).await.unwrap();
            match rej {
                NetServerMsg::Rejected { reason } => {
                    assert!(
                        reason.contains(&g_fp) && reason.contains("Griefing im Test"),
                        "Expected Device-ID ban rejection, got: {}",
                        reason
                    );
                }
                other => panic!("Expected Rejected for banned Device-ID, got {:?}", other),
            }

            // 8. Reset Area & Regenerate World via Admin API
            let (c_ar, _, _) = raw_http(
                adm_addr,
                "POST",
                "/api/action",
                Some(&sess_cookie),
                Some(&csrf),
                Some(r#"{"type":"ResetArea","lat":52.52,"lon":13.40,"radius_km":3.0,"reset_rifts":true,"restore_buildings":true,"remove_vehicles":false,"remove_bases":false}"#),
            )
            .await;
            assert_eq!(c_ar, 200);

            let (c_reg, _, reg_body) = raw_http(
                adm_addr,
                "POST",
                "/api/action",
                Some(&sess_cookie),
                Some(&csrf),
                Some(r#"{"type":"RegenerateWorld","new_seed":987654321,"keep_characters":false}"#),
            )
            .await;
            assert_eq!(c_reg, 200);
            let rj: serde_json::Value = serde_json::from_str(&reg_body).unwrap();
            assert_eq!(rj["state"]["world_seed"], 987654321);
            // Device-ID ban list MUST survive world regeneration!
            assert_eq!(rj["state"]["bans"].as_array().unwrap().len(), 1);
        });

        srv.shutdown();
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
