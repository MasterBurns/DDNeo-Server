use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const DEFAULT_SERVER_PORT: u16 = 27777;
pub const LAN_DISCOVERY_PORT: u16 = 27778;
pub const DEFAULT_EMBEDDED_MAX_PLAYERS: u8 = 4;
pub const DEFAULT_DEDICATED_MAX_PLAYERS: u8 = 12;
pub const PROTOCOL_VERSION: u32 = 6;
pub const LAN_DISCOVER_MAGIC: &[u8] = b"DDNEO_DISCOVER_V6";

const EARTH_RADIUS_M: f64 = 6_378_137.0;
const LOCAL_INTEREST_RADIUS_M: f64 = 1_850.0;

#[inline]
pub fn merc_to_lat_lon_deg(mx: f64, my: f64) -> (f64, f64) {
    let lon = (mx / EARTH_RADIUS_M).to_degrees();
    let lat = (2.0 * (my / EARTH_RADIUS_M).exp().atan() - std::f64::consts::FRAC_PI_2).to_degrees();
    (lat, lon)
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
    Welcome {
        server_name: String,
        max_players: u8,
        world_seed: u64,
        world_hour: f32,
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
        players: Vec<NetPlayerSnapshot>,
        character_directory: Vec<NetCharacterDirectoryEntry>,
        guilds: Vec<WirePlayerGuild>,
        all_vehicles: Vec<WireVehicle>,
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
}

fn default_bind_ip() -> String {
    "0.0.0.0".to_string()
}
fn default_tcp_port() -> u16 {
    DEFAULT_SERVER_PORT
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
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedServerWorld {
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
    snap: NetPlayerSnapshot,
    awaiting_creation: bool,
    reset_on_creation: bool,
}

/// Inspects a persisted server world file (e.g. `saves/embedded_mp_world.bin`) without starting
/// the server so the Main Menu OSM Map can immediately display the host's last saved server position.
pub fn peek_saved_character_summary(save_path: &str, player_uid: u64) -> Option<ServerCharacterSummary> {
    let bytes = std::fs::read(save_path).ok()?;
    let saved = bincode::deserialize::<PersistedServerWorld>(&bytes).ok()?;
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
    peers: HashMap<u64, ConnectedPeer>,
    characters: HashMap<u64, WireServerCharacter>,
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
            peers: HashMap::new(),
            characters: HashMap::new(),
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
        hub.write_status_json();
        hub
    }

    fn load_from_disk_if_present(&mut self) {
        let Some(ref path_str) = self.config.world_save_path else {
            return;
        };
        let path = Path::new(path_str);
        if !path.exists() {
            self.dirty = true;
            self.save_if_needed(true);
            return;
        }
        match std::fs::read(path) {
            Ok(bytes) => match bincode::deserialize::<PersistedServerWorld>(&bytes) {
                Ok(saved) => {
                    self.world_seed = if saved.world_seed == 0 {
                        rand::random::<u64>() | 1
                    } else {
                        saved.world_seed
                    };
                    self.world_hour = saved.world_hour.rem_euclid(24.0);
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
                            "[DDNeo-Server] Weltstatus geladen aus '{}': {} Charaktere, {} Gilden, {} Fahrzeuge, {} Risse versiegelt (Seed {}).",
                            path_str,
                            self.characters.len(),
                            self.guilds.len(),
                            self.vehicles.len(),
                            self.sealed_portals.len(),
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
            version: 2,
            world_seed: self.world_seed,
            world_hour: self.world_hour,
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
        self.write_status_json();
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
            NetClientMsg::ProbeServer { .. } | NetClientMsg::Hello { .. } => {}
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
                self.broadcast_all(&NetServerMsg::ChatBroadcast {
                    sender,
                    text: clean.chars().take(240).collect(),
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
}

enum HubEvent {
    ProbeQuery {
        player_uid: u64,
        reply_tx: tokio::sync::oneshot::Sender<NetServerMsg>,
    },
    PeerConnected {
        hello: NetClientMsg,
        tx: tokio::sync::mpsc::UnboundedSender<NetServerMsg>,
        accept_tx: tokio::sync::oneshot::Sender<bool>,
    },
    PeerPacket {
        uid: u64,
        msg: NetClientMsg,
    },
    PeerDisconnected {
        uid: u64,
    },
    Shutdown,
}

/// Runs the authoritative DDNeo server loop on an active Tokio runtime until `stop_flag` is set
/// or `shutdown_rx` resolves. Automatically flushes `server_world.bin` before returning.
pub async fn run_server_on_listener(
    listener: tokio::net::TcpListener,
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

    let accept_hub_tx = hub_tx.clone();
    let accept_stop = Arc::clone(&stop_flag);
    tokio::spawn(async move {
        while !accept_stop.load(Ordering::Relaxed) {
            let Ok(Ok((stream, _peer_addr))) =
                tokio::time::timeout(Duration::from_millis(300), listener.accept()).await
            else {
                continue;
            };
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
                let NetClientMsg::Hello { player_uid, .. } = &first_msg else {
                    return;
                };
                let uid = *player_uid;
                let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<NetServerMsg>();
                let (acc_tx, acc_rx) = tokio::sync::oneshot::channel::<bool>();
                if h_tx
                    .send(HubEvent::PeerConnected {
                        hello: first_msg,
                        tx: out_tx,
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
                    while !p_stop.load(Ordering::Relaxed) {
                        match read_packet::<NetClientMsg>(&mut rd).await {
                            Ok(pkt) => {
                                if h_tx.send(HubEvent::PeerPacket { uid, msg: pkt }).is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let _ = h_tx.send(HubEvent::PeerDisconnected { uid });
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
        HubEvent::PeerConnected {
            hello,
            tx,
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
                if !hub.config.password.is_empty() && password != hub.config.password {
                    let _ = tx.send(NetServerMsg::Rejected {
                        reason: "Falsches Server-Passwort!".to_string(),
                    });
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
                        snap,
                        awaiting_creation,
                        reset_on_creation: reset_character,
                    },
                );
                online_count.store(hub.peers.len(), Ordering::Relaxed);
                let _ = accept_tx.send(true);

                if !awaiting_creation {
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
            hub.handle_disconnect(uid);
            online_count.store(hub.peers.len(), Ordering::Relaxed);
        }
    }
    true
}

// =====================================================================
// BACKGROUND SERVER HANDLE (Used by In-Game Host & Unit Tests)
// =====================================================================
pub struct RunningServerHandle {
    pub bound_addr: SocketAddr,
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
        let (addr_tx, addr_rx) = std::sync::mpsc::channel::<Result<SocketAddr, String>>();

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
                    let _ = addr_tx.send(Ok(local_addr));
                    run_server_on_listener(listener, cfg_clone, stop_clone, count_clone).await;
                });
            })
            .map_err(|e| e.to_string())?;

        let bound_addr = addr_rx
            .recv_timeout(Duration::from_secs(4))
            .map_err(|_| "Timeout beim Starten des Servers".to_string())??;

        Ok(Self {
            bound_addr,
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
        };

        // 1. Start Dedicated Server #1, connect a player, found a guild + seal portal 999, then shut down!
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

        // 2. Reboot Dedicated Server #2 from the saved file -> verify guild, base, seed & sealed portal survived!
        {
            let mut srv2 = RunningServerHandle::start(cfg).expect("Server 2 bind");
            let addr = srv2.bound_addr;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
                let (mut rd, mut wr) = stream.into_split();
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
            });
            srv2.shutdown();
        }

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
