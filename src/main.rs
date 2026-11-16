use ddneo_server::{run_server_on_listener, ServerConfig};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

fn print_help() {
    println!("DDNeo Dedicated Server v{}", env!("CARGO_PKG_VERSION"));
    println!("Verwendung: ddneo-server [OPTIONEN]");
    println!();
    println!("Optionen:");
    println!("  --config <PFAD>       Pfad zur Konfigurationsdatei (Standard: server_config.json)");
    println!("  --bind <IP>           Bind-Adresse (Standard: 0.0.0.0)");
    println!("  --port <PORT>         TCP-Port (Standard: 27777)");
    println!("  --max-players <N>     Maximale Spieleranzahl (Standard: 12)");
    println!("  --name <TEXT>         Angezeigter Sitzungsname");
    println!("  --password <TEXT>     Optionales Server-Passwort");
    println!("  --lan                 UDP-LAN-Erkennung (Port 27778) aktivieren");
    println!("  --no-pause-empty      Weltzeit läuft weiter, auch wenn 0 Spieler online sind");
    println!("  -h, --help            Diese Hilfe anzeigen");
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut config_path = "server_config.json".to_string();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "--config" if i + 1 < args.len() => {
                config_path = args[i + 1].clone();
                i += 2;
                continue;
            }
            _ => {}
        }
        i += 1;
    }

    let mut cfg = if Path::new(&config_path).exists() {
        match std::fs::read_to_string(&config_path) {
            Ok(txt) => match serde_json::from_str::<ServerConfig>(&txt) {
                Ok(parsed) => parsed,
                Err(e) => {
                    eprintln!(
                        "[DDNeo-Server] Fehler in '{}': {} — verwende Standardwerte.",
                        config_path, e
                    );
                    ServerConfig::default()
                }
            },
            Err(_) => ServerConfig::default(),
        }
    } else {
        let def = ServerConfig::default();
        if let Ok(pretty) = serde_json::to_string_pretty(&def) {
            let _ = std::fs::write(&config_path, pretty);
            println!(
                "[DDNeo-Server] Standard-Konfiguration '{}' wurde angelegt.",
                config_path
            );
        }
        def
    };
    cfg.is_dedicated = true;

    // Apply CLI overrides
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 2;
                continue;
            }
            "--bind" if i + 1 < args.len() => {
                cfg.bind_ip = args[i + 1].clone();
                i += 2;
                continue;
            }
            "--port" if i + 1 < args.len() => {
                if let Ok(p) = args[i + 1].parse::<u16>() {
                    cfg.tcp_port = p;
                }
                i += 2;
                continue;
            }
            "--max-players" if i + 1 < args.len() => {
                if let Ok(mp) = args[i + 1].parse::<u8>() {
                    cfg.max_players = mp.max(2);
                }
                i += 2;
                continue;
            }
            "--name" if i + 1 < args.len() => {
                cfg.session_name = args[i + 1].clone();
                i += 2;
                continue;
            }
            "--password" if i + 1 < args.len() => {
                cfg.password = args[i + 1].clone();
                i += 2;
                continue;
            }
            "--lan" => {
                cfg.lan_discovery = true;
                i += 1;
                continue;
            }
            "--no-pause-empty" => {
                cfg.pause_when_empty = false;
                i += 1;
                continue;
            }
            _ => {}
        }
        i += 1;
    }

    let bind_addr = format!("{}:{}", cfg.bind_ip, cfg.tcp_port);
    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "[DDNeo-Server] KRITISCH: Konnte {} nicht binden: {}",
                bind_addr, e
            );
            std::process::exit(1);
        }
    };

    let actual_addr = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or(bind_addr);

    println!("==============================================================");
    println!("  DDNeo Dedicated Server v{}", env!("CARGO_PKG_VERSION"));
    println!("  Sitzung       : {}", cfg.session_name);
    println!("  Lauscht auf   : {} (TCP)", actual_addr);
    println!("  Max. Spieler  : {}", cfg.max_players);
    println!(
        "  Leerlauf-Modus: {}",
        if cfg.pause_when_empty {
            "0%-CPU Hibernation aktiv (Welt pausiert bei 0 Spielern)"
        } else {
            "Dauerlauf aktiv"
        }
    );
    if let Some(ref wp) = cfg.world_save_path {
        println!("  Weltspeicher  : {} (Intervall {}s)", wp, cfg.save_interval_secs);
    }
    println!("  Beenden       : Strg+C / SIGTERM (speichert automatisch)");
    println!("==============================================================");

    let stop_flag = Arc::new(AtomicBool::new(false));
    let online_count = Arc::new(AtomicUsize::new(0));

    let sig_stop = Arc::clone(&stop_flag);
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        println!("\n[DDNeo-Server] Stopp-Signal empfangen — speichere Weltstatus …");
        sig_stop.store(true, Ordering::Relaxed);
    });

    run_server_on_listener(listener, cfg, stop_flag, online_count).await;
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
