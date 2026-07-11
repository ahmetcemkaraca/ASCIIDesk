use std::path::{Path, PathBuf};
use std::sync::Arc;
use clap::{Parser, Subcommand};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use asciidesk_core::{ConfigManager, get_fingerprint, parse_verifying_key, TrustedDevice};
use asciidesk_host::{Host, HostOptions};
use asciidesk_client_tui::{Client, ClientOptions};
use asciidesk_rendezvous::{RendezvousServer, InMemoryStore};

#[derive(Parser)]
#[command(name = "asciidesk")]
#[command(about = "Terminal-first secure remote access", long_about = None)]
struct Cli {
    #[arg(short, long, value_name = "LEVEL", default_value = "info")]
    log_level: String,

    #[arg(short, long, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the remote access host server
    Host {
        /// Address to listen on
        #[arg(long, default_value = "0.0.0.0:7373")]
        listen: String,

        /// Custom device/host display name
        #[arg(long)]
        name: Option<String>,

        /// Path to custom terminal shell (e.g. powershell.exe, bash)
        #[arg(long)]
        shell: Option<String>,

        /// Run in headless mode (no real-time approval prompts; rejects untrusted clients)
        #[arg(long)]
        headless: bool,

        /// Allow pre-authorized trusted devices to bypass consent prompts
        #[arg(long, default_value_t = true)]
        allow_trusted: bool,

        /// Optional rendezvous signaling server URL (e.g. ws://127.0.0.1:8080)
        #[arg(long)]
        rendezvous: Option<String>,
    },

    /// Connect to a remote host terminal session
    Client {
        /// WebSocket URL of the host (or rendezvous URL if using --rendezvous)
        #[arg(long)]
        connect: String,

        /// One-time pairing code for verification
        #[arg(long)]
        code: Option<String>,

        /// Display name for this client
        #[arg(long)]
        name: Option<String>,

        /// Optional rendezvous signaling server URL (e.g. ws://127.0.0.1:8080)
        #[arg(long)]
        rendezvous: Option<String>,
    },

    /// Manage trusted client devices
    Trust {
        #[command(subcommand)]
        action: TrustAction,
    },

    /// List active paired devices (Future connection history)
    Devices,

    /// Check system configuration and environment capabilities
    Doctor,

    /// Start the optional connection rendezvous broker
    Rendezvous {
        /// Address to listen on
        #[arg(long, default_value = "0.0.0.0:8080")]
        listen: String,

        /// Storage engine to use
        #[arg(long, default_value = "memory")]
        store: String,

        /// Ephemeral code expiry in seconds
        #[arg(long, default_value_t = 300)]
        ttl_seconds: u64,
    },
}

#[derive(Subcommand)]
enum TrustAction {
    /// List all trusted device fingerprints
    List,
    /// Add a device fingerprint and public key to trust database
    Add {
        /// Display name for the trusted device
        #[arg(long)]
        name: String,

        /// Base64 encoded Ed25519 public key of the device
        #[arg(long)]
        key: String,
    },
    /// Remove a specific device fingerprint from trust database
    Remove {
        fingerprint: String,
    },
    /// Clear all trusted devices
    Clear,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Set up logging
    let log_level = match cli.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    match cli.command {
        Commands::Host { listen, name, shell, headless, allow_trusted, rendezvous } => {
            let host_opts = HostOptions {
                listen_addr: listen,
                name,
                shell,
                headless,
                allow_trusted,
                config_path: cli.config,
                rendezvous,
            };
            let host = Host::new(host_opts).map_err(|e| e as Box<dyn std::error::Error>)?;
            host.run().await.map_err(|e| e as Box<dyn std::error::Error>)?;
        }
        Commands::Client { connect, code, name, rendezvous } => {
            let client_opts = ClientOptions {
                connect_url: connect,
                pairing_code: code,
                name,
                config_path: cli.config,
                rendezvous,
            };
            let client = Client::new(client_opts)?;
            client.run().await?;
        }
        Commands::Trust { action } => {
            let config_mgr = ConfigManager::new(cli.config.as_deref())?;
            let mut config = config_mgr.load_or_create()?;

            match action {
                TrustAction::List => {
                    println!("========================================");
                    println!("Trusted Devices:");
                    if config.trusted_devices.is_empty() {
                        println!("  No trusted devices enrolled.");
                    } else {
                        for (i, dev) in config.trusted_devices.iter().enumerate() {
                            println!("{}. {} ({})", i + 1, dev.name, dev.fingerprint);
                        }
                    }
                    println!("========================================");
                }
                TrustAction::Add { name, key } => {
                    let key = key.trim().to_string();
                    match parse_verifying_key(&key) {
                        Ok(_) => {
                            let fp = get_fingerprint(&key);
                            config.trusted_devices.push(TrustedDevice {
                                name: name.clone(),
                                fingerprint: fp.clone(),
                                public_key: key,
                            });
                            config_mgr.save(&config)?;
                            println!("Successfully added device [{}] ({}) to trust store.", name, fp);
                        }
                        Err(e) => {
                            println!("Error: Invalid public key format. {}", e);
                        }
                    }
                }
                TrustAction::Remove { fingerprint } => {
                    let fp = fingerprint.trim().to_uppercase();
                    let before_len = config.trusted_devices.len();
                    config.trusted_devices.retain(|d| d.fingerprint != fp);
                    if config.trusted_devices.len() < before_len {
                        config_mgr.save(&config)?;
                        println!("Successfully removed device [{}] from trust store.", fp);
                    } else {
                        println!("Device [{}] was not found in trust store.", fp);
                    }
                }
                TrustAction::Clear => {
                    config.trusted_devices.clear();
                    config_mgr.save(&config)?;
                    println!("All trusted devices cleared.");
                }
            }
        }
        Commands::Devices => {
            println!("Devices command is scheduled for a future release (Phase 1+).");
        }
        Commands::Doctor => {
            run_doctor(cli.config.as_deref());
        }
        Commands::Rendezvous { listen, store: _, ttl_seconds: _ } => {
            let mem_store = Arc::new(InMemoryStore::new());
            let server = RendezvousServer::new(listen, mem_store);
            server.run().await?;
        }
    }

    Ok(())
}

fn run_doctor(custom_path: Option<&Path>) {
    println!("========================================");
    println!("ASCIIDesk Environment Diagnostics");
    println!("========================================");

    // 1. Check OS
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    println!("OS Platform:         {} ({})", os, arch);

    // 2. Check Terminal capabilities
    let term = std::env::var("TERM").unwrap_or_else(|_| "Not Set".to_string());
    let colorterm = std::env::var("COLORTERM").unwrap_or_else(|_| "Not Set".to_string());
    println!("TERM variable:       {}", term);
    println!("COLORTERM variable:  {}", colorterm);

    // 3. Config Path
    let config_mgr = ConfigManager::new(custom_path);
    match config_mgr {
        Ok(mgr) => {
            let path = mgr.config_dir();
            println!("Config Path:         {:?}", path);

            // 4. Config files
            match mgr.load_or_create() {
                Ok(cfg) => {
                    println!("Identity Key pair:   Valid");
                    println!("Identity Fingerprint: {}", get_fingerprint(&cfg.public_key));
                    println!("Trusted Count:       {}", cfg.trusted_devices.len());
                }
                Err(e) => {
                    println!("Identity Key pair:   Error ({})", e);
                }
            }
        }
        Err(e) => {
            println!("Config Directory:    Failed to resolve ({})", e);
        }
    }

    // 5. Windows PTY availability
    if cfg!(target_os = "windows") {
        // Test portable-pty initialization
        let pty_system_res = std::panic::catch_unwind(|| {
            portable_pty::native_pty_system()
        });
        match pty_system_res {
            Ok(_) => println!("Windows ConPTY PTY:  Available"),
            Err(_) => println!("Windows ConPTY PTY:  Unavailable / Failed to load"),
        }
    } else {
        println!("Unix PTY subsystem:  Supported");
    }

    // 6. Shell checks
    let default_shell = if cfg!(target_os = "windows") {
        if which("powershell.exe") {
            "powershell.exe (Active)"
        } else if which("cmd.exe") {
            "cmd.exe (Active)"
        } else {
            "None found"
        }
    } else {
        if which("/bin/bash") {
            "/bin/bash (Active)"
        } else if which("/bin/sh") {
            "/bin/sh (Active)"
        } else {
            "None found"
        }
    };
    println!("Default Shell:       {}", default_shell);
    println!("========================================");
}

fn which(name: &str) -> bool {
    if let Ok(paths) = std::env::var("PATH") {
        for path in std::env::split_paths(&paths) {
            let full_path = path.join(name);
            if full_path.exists() {
                return true;
            }
        }
    }
    false
}
