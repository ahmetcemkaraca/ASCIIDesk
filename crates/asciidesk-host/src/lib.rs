use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use tracing::{info, warn, error};
use rand::Rng;

use asciidesk_core::{
    Config, ConfigManager, parse_verifying_key, get_fingerprint, AuditLogger, TrustedDevice
};
use asciidesk_protocol::{Capability, ClientToHost, HostToClient};
use asciidesk_transport::MessageStream;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as WsMessage;

pub mod desktop;

#[derive(Clone)]
pub struct HostOptions {
    pub listen_addr: String,
    pub name: Option<String>,
    pub shell: Option<String>,
    pub headless: bool,
    pub allow_trusted: bool,
    pub config_path: Option<PathBuf>,
    pub rendezvous: Option<String>,
}

pub struct Host {
    options: HostOptions,
    config_manager: ConfigManager,
    config: Config,
    audit_logger: AuditLogger,
    pairing_code: String,
}

impl Host {
    pub fn new(options: HostOptions) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let config_manager = ConfigManager::new(options.config_path.as_deref())?;
        let config = config_manager.load_or_create()?;
        let audit_logger = AuditLogger::new(config_manager.config_dir());

        // Generate 6-digit random pairing code
        let mut rng = rand::thread_rng();
        let pairing_code = format!("{:06}", rng.gen_range(0..1000000));

        Ok(Self {
            options,
            config_manager,
            config,
            audit_logger,
            pairing_code,
        })
    }

    pub fn pairing_code(&self) -> &str {
        &self.pairing_code
    }

    pub async fn run(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let host_name = self.options.name.clone().unwrap_or(self.config.device_name.clone());
        let host_pub_key_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.config.public_key
        )?;
        let host_fp = get_fingerprint(&self.config.public_key);

        println!("====================================================");
        println!("ASCIIDesk Host starting...");
        println!("Device Name: {}", host_name);
        println!("Fingerprint: {}", host_fp);
        
        // Try to get local IPs
        if let Ok(ip) = local_ip_address::local_ip() {
            println!("Local IP:    {}", ip);
        }
        
        println!("Listening:   {}", self.options.listen_addr);
        println!("Pairing Code: {}", self.pairing_code);
        println!("\nWARNING: Anyone with the pairing code can request access.");
        if self.options.headless {
            println!("RUNNING IN HEADLESS MODE. Interactive consent is DISABLED.");
            println!("Only pre-approved trusted devices can connect.");
        } else {
            println!("Interactive consent is ENABLED. You must approve new clients.");
        }
        println!("====================================================");

        let listener = TcpListener::bind(&self.options.listen_addr).await?;

        if let Some(ref r_url) = self.options.rendezvous {
            let r_url = r_url.clone();
            let host_name = host_name.clone();
            let host_pub_key_b64 = self.config.public_key.clone();
            let listen_addr = self.options.listen_addr.clone();
            tokio::spawn(async move {
                if let Err(e) = run_host_signaling(&r_url, &host_name, &host_pub_key_b64, &listen_addr).await {
                    error!("Rendezvous signaling connection failed: {}", e);
                }
            });
        }

        while let Ok((stream, peer_addr)) = listener.accept().await {
            info!("New connection from {}", peer_addr);
            let ws_stream = match accept_async(stream).await {
                Ok(ws) => ws,
                Err(e) => {
                    error!("WebSocket handshake failed: {}", e);
                    continue;
                }
            };

            let mut msg_stream = MessageStream::new(ws_stream);
            let session_start = Instant::now();

            match self.handle_handshake(&mut msg_stream, peer_addr, &host_name, &host_pub_key_bytes).await {
                Ok(Some(client_info)) => {
                    info!("Handshake successful, starting session for {}", client_info.name);
                    let shell_to_use = self.options.shell.clone().unwrap_or_else(|| default_shell());
                    println!("\n[ASCIIDesk] Active session started from {} ({})", client_info.name, client_info.fingerprint);
                    
                    let pty_res = self.run_pty_session(&mut msg_stream, &shell_to_use).await;
                    
                    let duration = session_start.elapsed().as_secs();
                    println!("\n[ASCIIDesk] Session ended. Duration: {}s", duration);

                    let verdict = match pty_res {
                        Ok(_) => "Completed",
                        Err(e) => {
                            error!("PTY session error: {}", e);
                            "Error"
                        }
                    };

                    let _ = self.audit_logger.log_session(
                        &client_info.fingerprint,
                        &peer_addr.to_string(),
                        verdict,
                        "PTY",
                        Some(duration)
                    );
                }
                Ok(None) => {
                    // Handshake failed or denied, already logged/sent denial
                    let _ = self.audit_logger.log_session(
                        "UNKNOWN",
                        &peer_addr.to_string(),
                        "Denied",
                        "PTY",
                        None
                    );
                }
                Err(e) => {
                    error!("Session handshake error: {}", e);
                    let _ = self.audit_logger.log_session(
                        "UNKNOWN",
                        &peer_addr.to_string(),
                        "Handshake Error",
                        "PTY",
                        None
                    );
                }
            }
        }

        Ok(())
    }

    async fn handle_handshake(
        &mut self,
        stream: &mut MessageStream<HostToClient, ClientToHost, tokio::net::TcpStream>,
        peer_addr: SocketAddr,
        host_name: &str,
        host_pub_key: &[u8],
    ) -> Result<Option<ClientHandshakeInfo>, Box<dyn std::error::Error + Send + Sync>> {
        // 1. Read Client Hello
        let client_hello = match stream.next().await {
            Ok(ClientToHost::Hello { protocol_version, client_name, client_public_key, capabilities }) => {
                ClientHandshakeInfo {
                    _version: protocol_version,
                    name: client_name,
                    public_key: client_public_key,
                    _capabilities: capabilities,
                    fingerprint: String::new(), // to fill
                }
            }
            other => {
                warn!("Expected Hello, got {:?}", other);
                return Ok(None);
            }
        };

        let client_pub_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &client_hello.public_key
        );
        let client_fp = get_fingerprint(&client_pub_b64);
        let mut client_info = client_hello;
        client_info.fingerprint = client_fp.clone();

        // 2. Send Host HelloAck
        stream.send(&HostToClient::HelloAck {
            protocol_version: "1.0".to_string(),
            host_name: host_name.to_string(),
            host_public_key: host_pub_key.to_vec(),
            capabilities: vec![Capability::TerminalPty, Capability::TerminalResize, Capability::DesktopStreaming],
        }).await?;

        // 3. Authenticate client
        let is_trusted = self.config.trusted_devices.iter().any(|d| d.fingerprint == client_fp);

        if is_trusted && self.options.allow_trusted {
            // Cryptographic challenge
            let challenge = rand::thread_rng().gen::<[u8; 32]>();
            stream.send(&HostToClient::AuthRequired { challenge: challenge.to_vec() }).await?;

            match stream.next().await {
                Ok(ClientToHost::ChallengeResponse { signature }) => {
                    let ver_key = parse_verifying_key(&client_pub_b64)?;
                    let sig = ed25519_dalek::Signature::from_slice(&signature)?;
                    if ver_key.verify_strict(&challenge, &sig).is_ok() {
                        stream.send(&HostToClient::AuthAccepted).await?;
                        info!("Authenticated trusted device {}", client_fp);
                        return Ok(Some(client_info));
                    } else {
                        stream.send(&HostToClient::AuthDenied { reason: "Cryptographic signature verification failed".to_string() }).await?;
                        return Ok(None);
                    }
                }
                other => {
                    warn!("Expected ChallengeResponse, got {:?}", other);
                    stream.send(&HostToClient::AuthDenied { reason: "Challenge response expected".to_string() }).await?;
                    return Ok(None);
                }
            }
        }

        // Untrusted device authentication via pairing code
        stream.send(&HostToClient::AuthRequired { challenge: Vec::new() }).await?;

        match stream.next().await {
            Ok(ClientToHost::PairingCode { code }) => {
                if code != self.pairing_code {
                    stream.send(&HostToClient::AuthDenied { reason: "Invalid pairing code".to_string() }).await?;
                    return Ok(None);
                }
            }
            other => {
                warn!("Expected PairingCode, got {:?}", other);
                stream.send(&HostToClient::AuthDenied { reason: "Pairing code expected".to_string() }).await?;
                return Ok(None);
            }
        }

        // Pairing code verified, check for headless mode block
        if self.options.headless {
            stream.send(&HostToClient::AuthDenied { reason: "Host is headless and this device is not trusted.".to_string() }).await?;
            return Ok(None);
        }

        // Show interactive consent prompt
        println!("\n>>> [CONSENT REQUIRED] <<<");
        println!("Incoming ASCIIDesk PTY terminal session request:");
        println!("  Client Device: {}", client_info.name);
        println!("  Fingerprint:   {}", client_fp);
        println!("  From Network:  {}", peer_addr);
        print!("Allow access to a terminal shell running as your user? [y/N]: ");
        std::io::stdout().flush()?;

        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let approved = line.trim().to_lowercase() == "y";

        if approved {
            // Add to trusted list
            println!("Adding client to trusted devices...");
            self.config.trusted_devices.push(TrustedDevice {
                name: client_info.name.clone(),
                fingerprint: client_fp.clone(),
                public_key: client_pub_b64.clone(),
            });
            let _ = self.config_manager.save(&self.config);

            stream.send(&HostToClient::AuthAccepted).await?;
            Ok(Some(client_info))
        } else {
            println!("Connection request denied.");
            stream.send(&HostToClient::AuthDenied { reason: "Denied by host operator".to_string() }).await?;
            Ok(None)
        }
    }

    async fn run_pty_session(
        &self,
        stream: &mut MessageStream<HostToClient, ClientToHost, tokio::net::TcpStream>,
        shell_path: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pty_system = native_pty_system();
        let pair = pty_system.openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })?;

        let cmd = CommandBuilder::new(shell_path);
        
        // Spawn shell process
        let mut child = pair.slave.spawn_command(cmd)?;
        
        // Setup PTY output thread to channel
        let mut pty_reader = pair.master.try_clone_reader()?;
        let (pty_out_tx, mut pty_out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
        
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = pty_reader.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if pty_out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
            info!("PTY output reader thread exiting");
        });

        // Setup PTY input thread from channel
        let mut pty_writer = pair.master.take_writer()?;
        let (pty_in_tx, mut pty_in_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
        
        std::thread::spawn(move || {
            while let Some(bytes) = pty_in_rx.blocking_recv() {
                if pty_writer.write_all(&bytes).is_err() || pty_writer.flush().is_err() {
                    break;
                }
            }
            info!("PTY input writer thread exiting");
        });

        let master_close_handle = pair.master;

        let (desktop_tx, mut desktop_rx) = tokio::sync::mpsc::channel::<String>(16);
        let mut desktop_task_abort: Option<tokio::task::JoinHandle<()>> = None;
        let current_cols = std::sync::Arc::new(std::sync::atomic::AtomicU16::new(80));
        let current_rows = std::sync::Arc::new(std::sync::atomic::AtomicU16::new(24));

        loop {
            tokio::select! {
                // Read from PTY output -> Send to Client
                Some(bytes) = pty_out_rx.recv() => {
                    stream.send(&HostToClient::PtyOutput { bytes }).await?;
                }
                // Read from desktop capture -> Send to Client
                Some(frame_text) = desktop_rx.recv() => {
                    stream.send(&HostToClient::DesktopFrame { frame_text }).await?;
                }
                // Read from client -> Handle
                msg_res = tokio::time::timeout(std::time::Duration::from_secs(15), stream.next()) => {
                    match msg_res {
                        Ok(Ok(ClientToHost::PtyInput { bytes })) => {
                            if pty_in_tx.send(bytes).await.is_err() {
                                break;
                            }
                        }
                        Ok(Ok(ClientToHost::PtyResize { cols, rows })) => {
                            info!("Resizing remote PTY to {}x{}", cols, rows);
                            current_cols.store(cols, std::sync::atomic::Ordering::Relaxed);
                            current_rows.store(rows, std::sync::atomic::Ordering::Relaxed);
                            let _ = master_close_handle.resize(PtySize {
                                rows,
                                cols,
                                pixel_width: 0,
                                pixel_height: 0,
                            });
                        }
                        Ok(Ok(ClientToHost::StartDesktopStream)) => {
                            info!("Starting desktop stream");
                            if desktop_task_abort.is_none() {
                                let tx = desktop_tx.clone();
                                let cols_ref = current_cols.clone();
                                let rows_ref = current_rows.clone();
                                let handle = tokio::spawn(async move {
                                    let mut interval = tokio::time::interval(std::time::Duration::from_millis(100)); // ~10 FPS
                                    loop {
                                        interval.tick().await;
                                        let c = cols_ref.load(std::sync::atomic::Ordering::Relaxed);
                                        let r = rows_ref.load(std::sync::atomic::Ordering::Relaxed);
                                        // Use blocking operation safely by spawning it on a blocking thread or just direct (xcap might block slightly)
                                        // Wait, capture_desktop_frame does some image processing. Better spawn_blocking or just inline since tokio can handle short blocks.
                                        let frame_res = tokio::task::spawn_blocking(move || {
                                            crate::desktop::capture_desktop_frame(c, r)
                                        }).await;
                                        
                                        if let Ok(Ok(frame)) = frame_res {
                                            if tx.send(frame).await.is_err() {
                                                break;
                                            }
                                        }
                                    }
                                });
                                desktop_task_abort = Some(handle);
                            }
                        }
                        Ok(Ok(ClientToHost::StopDesktopStream)) => {
                            info!("Stopping desktop stream");
                            if let Some(handle) = desktop_task_abort.take() {
                                handle.abort();
                            }
                        }
                        Ok(Ok(ClientToHost::Ping)) => {
                            let _ = stream.send(&HostToClient::Pong).await;
                        }
                        Ok(Ok(ClientToHost::Close)) | Ok(Err(_)) => {
                            break;
                        }
                        Err(_) => {
                            // Timeout elapsed without receiving any message from client
                            warn!("Connection timed out waiting for keepalive");
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        // Cleanup
        let _ = child.kill();
        Ok(())
    }
}

struct ClientHandshakeInfo {
    _version: String,
    name: String,
    public_key: Vec<u8>,
    _capabilities: Vec<Capability>,
    fingerprint: String,
}

fn default_shell() -> String {
    if cfg!(target_os = "windows") {
        if which("powershell.exe") {
            "powershell.exe".to_string()
        } else {
            "cmd.exe".to_string()
        }
    } else {
        if which("/bin/bash") {
            "/bin/bash".to_string()
        } else {
            "/bin/sh".to_string()
        }
    }
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

async fn run_host_signaling(
    url: &str,
    name: &str,
    pub_key: &str,
    listen_addr: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio_tungstenite::connect_async;
    use asciidesk_rendezvous::RendezvousMessage;
    
    let (ws_stream, _) = connect_async(url).await?;
    let (mut ws_write, mut ws_read) = ws_stream.split();
    
    let reg = RendezvousMessage::RegisterHost {
        name: name.to_string(),
        public_key: pub_key.to_string(),
    };
    ws_write.send(WsMessage::Text(serde_json::to_string(&reg)?)).await?;
    
    while let Some(msg_res) = ws_read.next().await {
        match msg_res {
            Ok(WsMessage::Text(text)) => {
                if let Ok(parsed) = serde_json::from_str::<RendezvousMessage>(&text) {
                    match parsed {
                        RendezvousMessage::HostRegistered { pairing_code } => {
                            println!("\n========================================");
                            println!("Registered on Rendezvous Broker!");
                            println!("Rendezvous Pairing Code: {}", pairing_code);
                            println!("========================================");
                        }
                        RendezvousMessage::ClientMatched { client_name, client_public_key } => {
                            info!("Rendezvous client matched: {} ({})", client_name, client_public_key);
                            let mut candidates = Vec::new();
                            let port = listen_addr.split(':').last().unwrap_or("7373");
                            
                            if let Ok(ip) = local_ip_address::local_ip() {
                                candidates.push(format!("ws://{}:{}", ip, port));
                            }
                            candidates.push(format!("ws://127.0.0.1:{}", port));
                            
                            // NAT Traversal / Public IP
                            if let Ok(resp) = reqwest::get("https://api.ipify.org").await {
                                if let Ok(ip_text) = resp.text().await {
                                    let ip_text = ip_text.trim();
                                    if !ip_text.is_empty() {
                                        candidates.push(format!("ws://{}:{}", ip_text, port));
                                        info!("Added public IP candidate: {}", ip_text);
                                    }
                                }
                            }
                            
                            let reply = RendezvousMessage::SendCandidates {
                                target_public_key: client_public_key,
                                candidates,
                            };
                            let _ = ws_write.send(WsMessage::Text(serde_json::to_string(&reply)?)).await;
                        }
                        _ => {}
                    }
                }
            }
            Ok(WsMessage::Close(_)) | Err(_) => break,
            _ => {}
        }
    }
    Ok(())
}
