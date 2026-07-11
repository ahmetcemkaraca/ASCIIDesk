use std::io::Write;
use std::path::PathBuf;
use tokio_tungstenite::connect_async;
use crossterm::event::{Event, KeyCode, KeyModifiers};
use tracing::{info, error};

use asciidesk_core::{Config, ConfigManager, parse_signing_key, get_fingerprint};
use asciidesk_protocol::{Capability, ClientToHost, HostToClient};
use asciidesk_transport::MessageStream;
use ed25519_dalek::Signer;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as WsMessage;

pub struct ClientOptions {
    pub connect_url: String,
    pub pairing_code: Option<String>,
    pub name: Option<String>,
    pub config_path: Option<PathBuf>,
    pub rendezvous: Option<String>,
}

pub struct Client {
    options: ClientOptions,
    _config_manager: ConfigManager,
    config: Config,
}

struct RawModeGuard;

impl RawModeGuard {
    fn enable() -> Result<Self, std::io::Error> {
        crossterm::terminal::enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::queue!(
            std::io::stdout(),
            crossterm::cursor::Show,
        );
        let _ = std::io::stdout().flush();
    }
}

impl Client {
    pub fn new(options: ClientOptions) -> Result<Self, Box<dyn std::error::Error>> {
        let config_manager = ConfigManager::new(options.config_path.as_deref())?;
        let config = config_manager.load_or_create()?;

        Ok(Self {
            options,
            _config_manager: config_manager,
            config,
        })
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        let client_name = self.options.name.clone().unwrap_or(self.config.device_name.clone());
        let client_pub_key_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.config.public_key
        )?;
        let _client_fp = get_fingerprint(&self.config.public_key);

        let target_url = if let Some(ref r_url) = self.options.rendezvous {
            let code = if let Some(ref c) = self.options.pairing_code {
                c.clone()
            } else {
                print!("Enter Pairing Code: ");
                std::io::stdout().flush()?;
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                line.trim().to_string()
            };
            resolve_host_via_rendezvous(r_url, &code, &client_name, &self.config.public_key).await?
        } else {
            self.options.connect_url.clone()
        };

        println!("Connecting to host at: {}", target_url);
        let (ws_stream, _) = connect_async(&target_url).await?;
        let mut msg_stream = MessageStream::new(ws_stream);

        // 1. Send Client Hello
        msg_stream.send(&ClientToHost::Hello {
            protocol_version: "1.0".to_string(),
            client_name,
            client_public_key: client_pub_key_bytes,
            capabilities: vec![Capability::TerminalPty, Capability::TerminalResize],
        }).await?;

        // 2. Expect Host HelloAck
        let _host_info = match msg_stream.next().await? {
            HostToClient::HelloAck { host_name, host_public_key, capabilities: _, .. } => {
                let host_pub_b64 = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &host_public_key
                );
                let host_fp = get_fingerprint(&host_pub_b64);
                println!("Connected to host: {} ({})", host_name, host_fp);
                (host_name, host_fp)
            }
            other => {
                return Err(format!("Handshake failed: expected HelloAck, got {:?}", other).into());
            }
        };

        // 3. Process Authentication
        match msg_stream.next().await? {
            HostToClient::AuthRequired { challenge } => {
                if !challenge.is_empty() {
                    // Cryptographic authentication (Trusted Device path)
                    println!("Authenticating using cached trusted key...");
                    let sign_key = parse_signing_key(&self.config.private_key)?;
                    let signature = sign_key.sign(&challenge);
                    msg_stream.send(&ClientToHost::ChallengeResponse {
                        signature: signature.to_vec(),
                    }).await?;
                } else {
                    // Pairing code authentication
                    let code = if let Some(c) = &self.options.pairing_code {
                        c.clone()
                    } else {
                        print!("Enter Pairing Code: ");
                        std::io::stdout().flush()?;
                        let mut line = String::new();
                        std::io::stdin().read_line(&mut line)?;
                        line.trim().to_string()
                    };

                    msg_stream.send(&ClientToHost::PairingCode { code }).await?;
                }
            }
            HostToClient::AuthAccepted => {
                // Instantly accepted (should not happen before challenge/pairing, but support it)
            }
            HostToClient::AuthDenied { reason } => {
                return Err(format!("Authentication denied: {}", reason).into());
            }
            other => {
                return Err(format!("Handshake failed: expected AuthRequired, got {:?}", other).into());
            }
        }

        // Wait for AuthAccepted
        match msg_stream.next().await? {
            HostToClient::AuthAccepted => {
                println!("Connection established!");
            }
            HostToClient::AuthDenied { reason } => {
                return Err(format!("Authentication denied: {}", reason).into());
            }
            other => {
                return Err(format!("Unexpected message after auth response: {:?}", other).into());
            }
        }

        // Run remote interactive terminal session
        self.run_interactive_loop(msg_stream).await?;

        Ok(())
    }

    async fn run_interactive_loop<S>(
        &self,
        mut stream: MessageStream<ClientToHost, HostToClient, S>,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        // Enable raw mode and hide cursor
        let _guard = RawModeGuard::enable()?;
        crossterm::queue!(
            std::io::stdout(),
            crossterm::cursor::Hide,
        )?;
        std::io::stdout().flush()?;

        // Send initial window size
        let (initial_cols, initial_rows) = crossterm::terminal::size().unwrap_or((80, 24));
        stream.send(&ClientToHost::PtyResize {
            cols: initial_cols,
            rows: initial_rows,
        }).await?;

        // Channel to receive crossterm events in background
        let (evt_tx, mut evt_rx) = tokio::sync::mpsc::channel::<Event>(100);
        std::thread::spawn(move || {
            loop {
                match crossterm::event::read() {
                    Ok(event) => {
                        if evt_tx.blocking_send(event).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Error reading crossterm events: {}", e);
                        break;
                    }
                }
            }
        });

        let mut stdout = std::io::stdout();
        let mut ping_interval = tokio::time::interval(std::time::Duration::from_secs(5));
        let mut last_pong = std::time::Instant::now();

        loop {
            tokio::select! {
                _ = ping_interval.tick() => {
                    if last_pong.elapsed().as_secs() > 15 {
                        break;
                    }
                    let _ = stream.send(&ClientToHost::Ping).await;
                }
                // Read local events -> Send to host
                Some(event) = evt_rx.recv() => {
                    match event {
                        Event::Key(key_event) => {
                            if key_event.kind == crossterm::event::KeyEventKind::Press {
                                if let Some(bytes) = key_event_to_bytes(key_event) {
                                    stream.send(&ClientToHost::PtyInput { bytes }).await?;
                                }
                            }
                        }
                        Event::Resize(width, height) => {
                            stream.send(&ClientToHost::PtyResize {
                                cols: width,
                                rows: height,
                            }).await?;
                        }
                        _ => {}
                    }
                }
                // Read from host -> print to stdout
                msg_res = stream.next() => {
                    match msg_res {
                        Ok(HostToClient::PtyOutput { bytes }) => {
                            stdout.write_all(&bytes)?;
                            stdout.flush()?;
                        }
                        Ok(HostToClient::PtyExit { exit_code }) => {
                            // Restore terminal, then show exit code
                            drop(_guard);
                            println!("\n[ASCIIDesk] Remote process exited with code {}", exit_code);
                            break;
                        }
                        Ok(HostToClient::Pong) => {
                            last_pong = std::time::Instant::now();
                        }
                        Ok(HostToClient::Close) | Err(_) => {
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(())
    }
}

fn key_event_to_bytes(key: crossterm::event::KeyEvent) -> Option<Vec<u8>> {
    match key.code {
        KeyCode::Char(c) => {
            if key.modifiers.contains(KeyModifiers::CONTROL) {
                let code = c.to_ascii_lowercase();
                if code >= 'a' && code <= 'z' {
                    Some(vec![code as u8 - b'a' + 1])
                } else {
                    None
                }
            } else {
                Some(c.to_string().into_bytes())
            }
        }
        KeyCode::Enter => Some(vec![b'\r']),
        KeyCode::Backspace => Some(vec![127]), // ASCII Delete/Backspace representation
        KeyCode::Tab => Some(vec![b'\t']),
        KeyCode::Esc => Some(vec![27]),
        KeyCode::Up => Some(b"\x1b[A".to_vec()),
        KeyCode::Down => Some(b"\x1b[B".to_vec()),
        KeyCode::Right => Some(b"\x1b[C".to_vec()),
        KeyCode::Left => Some(b"\x1b[D".to_vec()),
        KeyCode::Home => Some(b"\x1b[H".to_vec()),
        KeyCode::End => Some(b"\x1b[F".to_vec()),
        KeyCode::Delete => Some(b"\x1b[3~".to_vec()),
        _ => None,
    }
}

async fn resolve_host_via_rendezvous(
    rendezvous_url: &str,
    code: &str,
    client_name: &str,
    client_pub_b64: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use tokio_tungstenite::connect_async;
    use asciidesk_rendezvous::RendezvousMessage;
    
    let (ws_stream, _) = connect_async(rendezvous_url).await?;
    let (mut ws_write, mut ws_read) = ws_stream.split();
    
    let req = RendezvousMessage::RequestPairing {
        code: code.to_string(),
        name: client_name.to_string(),
        public_key: client_pub_b64.to_string(),
    };
    ws_write.send(WsMessage::Text(serde_json::to_string(&req)?)).await?;
    
    let mut host_pub_key = None;
    
    while let Some(msg_res) = ws_read.next().await {
        match msg_res {
            Ok(WsMessage::Text(text)) => {
                if let Ok(parsed) = serde_json::from_str::<RendezvousMessage>(&text) {
                    match parsed {
                        RendezvousMessage::PairingMatched { host_name, host_public_key: hpk } => {
                            println!("Pairing matched with host: {}", host_name);
                            host_pub_key = Some(hpk);
                        }
                        RendezvousMessage::CandidatesReceived { from_public_key, candidates } => {
                            if let Some(ref hpk) = host_pub_key {
                                if from_public_key == *hpk {
                                    for candidate in candidates {
                                        info!("Trying candidate: {}", candidate);
                                        // Attempt connection test
                                        if let Ok((_ws, _)) = connect_async(&candidate).await {
                                            println!("Resolved direct connection path: {}", candidate);
                                            return Ok(candidate);
                                        }
                                    }
                                }
                            }
                            return Err("Could not connect to any resolved direct host candidates".into());
                        }
                        RendezvousMessage::Error { message } => {
                            return Err(format!("Rendezvous error: {}", message).into());
                        }
                        _ => {}
                    }
                }
            }
            Ok(WsMessage::Close(_)) | Err(_) => break,
            _ => {}
        }
    }
    
    Err("Rendezvous matchmaking failed to resolve host".into())
}
