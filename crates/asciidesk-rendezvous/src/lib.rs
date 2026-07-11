use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use thiserror::Error;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{info, error};

#[derive(Debug, Error)]
pub enum RendezvousError {
    #[error("Pairing code not found or expired")]
    InvalidPairingCode,
    #[error("Device not found")]
    DeviceNotFound,
    #[error("Session offer not found")]
    OfferNotFound,
    #[error("Store error: {0}")]
    Store(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DevicePresence {
    pub public_key: String, // base64
    pub display_name: String,
    pub address: String, // last seen connection string
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SessionOffer {
    pub session_id: String,
    pub host_public_key: String,
    pub client_public_key: String,
    pub host_address_candidates: Vec<String>,
    pub client_address_candidates: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub ttl_secs: u64,
}

pub trait RendezvousStore: Send + Sync {
    fn put_device(&self, device: DevicePresence) -> Result<(), RendezvousError>;
    fn get_device(&self, public_key: &str) -> Result<DevicePresence, RendezvousError>;
    
    fn create_pairing_code(&self, code: String, host_public_key: String, ttl_secs: u64) -> Result<(), RendezvousError>;
    fn consume_pairing_code(&self, code: &str) -> Result<String, RendezvousError>; // returns host_public_key
    
    fn put_session_offer(&self, offer: SessionOffer) -> Result<(), RendezvousError>;
    fn get_session_offer(&self, host_public_key: &str, client_public_key: &str) -> Result<SessionOffer, RendezvousError>;
    
    fn cleanup_expired(&self, max_age: Duration) -> Result<(), RendezvousError>;
}

// In-Memory implementation
struct EphemeralPairing {
    host_public_key: String,
    expiry: Instant,
}

pub struct InMemoryStore {
    devices: RwLock<HashMap<String, DevicePresence>>,
    pairings: RwLock<HashMap<String, EphemeralPairing>>,
    offers: RwLock<HashMap<String, SessionOffer>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            devices: RwLock::new(HashMap::new()),
            pairings: RwLock::new(HashMap::new()),
            offers: RwLock::new(HashMap::new()),
        }
    }
}

impl RendezvousStore for InMemoryStore {
    fn put_device(&self, device: DevicePresence) -> Result<(), RendezvousError> {
        let mut dev = self.devices.write().map_err(|e| RendezvousError::Store(e.to_string()))?;
        dev.insert(device.public_key.clone(), device);
        Ok(())
    }

    fn get_device(&self, public_key: &str) -> Result<DevicePresence, RendezvousError> {
        let dev = self.devices.read().map_err(|e| RendezvousError::Store(e.to_string()))?;
        dev.get(public_key).cloned().ok_or(RendezvousError::DeviceNotFound)
    }

    fn create_pairing_code(&self, code: String, host_public_key: String, ttl_secs: u64) -> Result<(), RendezvousError> {
        let mut pairs = self.pairings.write().map_err(|e| RendezvousError::Store(e.to_string()))?;
        pairs.insert(code, EphemeralPairing {
            host_public_key,
            expiry: Instant::now() + Duration::from_secs(ttl_secs),
        });
        Ok(())
    }

    fn consume_pairing_code(&self, code: &str) -> Result<String, RendezvousError> {
        let mut pairs = self.pairings.write().map_err(|e| RendezvousError::Store(e.to_string()))?;
        if let Some(pairing) = pairs.remove(code) {
            if Instant::now() < pairing.expiry {
                Ok(pairing.host_public_key)
            } else {
                Err(RendezvousError::InvalidPairingCode)
            }
        } else {
            Err(RendezvousError::InvalidPairingCode)
        }
    }

    fn put_session_offer(&self, offer: SessionOffer) -> Result<(), RendezvousError> {
        let mut off = self.offers.write().map_err(|e| RendezvousError::Store(e.to_string()))?;
        let key = format!("{}:{}", offer.host_public_key, offer.client_public_key);
        off.insert(key, offer);
        Ok(())
    }

    fn get_session_offer(&self, host_public_key: &str, client_public_key: &str) -> Result<SessionOffer, RendezvousError> {
        let mut off = self.offers.write().map_err(|e| RendezvousError::Store(e.to_string()))?;
        let key = format!("{}:{}", host_public_key, client_public_key);
        if let Some(offer) = off.remove(&key) {
            let elapsed = Utc::now().signed_duration_since(offer.created_at).num_seconds();
            if elapsed < offer.ttl_secs as i64 {
                Ok(offer)
            } else {
                Err(RendezvousError::OfferNotFound)
            }
        } else {
            Err(RendezvousError::OfferNotFound)
        }
    }

    fn cleanup_expired(&self, max_age: Duration) -> Result<(), RendezvousError> {
        let now = Utc::now();
        {
            let mut dev = self.devices.write().map_err(|e| RendezvousError::Store(e.to_string()))?;
            dev.retain(|_, d| {
                let age = now.signed_duration_since(d.last_seen);
                age.to_std().unwrap_or(Duration::ZERO) < max_age
            });
        }
        {
            let mut pairs = self.pairings.write().map_err(|e| RendezvousError::Store(e.to_string()))?;
            let now_inst = Instant::now();
            pairs.retain(|_, p| now_inst < p.expiry);
        }
        {
            let mut off = self.offers.write().map_err(|e| RendezvousError::Store(e.to_string()))?;
            off.retain(|_, o| {
                let elapsed = now.signed_duration_since(o.created_at).num_seconds();
                elapsed < o.ttl_secs as i64
            });
        }
        Ok(())
    }
}

// Epic 8: Rendezvous Signaling WebSocket Protocol Messages
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RendezvousMessage {
    RegisterHost {
        name: String,
        public_key: String,
    },
    HostRegistered {
        pairing_code: String,
    },
    RequestPairing {
        code: String,
        name: String,
        public_key: String,
    },
    PairingMatched {
        host_name: String,
        host_public_key: String,
    },
    ClientMatched {
        client_name: String,
        client_public_key: String,
    },
    SendCandidates {
        target_public_key: String,
        candidates: Vec<String>,
    },
    CandidatesReceived {
        from_public_key: String,
        candidates: Vec<String>,
    },
    Error {
        message: String,
    },
}

type PeerTx = tokio::sync::mpsc::UnboundedSender<RendezvousMessage>;

pub struct RendezvousServer {
    listen_addr: String,
    store: Arc<dyn RendezvousStore>,
    active_peers: Arc<RwLock<HashMap<String, PeerTx>>>,
}

impl RendezvousServer {
    pub fn new(listen_addr: String, store: Arc<dyn RendezvousStore>) -> Self {
        Self {
            listen_addr,
            store,
            active_peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        println!("====================================================");
        println!("ASCIIDesk Rendezvous Server starting...");
        println!("Listening on: {}", self.listen_addr);
        println!("Store Mode:   In-Memory WebSocket Signaling Broker");
        println!("====================================================");

        let store_clone = self.store.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let _ = store_clone.cleanup_expired(Duration::from_secs(300));
            }
        });

        let listener = TcpListener::bind(&self.listen_addr).await?;
        let active_peers = self.active_peers.clone();
        let store = self.store.clone();

        while let Ok((stream, peer_addr)) = listener.accept().await {
            let active_peers = active_peers.clone();
            let store = store.clone();

            tokio::spawn(async move {
                let ws_stream = match accept_async(stream).await {
                    Ok(ws) => ws,
                    Err(e) => {
                        error!("Rendezvous WS handshake error: {}", e);
                        return;
                    }
                };

                info!("New signaling connection from {}", peer_addr);
                let (mut ws_write, mut ws_read) = ws_stream.split();
                let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<RendezvousMessage>();

                // Write loop
                let write_task = tokio::spawn(async move {
                    while let Some(msg) = rx.recv().await {
                        if let Ok(serialized) = serde_json::to_string(&msg) {
                            if ws_write.send(WsMessage::Text(serialized)).await.is_err() {
                                break;
                            }
                        }
                    }
                });

                let mut device_key = None;

                // Read loop
                while let Some(msg_res) = ws_read.next().await {
                    match msg_res {
                        Ok(WsMessage::Text(text)) => {
                            if let Ok(parsed) = serde_json::from_str::<RendezvousMessage>(&text) {
                                match handle_message(parsed, &store, &active_peers, tx.clone(), &mut device_key) {
                                    Ok(Some(reply)) => {
                                        let _ = tx.send(reply);
                                    }
                                    Ok(None) => {}
                                    Err(e) => {
                                        let _ = tx.send(RendezvousMessage::Error { message: e });
                                    }
                                }
                            }
                        }
                        Ok(WsMessage::Close(_)) | Err(_) => {
                            break;
                        }
                        _ => {}
                    }
                }

                // Cleanup peer registration
                if let Some(ref key) = device_key {
                    let mut peers = active_peers.write().unwrap();
                    peers.remove(key);
                    info!("Rendezvous peer disconnected: {}", key);
                }
                write_task.abort();
            });
        }

        Ok(())
    }
}

fn handle_message(
    msg: RendezvousMessage,
    store: &Arc<dyn RendezvousStore>,
    active_peers: &Arc<RwLock<HashMap<String, PeerTx>>>,
    sender: PeerTx,
    device_key: &mut Option<String>,
) -> Result<Option<RendezvousMessage>, String> {
    match msg {
        RendezvousMessage::RegisterHost { name: _, public_key } => {
            *device_key = Some(public_key.clone());
            {
                let mut peers = active_peers.write().unwrap();
                peers.insert(public_key.clone(), sender);
            }

            // Generate 6 digit code
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let code = format!("{:06}", rng.gen_range(0..1000000));
            
            store.create_pairing_code(code.clone(), public_key, 300)
                .map_err(|e| e.to_string())?;

            Ok(Some(RendezvousMessage::HostRegistered { pairing_code: code }))
        }
        RendezvousMessage::RequestPairing { code, name, public_key } => {
            *device_key = Some(public_key.clone());
            {
                let mut peers = active_peers.write().unwrap();
                peers.insert(public_key.clone(), sender);
            }

            let host_pub_key = store.consume_pairing_code(&code)
                .map_err(|_| "Invalid pairing code or expired".to_string())?;

            let peers = active_peers.read().unwrap();
            if let Some(host_sender) = peers.get(&host_pub_key) {
                // Notify Host of client matching
                let _ = host_sender.send(RendezvousMessage::ClientMatched {
                    client_name: name,
                    client_public_key: public_key.clone(),
                });

                // Reply to Client with host info
                Ok(Some(RendezvousMessage::PairingMatched {
                    host_name: "Remote Host".to_string(),
                    host_public_key: host_pub_key,
                }))
            } else {
                Err("Matched host is currently offline".to_string())
            }
        }
        RendezvousMessage::SendCandidates { target_public_key, candidates } => {
            let from_key = device_key.as_ref().ok_or("Not registered".to_string())?;
            let peers = active_peers.read().unwrap();
            
            if let Some(target_sender) = peers.get(&target_public_key) {
                let _ = target_sender.send(RendezvousMessage::CandidatesReceived {
                    from_public_key: from_key.clone(),
                    candidates,
                });
                Ok(None)
            } else {
                Err("Target peer is offline".to_string())
            }
        }
        _ => Err("Invalid command sent to signaling server".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_store_device_presence() {
        let store = InMemoryStore::new();
        let dev = DevicePresence {
            public_key: "test-pub-key".to_string(),
            display_name: "test-device".to_string(),
            address: "127.0.0.1:7373".to_string(),
            last_seen: Utc::now(),
        };

        store.put_device(dev.clone()).unwrap();
        let loaded = store.get_device("test-pub-key").unwrap();
        assert_eq!(loaded.display_name, "test-device");
        assert_eq!(loaded.address, "127.0.0.1:7373");
    }

    #[test]
    fn test_in_memory_store_pairing_code() {
        let store = InMemoryStore::new();
        store.create_pairing_code("123456".to_string(), "host-pub".to_string(), 2).unwrap();

        // Consume pairing code
        let host_pub = store.consume_pairing_code("123456").unwrap();
        assert_eq!(host_pub, "host-pub");

        // Try consuming again (should be single-use)
        assert!(store.consume_pairing_code("123456").is_err());
    }

    #[tokio::test]
    async fn test_in_memory_store_expiry() {
        let store = InMemoryStore::new();
        store.create_pairing_code("111222".to_string(), "host-pub".to_string(), 1).unwrap();

        // Wait for expiry
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Try consuming expired code
        assert!(store.consume_pairing_code("111222").is_err());
    }

    #[test]
    fn test_in_memory_store_session_offer() {
        let store = InMemoryStore::new();
        let offer = SessionOffer {
            session_id: "session-1".to_string(),
            host_public_key: "host-pub".to_string(),
            client_public_key: "client-pub".to_string(),
            host_address_candidates: vec!["ws://1.1.1.1:7373".to_string()],
            client_address_candidates: vec![],
            created_at: Utc::now(),
            ttl_secs: 10,
        };

        store.put_session_offer(offer).unwrap();
        let loaded = store.get_session_offer("host-pub", "client-pub").unwrap();
        assert_eq!(loaded.session_id, "session-1");
        assert_eq!(loaded.host_address_candidates[0], "ws://1.1.1.1:7373");

        // Second retrieve should fail (single-use or consumed)
        assert!(store.get_session_offer("host-pub", "client-pub").is_err());
    }
}
