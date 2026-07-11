use std::path::{Path, PathBuf};
use std::fs::{self, OpenOptions};
use std::io::Write;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use chrono::Utc;
use tracing::info;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Config directory not found")]
    ConfigDirNotFound,
    #[error("Invalid key format: {0}")]
    InvalidKey(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TrustedDevice {
    pub name: String,
    pub fingerprint: String,
    pub public_key: String, // base64 encoded public key
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub device_name: String,
    pub private_key: String, // base64 encoded signing key (32 bytes seed)
    pub public_key: String,  // base64 encoded verifying key (32 bytes)
    pub trusted_devices: Vec<TrustedDevice>,
}

pub struct ConfigManager {
    config_dir: PathBuf,
    config_path: PathBuf,
}

impl ConfigManager {
    pub fn new(custom_path: Option<&Path>) -> Result<Self, CoreError> {
        let config_dir = if let Some(path) = custom_path {
            path.to_path_buf()
        } else {
            dirs::config_dir()
                .ok_or(CoreError::ConfigDirNotFound)?
                .join("ASCIIDesk")
        };

        let config_path = config_dir.join("config.json");
        Ok(Self { config_dir, config_path })
    }

    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    pub fn load_or_create(&self) -> Result<Config, CoreError> {
        if !self.config_dir.exists() {
            fs::create_dir_all(&self.config_dir)?;
        }

        if self.config_path.exists() {
            let content = fs::read_to_string(&self.config_path)?;
            let config: Config = serde_json::from_str(&content)?;
            Ok(config)
        } else {
            let config = self.generate_default_config()?;
            self.save(&config)?;
            Ok(config)
        }
    }

    pub fn save(&self, config: &Config) -> Result<(), CoreError> {
        if !self.config_dir.exists() {
            fs::create_dir_all(&self.config_dir)?;
        }
        let content = serde_json::to_string_pretty(config)?;
        fs::write(&self.config_path, content)?;
        Ok(())
    }

    fn generate_default_config(&self) -> Result<Config, CoreError> {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let private_key_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, signing_key.to_bytes());
        let public_key_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, verifying_key.to_bytes());

        // Get local OS username or computer name for a friendly default device name
        let device_name = whoami_device_name();

        Ok(Config {
            device_name,
            private_key: private_key_b64,
            public_key: public_key_b64,
            trusted_devices: Vec::new(),
        })
    }
}

fn whoami_device_name() -> String {
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "Unknown Device".to_string());
    format!("asciidesk-{}", hostname)
}

// Key utilities
pub fn parse_signing_key(b64_key: &str) -> Result<SigningKey, CoreError> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64_key)
        .map_err(|e| CoreError::InvalidKey(e.to_string()))?;
    let array: [u8; 32] = bytes.try_into()
        .map_err(|_| CoreError::InvalidKey("Key must be 32 bytes".to_string()))?;
    Ok(SigningKey::from_bytes(&array))
}

pub fn parse_verifying_key(b64_key: &str) -> Result<VerifyingKey, CoreError> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64_key)
        .map_err(|e| CoreError::InvalidKey(e.to_string()))?;
    let array: [u8; 32] = bytes.try_into()
        .map_err(|_| CoreError::InvalidKey("Key must be 32 bytes".to_string()))?;
    VerifyingKey::from_bytes(&array)
        .map_err(|e| CoreError::InvalidKey(e.to_string()))
}

pub fn get_fingerprint(public_key_b64: &str) -> String {
    if let Ok(bytes) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, public_key_b64) {
        hex::encode(&bytes[0..8.min(bytes.len())]).to_uppercase()
    } else {
        "UNKNOWN".to_string()
    }
}

// Audit Logger
pub struct AuditLogger {
    log_path: PathBuf,
}

impl AuditLogger {
    pub fn new(config_dir: &Path) -> Self {
        Self {
            log_path: config_dir.join("session_audit.log"),
        }
    }

    pub fn log_session(
        &self,
        client_fingerprint: &str,
        client_ip: &str,
        verdict: &str, // "Approved", "Denied", "Timeout"
        mode: &str,    // "PTY", "Desktop"
        duration_secs: Option<u64>,
    ) -> Result<(), std::io::Error> {
        let timestamp = Utc::now().to_rfc3339();
        let log_line = format!(
            "[{}] Fingerprint: {} | IP: {} | Verdict: {} | Mode: {} | Duration: {}\n",
            timestamp,
            client_fingerprint,
            client_ip,
            verdict,
            mode,
            duration_secs
                .map(|s| format!("{}s", s))
                .unwrap_or_else(|| "N/A".to_string())
        );

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;
        file.write_all(log_line.as_bytes())?;
        info!("Audit logged to {:?}", self.log_path);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_generation() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let pub_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, verifying_key.to_bytes());
        
        let fp = get_fingerprint(&pub_b64);
        assert_eq!(fp.len(), 16); // Hex-encoded 8 bytes = 16 characters
    }

    #[test]
    fn test_config_load_and_save() {
        let temp_dir = std::env::temp_dir().join(format!("asciidesk_test_{}", rand::random::<u32>()));
        let manager = ConfigManager::new(Some(&temp_dir)).unwrap();
        
        // 1. Initial creation
        let mut config = manager.load_or_create().unwrap();
        assert!(!config.device_name.is_empty());
        assert!(!config.private_key.is_empty());
        assert!(config.trusted_devices.is_empty());

        // 2. Add trusted device
        config.trusted_devices.push(TrustedDevice {
            name: "test-client".to_string(),
            fingerprint: "AA11BB22CC33DD44".to_string(),
            public_key: "some-key".to_string(),
        });
        manager.save(&config).unwrap();

        // 3. Reload config and verify
        let reloaded = manager.load_or_create().unwrap();
        assert_eq!(reloaded.trusted_devices.len(), 1);
        assert_eq!(reloaded.trusted_devices[0].name, "test-client");
        assert_eq!(reloaded.trusted_devices[0].fingerprint, "AA11BB22CC33DD44");

        // Cleanup
        let _ = fs::remove_dir_all(temp_dir);
    }
}

