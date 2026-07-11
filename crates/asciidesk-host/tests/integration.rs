use std::net::TcpListener as StdListener;
use std::time::Duration;
use tokio_tungstenite::connect_async;
use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;

use asciidesk_core::{Config, TrustedDevice, get_fingerprint};
use asciidesk_host::{Host, HostOptions};
use asciidesk_protocol::{Capability, ClientToHost, HostToClient};
use asciidesk_transport::MessageStream;

fn get_free_port() -> u16 {
    let listener = StdListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

#[tokio::test]
async fn test_cryptographic_trusted_auth_flow() {
    let temp_dir = std::env::temp_dir().join(format!("asciidesk_integration_test_{}", rand::random::<u32>()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    // 1. Generate client keypair
    let mut csprng = OsRng;
    let client_signing_key = SigningKey::generate(&mut csprng);
    let client_verifying_key = client_signing_key.verifying_key();
    let _client_private_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, client_signing_key.to_bytes());
    let client_public_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, client_verifying_key.to_bytes());
    let client_fp = get_fingerprint(&client_public_b64);

    // 2. Generate host keypair
    let host_signing_key = SigningKey::generate(&mut csprng);
    let host_verifying_key = host_signing_key.verifying_key();
    let host_private_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, host_signing_key.to_bytes());
    let host_public_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, host_verifying_key.to_bytes());

    // 3. Pre-create Host's config.json with Client in trusted list
    let host_config = Config {
        device_name: "test-host".to_string(),
        private_key: host_private_b64,
        public_key: host_public_b64,
        trusted_devices: vec![TrustedDevice {
            name: "test-client".to_string(),
            fingerprint: client_fp,
            public_key: client_public_b64,
        }],
    };

    let config_json = serde_json::to_string_pretty(&host_config).unwrap();
    std::fs::write(temp_dir.join("config.json"), config_json).unwrap();

    // 4. Start Host on a free port
    let port = get_free_port();
    let listen_addr = format!("127.0.0.1:{}", port);

    let host_opts = HostOptions {
        listen_addr: listen_addr.clone(),
        name: None,
        shell: None,
        headless: false,
        allow_trusted: true,
        config_path: Some(temp_dir.clone()),
        rendezvous: None,
    };

    let host = Host::new(host_opts).unwrap();

    // Spawn Host run loop
    let _host_handle = tokio::spawn(async move {
        if let Err(e) = host.run().await {
            eprintln!("Host run failed: {:?}", e);
        }
    });

    // Wait slightly for host to start
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 5. Connect Client using tokio-tungstenite & MessageStream
    let connect_url = format!("ws://{}", listen_addr);
    let (ws_stream, _) = connect_async(&connect_url).await.unwrap();
    let mut client_stream = MessageStream::<ClientToHost, HostToClient, _>::new(ws_stream);

    // 6. Send Hello
    client_stream.send(&ClientToHost::Hello {
        protocol_version: "1.0".to_string(),
        client_name: "test-client".to_string(),
        client_public_key: client_verifying_key.to_bytes().to_vec(),
        capabilities: vec![Capability::TerminalPty, Capability::TerminalResize],
    }).await.unwrap();

    // 7. Expect HelloAck
    let ack = client_stream.next().await.unwrap();
    match ack {
        HostToClient::HelloAck { protocol_version, host_name, .. } => {
            assert_eq!(protocol_version, "1.0");
            assert_eq!(host_name, "test-host");
        }
        other => panic!("Expected HelloAck, got {:?}", other),
    }

    // 8. Expect AuthRequired (with challenge)
    let auth_req = client_stream.next().await.unwrap();
    let challenge = match auth_req {
        HostToClient::AuthRequired { challenge } => {
            assert_eq!(challenge.len(), 32, "Challenge should be 32 bytes for cryptographic auth");
            challenge
        }
        other => panic!("Expected AuthRequired, got {:?}", other),
    };

    // 9. Sign challenge and send ChallengeResponse
    let signature = client_signing_key.sign(&challenge);
    client_stream.send(&ClientToHost::ChallengeResponse {
        signature: signature.to_vec(),
    }).await.unwrap();

    // 10. Expect AuthAccepted
    let auth_res = client_stream.next().await.unwrap();
    match auth_res {
        HostToClient::AuthAccepted => {}
        other => panic!("Expected AuthAccepted, got {:?}", other),
    }

    // Clean up
    let _ = std::fs::remove_dir_all(&temp_dir);
}
