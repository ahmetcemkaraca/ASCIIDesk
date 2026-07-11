# ASCIIDesk Protocol Specification

This document details the connection sequence and message formats exchanged between an ASCIIDesk client and host.

---

## 1. Protocol Messages (JSON Serialization)

Messages are serialized as JSON over a WebSocket connection.

### Client-to-Host Messages (`ClientToHost`)

```rust
pub enum ClientToHost {
    Hello {
        protocol_version: String,
        client_name: String,
        client_public_key: Vec<u8>,
        capabilities: Vec<Capability>,
    },
    PairingCode {
        code: String,
    },
    ChallengeResponse {
        signature: Vec<u8>,
    },
    PtyInput {
        bytes: Vec<u8>,
    },
    PtyResize {
        cols: u16,
        rows: u16,
    },
    Ping,
    Close,
}
```

### Host-to-Client Messages (`HostToClient`)

```rust
pub enum HostToClient {
    HelloAck {
        protocol_version: String,
        host_name: String,
        host_public_key: Vec<u8>,
        capabilities: Vec<Capability>,
    },
    AuthRequired {
        challenge: Vec<u8>,
    },
    AuthAccepted,
    AuthDenied {
        reason: String,
    },
    PtyOutput {
        bytes: Vec<u8>,
    },
    PtyExit {
        exit_code: i32,
    },
    Error {
        code: String,
        message: String,
    },
    Pong,
    Close,
}
```

---

## 2. Capabilities Enums

Capabilities represent supported features. During the handshake, both sides send their list, and the negotiated feature set is the intersection of these capabilities.

*   `TerminalPty`: Basic terminal stream.
*   `TerminalResize`: Ability to resize the host PTY based on the client window size.
*   `AnsiDesktopFrames`: Streaming graphical screen converted to color/ANSI text.
*   `MouseInput`: Mouse tracking and click injection.
*   `KeyboardInput`: Raw keyboard events.
*   `ClipboardText`: Synchronize clipboard changes.
*   `FileTransfer`: In-band file transfer support.

---

## 3. Session Connection Sequence

### Step 1: Handshake
1.  **Client connects** via WebSocket.
2.  **Client sends** `ClientToHost::Hello`.
3.  **Host responds** with `HostToClient::HelloAck`.

### Step 2: Authentication
The host issues an authentication challenge.
1.  **Host sends** `HostToClient::AuthRequired { challenge }` (containing 32 random bytes).
2.  **Client decides authentication pathway**:
    *   **Option A: Trusted Device Path**:
        *   Client signs the challenge bytes with its Ed25519 private key.
        *   Client sends `ClientToHost::ChallengeResponse { signature }`.
        *   Host verifies the signature using the client's public key (retrieved from `ClientToHost::Hello` and checked against the host's local trusted device list).
    *   **Option B: One-Time Pairing Code Path**:
        *   Client sends `ClientToHost::PairingCode { code }`.
        *   Host verifies the code matches its active ephemeral pairing code.
3.  **Host Consent Prompt (if not trusted)**:
    *   If the pairing code is correct, the host checks if the device is trusted.
    *   If untrusted, the host prompts the local operator: `"Incoming ASCIIDesk terminal session from <client name> (<fingerprint>). Allow? [y/N]"`.
    *   If accepted (or if trusted device auth succeeded), the host adds the client to the trusted list if requested, and sends `HostToClient::AuthAccepted`.
    *   If rejected, the host sends `HostToClient::AuthDenied` and terminates the connection.

### Step 3: Session Active
*   Client sends keyboard input via `ClientToHost::PtyInput { bytes }`.
*   Host sends terminal output via `HostToClient::PtyOutput { bytes }`.
*   Client sends window size changes via `ClientToHost::PtyResize { cols, rows }`.
*   Heartbeats are maintained with periodic `Ping`/`Pong` exchanges.
