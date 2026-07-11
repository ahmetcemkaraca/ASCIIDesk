# ASCIIDesk Epics & Acceptance Criteria

This document tracks development epics and specific acceptance criteria for the ASCIIDesk project.

---

## Epic 1: Repository Scaffold and Architecture Docs
**Goal**: Establish the Rust workspace, crate directory layout, and complete architectural documentation.
*   **Acceptance Criteria**:
    *   Rust workspace `Cargo.toml` parses correctly.
    *   All requested documentation files exist (`README.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/PROTOCOL.md`, `docs/ROADMAP.md`, `docs/EPICS.md`, `docs/THREAT_MODEL.md`).
    *   `cargo run -p asciidesk-cli -- --help` prints command usage and options successfully.

---

## Epic 2: Protocol and Transport
**Goal**: Implement capabilities negotiation, versioning, message serialization, and WebSocket networking.
*   **Acceptance Criteria**:
    *   Protocol messages `ClientToHost` and `HostToClient` serialize/deserialize without data loss.
    *   Handshake sequence executes (Hello from client -> HelloAck from host -> AuthRequired).
    *   WebSocket transport handles connections, disconnection detection, and heartbeat (ping/pong).
    *   Unit tests cover serialization of all message variants.

---

## Epic 3: Device Identity and Local Config
**Goal**: Generate secure, persistent device identity keypairs and handle local settings (including trust stores).
*   **Acceptance Criteria**:
    *   On first startup, the app creates a secure folder structure under the OS-appropriate config directory (e.g., `AppData\Roaming\ASCIIDesk` on Windows).
    *   An Ed25519 identity keypair is generated and stored securely.
    *   Stable device fingerprint (e.g., hex or base64 of public key hash) is generated and displayed.
    *   Trusted client fingerprints can be saved, removed, and listed via `asciidesk trust` commands.

---

## Epic 4: Windows Host PTY
**Goal**: Spawn PTY sessions, prompt for user consent, and bridge I/O between the PTY process and the WebSocket server.
*   **Acceptance Criteria**:
    *   Host accepts connections and validates pairing codes.
    *   Host displays a clear visual terminal prompt: `"Incoming ASCIIDesk terminal session from <client fingerprint/display name>. Allow? [y/N]"`.
    *   Upon approval, host spawns PowerShell/cmd via ConPTY (`portable-pty`).
    *   PTY output is captured and sent over the WebSocket.
    *   Incoming inputs are successfully written to the PTY.

---

## Epic 5: Windows/Linux Terminal Client
**Goal**: Build a TUI client that hooks stdin/stdout, manages Raw terminal state, and renders remote PTY stream.
*   **Acceptance Criteria**:
    *   Client successfully connects, performs handshake, and sends the pairing code.
    *   TUI starts, raw mode is enabled, and incoming PTY characters/escape codes render accurately.
    *   Local keyboard input is sent directly to the host.
    *   Window resize events (cols/rows) are monitored and forwarded to the host's PTY.
    *   Exiting (Ctrl+D or exit command) returns the terminal back to normal scroll/cooked state.

---

## Epic 6: Audit and Safety Controls
**Goal**: Build auditing mechanisms and safety parameters to enforce user consent.
*   **Acceptance Criteria**:
    *   Sessions (both accepted and denied) are logged locally in `session_audit.log` with timestamps, fingerprints, and IP.
    *   Headless mode requires the explicit `--headless` flag.
    *   Without `--headless` and pre-authorized trust, unauthorized incoming sessions are auto-denied or prompt host.
    *   Headless mode blocks desktop-control mode and allows connection only for pre-authorized trusted devices.

---

## Epic 7: Minimal Rendezvous Skeleton
**Goal**: Provide a lightweight, in-memory broker service to coordinate connection handshakes without proxying console/PTY payload data.
*   **Acceptance Criteria**:
    *   Rendezvous server listens on a custom port and maintains ephemeral pairing codes.
    *   Implements `RendezvousStore` trait with in-memory storage.
    *   Cleans up expired pairs periodically.
    *   Exchanges client/host endpoints to establish direct connection.

---

## Epic 8: ASCII Desktop Interfaces
**Goal**: Define the extensibility points (traits, messages, enums) for future screenshot streaming and input injection.
*   **Acceptance Criteria**:
    *   `ScreenCaptureProvider`, `AsciiEncoder`, and `InputInjector` traits are defined.
    *   `RenderProfile` enums and frame structs compile under `crates/asciidesk-protocol`.
    *   No unsafe control execution occurs in MVP-1.

---

## Epic 9: Packaging Roadmap
**Goal**: Document the build process, binary distribution, and future package managers wrapper.
*   **Acceptance Criteria**:
    *   Clear instructions exist on compiling release binaries.
    *   Architecture documents reference future npm/npx-based distribution.
