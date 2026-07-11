# ASCIIDesk Release Roadmap

This document maps the evolution of ASCIIDesk from MVP to a full-featured terminal-based remote access tool.

---

## Phase 0: Terminal Remote Core
*   [x] Set up workspace and CLI scaffolding.
*   [x] Establish versioned protocol structures and capability negotiation.
*   [x] Define cryptographic identity and trust management commands.
*   [x] Write basic WebSocket client-server transport layers.

## Phase 1: Windows Host & Linux Client MVP (Current Objective)
*   [x] Integrate `portable-pty` for ConPTY launching on Windows hosts.
*   [x] Build local host consent prompts and audit logging.
*   [x] Build client raw terminal reader and crossterm TUI render loop.
*   [x] Implement window resize signal forwarding.
*   [x] Add direct-connection support with one-time pairing codes.

## Phase 2: Linux Host & Multi-platform Client Support
*   [ ] Integrate Unix PTY spawning for Linux hosts.
*   [ ] Ensure raw-terminal teardown is resilient to sudden network terminations.
*   [ ] Extend rendezvous metadata server to support NAT traversal/hole punching.

## Phase 3: ASCII Desktop Capture and Streaming
*   [ ] Define `ScreenCaptureProvider` (captures desktop frames).
*   [ ] Implement host-side `AsciiEncoder` converting screenshots to color/ANSI/Unicode blocks.
*   [ ] Build client-side frames renderer utilizing high-performance Crossterm queues.
*   [ ] Support custom render profiles (monochrome, 16-color, truecolor, braille).

## Phase 4: Full GUI Remote Control
*   [ ] Implement Windows/Linux mouse and keyboard input injection interfaces.
*   [ ] Create visible host session HUD overlay and permission scopes.
*   [ ] Support clipboard sharing and file transfer via protocol extensions.

## Phase 5: Client Ecosystem & Relay
*   [ ] Build browser client (TUI interface compiled to WebAssembly).
*   [ ] Build mobile clients (Android/iOS terminals).
*   [ ] Introduce end-to-end encrypted relay fallback service.
*   [ ] Publish npm/npx wrappers for lightweight zero-install clients.
