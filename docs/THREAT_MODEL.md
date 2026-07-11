# ASCIIDesk Threat Model

This document outlines the assets, entry points, threats, and security controls for the ASCIIDesk architecture.

---

## 1. System Assets
*   **Host Shell Access**: Terminal command execution context (user privileges).
*   **Device Private Keys**: Ed25519 private keys stored locally on host and client.
*   **Trusted Devices configuration**: Local trust store JSON, defining authorization whitelist.
*   **Audit logs**: History of session accesses.

---

## 2. Attack Vectors & Threat Scenarios

| Threat | Target | Description | Mitigation |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Host Identity | A malicious host impersonates a legitimate host. | Host signs a hello challenge using its persistent identity key. Client verifies the host's public key fingerprint. |
| **Tampering** | Session I/O | An attacker in the network path alters PTY input or output. | Connection runs over TLS or Noise Protocol. Handshake requires cryptographically signed tokens. |
| **Information Disclosure** | Relay Broker | Eavesdropping on a rendezvous relay. | Relays cannot read console streams because terminal data is never routed through the rendezvous service; direct WebSockets are preferred. |
| **Elevation of Privilege** | Host Machine | Executing commands with elevated admin rights. | ASCIIDesk runs purely in user-space without any kernel components or service configurations. Elevated access is restricted to the host process's context. |
| **Denial of Service** | Host Server | Flooding host port with bogus auth requests. | Short timeouts, strict limits on maximum simultaneous connections, and instant socket drop for invalid pairing codes. |
| **Covert Surveillance** | Remote Host | Attacker utilizes headless mode to silently capture host desktop. | Headless mode (`--headless`) completely blocks graphical desktop frames/control. It only allows PTY terminal sessions. |

---

## 3. Secure Defaults
*   **Default Deny**: Connections from untrusted client fingerprints are rejected unless a correct pairing code is supplied AND the host owner clicks "y" at the consent prompt.
*   **Single-use Pairing Code**: Active pairing codes are randomized on start, expire after 5 minutes, and are wiped immediately upon verification success/failure.
*   **No Auto-Persistence**: ASCIIDesk does not add registry run keys, systemd services, or cron tasks by default. Launching requires explicit execution.
