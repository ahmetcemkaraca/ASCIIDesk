# ASCIIDesk Security Model & Policy

ASCIIDesk is designed for legitimate, consent-based remote terminal and screen access. It enforces strong security constraints by default to prevent abuse.

---

## 1. Consent Model
No connection can be established without explicit, real-time approval from the host machine's operator, unless the host has been explicitly configured to trust a specific client.

*   **Interactive Consent**: When an untrusted client connects, a prompt is shown in the host's terminal asking the operator to approve (`y/N`).
*   **Time-Bound Pairing Codes**: The host prints a random, short-lived, single-use pairing code. The client must supply this code to request authorization.
*   **Visible Active Session**: While a client is connected, the host displays a clear visual session indicator. The session can be terminated immediately by the host at any time.

---

## 2. Trusted Device Model
A host owner can choose to enroll trusted clients to bypass interactive consent.
*   **Public Key Cryptography**: Devices identify themselves using unique Ed25519 public key fingerprints.
*   **Explicit Enrollment**: A device fingerprint can only be trusted by running command-line commands locally on the host machine:
    *   `asciidesk trust list`
    *   `asciidesk trust remove <fingerprint>`
    *   `asciidesk trust clear`
*   **No Silent Trust**: Trust configuration is stored in a plain-text configuration file under the user's config directory, audit-ready and editable.

---

## 3. Threat Model Summary
*   **Impersonation**: Mitigated by cryptographically signing handshakes. Clients cannot spoof fingerprints because they must sign a handshake challenge with their private key.
*   **Eavesdropping (Relay)**: The rendezvous service only helps establish the direct WebSocket connection. No terminal payload data passes through the rendezvous service.
*   **Unauthorized Headless Access**: Headless mode (`--headless`) requires an explicit CLI flag. It disables interactive consent but enforces that *only* registered trusted devices can connect. Headless mode also completely disables desktop capture capabilities (once implemented) to prevent covert surveillance.
*   **Privilege Escalation**: ASCIIDesk runs in user-space and does not include any service installer or automatic privilege escalation code. It respects the standard OS permissions of the running user.

---

## 4. Data Minimization
*   **No Central Collection**: Screen, terminal, input, or file data is never sent to or cached on any central server.
*   **No Sensitive Logs**: Pairing codes are never written to persistent logs. Audit logs only store the connection metadata (timestamp, client fingerprint, IP address, and acceptance verdict).
*   **Optional Rendezvous**: The rendezvous service is self-hostable and does not persist any long-lived tracking data. It uses memory-only storage by default.

---

## 5. No Stealth Behavior Policy
ASCIIDesk explicitly prohibits features that support covert monitoring:
*   No background process hiding.
*   No automatic silent installation without a terminal prompt.
*   No credential dumping or OS security prompt bypasses.
*   Every active session must be visibly auditable by both endpoints.
