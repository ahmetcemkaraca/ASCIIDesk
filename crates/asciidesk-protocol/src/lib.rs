use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    TerminalPty,
    TerminalResize,
    AnsiDesktopFrames,
    UnicodeHalfBlockFrames,
    SixelFrames,
    MouseInput,
    KeyboardInput,
    ClipboardText,
    FileTransfer,
    RelayFallback,
    TrustedDeviceAuth,
    DesktopStreaming,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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
    ConsentResponseAck,
    PtyInput {
        bytes: Vec<u8>,
    },
    PtyResize {
        cols: u16,
        rows: u16,
    },
    MouseInput {
        x: u16,
        y: u16,
        button: u8, // 0: Left, 1: Right, 2: Middle, 3: None (just move)
        state: u8,  // 0: Down, 1: Up, 2: Move
    },
    MouseScroll {
        delta_x: i32,
        delta_y: i32,
    },
    KeyboardInput {
        keycode: u32,
        state: u8, // 0: Down, 1: Up
    },
    ClipboardText {
        text: String,
    },
    SetZoom {
        zoom_factor: f32,
        pan_x: f32,
        pan_y: f32,
    },
    StartDesktopStream,
    StopDesktopStream,
    Ping,
    Close,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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
    DesktopFramePlaceholder {
        frame_id: u64,
        timestamp: u64,
        width_cells: u16,
        height_cells: u16,
        encoding: String,
        payload: Vec<u8>,
    },
    DesktopFrame {
        frame_text: String,
    },
    Error {
        code: String,
        message: String,
    },
    ClipboardText {
        text: String,
    },
    Pong,
    Close,
}

// Epic 8: ASCII Desktop Future Interfaces

#[derive(Debug, Clone)]
pub struct RawFrame {
    pub width: u32,
    pub height: u32,
    pub data: Vec<u8>, // RGBA pixels
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RenderProfile {
    MonochromeAscii,
    Ansi16,
    Ansi256,
    Truecolor,
    UnicodeHalfBlock,
    Braille,
}

#[derive(Debug, Clone)]
pub struct EncodedFrame {
    pub frame_id: u64,
    pub timestamp_ms: u64,
    pub width_cells: u16,
    pub height_cells: u16,
    pub profile: RenderProfile,
    pub payload: Vec<u8>, // Already encoded ANSI string/data
}

pub trait ScreenCaptureProvider {
    type Error;
    fn capture_frame(&mut self) -> Result<RawFrame, Self::Error>;
}

pub trait AsciiEncoder {
    type Error;
    fn encode(&mut self, raw_frame: &RawFrame, profile: RenderProfile) -> Result<EncodedFrame, Self::Error>;
}

pub trait InputInjector {
    type Error;
    fn send_mouse_event(&mut self, button: u8, x: u16, y: u16) -> Result<(), Self::Error>;
    fn send_keyboard_event(&mut self, key_code: u16, state: u8) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_to_host_serde() {
        let msg = ClientToHost::Hello {
            protocol_version: "1.0".to_string(),
            client_name: "test-client".to_string(),
            client_public_key: vec![1, 2, 3, 4],
            capabilities: vec![Capability::TerminalPty, Capability::TerminalResize],
        };

        let serialized = serde_json::to_string(&msg).unwrap();
        let deserialized: ClientToHost = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            ClientToHost::Hello { protocol_version, client_name, client_public_key, capabilities } => {
                assert_eq!(protocol_version, "1.0");
                assert_eq!(client_name, "test-client");
                assert_eq!(client_public_key, vec![1, 2, 3, 4]);
                assert_eq!(capabilities.len(), 2);
                assert!(capabilities.contains(&Capability::TerminalPty));
            }
            _ => panic!("Deserialization yielded incorrect variant"),
        }
    }

    #[test]
    fn test_host_to_client_serde() {
        let msg = HostToClient::HelloAck {
            protocol_version: "1.0".to_string(),
            host_name: "test-host".to_string(),
            host_public_key: vec![5, 6, 7, 8],
            capabilities: vec![Capability::TerminalPty],
        };

        let serialized = serde_json::to_string(&msg).unwrap();
        let deserialized: HostToClient = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            HostToClient::HelloAck { protocol_version, host_name, host_public_key, capabilities } => {
                assert_eq!(protocol_version, "1.0");
                assert_eq!(host_name, "test-host");
                assert_eq!(host_public_key, vec![5, 6, 7, 8]);
                assert_eq!(capabilities.len(), 1);
            }
            _ => panic!("Deserialization yielded incorrect variant"),
        }
    }
}

