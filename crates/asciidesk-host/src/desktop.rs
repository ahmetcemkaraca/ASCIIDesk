use std::time::{SystemTime, UNIX_EPOCH};
use asciidesk_protocol::{
    RawFrame, EncodedFrame, RenderProfile, ScreenCaptureProvider, AsciiEncoder,
};
use xcap::Monitor;

pub struct XcapCaptureProvider {
    monitor: Option<Monitor>,
}

impl XcapCaptureProvider {
    pub fn new() -> Self {
        let monitor = Monitor::all().ok().and_then(|s| s.into_iter().next());
        Self { monitor }
    }
}

impl ScreenCaptureProvider for XcapCaptureProvider {
    type Error = String;

    fn capture_frame(&mut self) -> Result<RawFrame, Self::Error> {
        let monitor = self.monitor.as_ref().ok_or_else(|| "No active monitor found".to_string())?;
        let image = monitor.capture_image()
            .map_err(|e| format!("Monitor capture failed: {:?}", e))?;
            
        Ok(RawFrame {
            width: image.width(),
            height: image.height(),
            data: image.into_raw(),
        })
    }
}

pub struct DefaultAsciiEncoder {
    frame_count: u64,
}

impl DefaultAsciiEncoder {
    pub fn new() -> Self {
        Self { frame_count: 0 }
    }
}

impl AsciiEncoder for DefaultAsciiEncoder {
    type Error = String;

    fn encode(&mut self, raw_frame: &RawFrame, profile: RenderProfile) -> Result<EncodedFrame, Self::Error> {
        self.frame_count += 1;
        
        // Default target terminal dimensions
        let width_cells = 80u16;
        let height_cells = 24u16;

        let w = raw_frame.width as usize;
        let h = raw_frame.height as usize;
        let w_cells = width_cells as usize;
        let h_cells = height_cells as usize;

        let mut payload = Vec::new();

        for cy in 0..h_cells {
            for cx in 0..w_cells {
                // Calculate pixel bounds for downsampling
                let x_start = cx * w / w_cells;
                let x_end = ((cx + 1) * w / w_cells).min(w);
                let y_start = cy * h / h_cells;
                let y_end = ((cy + 1) * h / h_cells).min(h);

                let mut r_sum = 0u64;
                let mut g_sum = 0u64;
                let mut b_sum = 0u64;
                let mut count = 0u64;

                for y in y_start..y_end {
                    for x in x_start..x_end {
                        let idx = (y * w + x) * 4;
                        if idx + 3 < raw_frame.data.len() {
                            r_sum += raw_frame.data[idx] as u64;
                            g_sum += raw_frame.data[idx + 1] as u64;
                            b_sum += raw_frame.data[idx + 2] as u64;
                            count += 1;
                        }
                    }
                }

                // Average colors
                let (r, g, b) = if count > 0 {
                    (
                        (r_sum / count) as u8,
                        (g_sum / count) as u8,
                        (b_sum / count) as u8,
                    )
                } else {
                    (0, 0, 0)
                };

                // Map to profile
                match profile {
                    RenderProfile::MonochromeAscii => {
                        let y_lum = (0.2126 * r as f32 + 0.7152 * g as f32 + 0.0722 * b as f32) as u8;
                        let ramp = b" .:-=+*#%@";
                        let ramp_idx = (y_lum as usize * (ramp.len() - 1)) / 255;
                        payload.push(ramp[ramp_idx]);
                    }
                    RenderProfile::Truecolor | RenderProfile::UnicodeHalfBlock | RenderProfile::Braille => {
                        let ansi = format!("\x1b[38;2;{};{};{}m█", r, g, b);
                        payload.extend_from_slice(ansi.as_bytes());
                    }
                    RenderProfile::Ansi256 => {
                        let r_idx = (r as u32 * 5 / 255) as u8;
                        let g_idx = (g as u32 * 5 / 255) as u8;
                        let b_idx = (b as u32 * 5 / 255) as u8;
                        let color_idx = 16 + 36 * r_idx + 6 * g_idx + b_idx;
                        let ansi = format!("\x1b[38;5;{}m█", color_idx);
                        payload.extend_from_slice(ansi.as_bytes());
                    }
                    RenderProfile::Ansi16 => {
                        let mut ansi_code = 30;
                        if r >= 128 { ansi_code += 1; }
                        if g >= 128 { ansi_code += 2; }
                        if b >= 128 { ansi_code += 4; }
                        if r > 200 || g > 200 || b > 200 { ansi_code += 60; }
                        let ansi = format!("\x1b[{}m█", ansi_code);
                        payload.extend_from_slice(ansi.as_bytes());
                    }
                }
            }
            payload.extend_from_slice(b"\n");
        }
        
        payload.extend_from_slice(b"\x1b[0m");

        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Ok(EncodedFrame {
            frame_id: self.frame_count,
            timestamp_ms,
            width_cells,
            height_cells,
            profile,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ascii_encoder_monochrome() {
        let mut encoder = DefaultAsciiEncoder::new();
        // Create 80x24 red pixels
        let mut pixels = vec![0u8; 80 * 24 * 4];
        for i in 0..80 * 24 {
            pixels[i * 4] = 255;     // R
            pixels[i * 4 + 1] = 0;   // G
            pixels[i * 4 + 2] = 0;   // B
            pixels[i * 4 + 3] = 255; // A
        }

        let raw = RawFrame {
            width: 80,
            height: 24,
            data: pixels,
        };

        let encoded = encoder.encode(&raw, RenderProfile::MonochromeAscii).unwrap();
        assert_eq!(encoded.frame_id, 1);
        assert_eq!(encoded.width_cells, 80);
        assert_eq!(encoded.height_cells, 24);
        assert!(!encoded.payload.is_empty());
    }

    #[test]
    fn test_ascii_encoder_truecolor() {
        let mut encoder = DefaultAsciiEncoder::new();
        // Create 160x48 blue pixels
        let mut pixels = vec![0u8; 160 * 48 * 4];
        for i in 0..160 * 48 {
            pixels[i * 4] = 0;
            pixels[i * 4 + 1] = 0;
            pixels[i * 4 + 2] = 255;
            pixels[i * 4 + 3] = 255;
        }

        let raw = RawFrame {
            width: 160,
            height: 48,
            data: pixels,
        };

        let encoded = encoder.encode(&raw, RenderProfile::Truecolor).unwrap();
        assert_eq!(encoded.frame_id, 1);
        assert_eq!(encoded.width_cells, 80);
        assert_eq!(encoded.height_cells, 24);
        assert!(!encoded.payload.is_empty());
        // Verify truecolor ANSI escape codes exist in payload
        let payload_str = String::from_utf8(encoded.payload).unwrap();
        assert!(payload_str.contains("\x1b[38;2;"));
    }
}

