pub fn hijack_active_session() {
    #[cfg(target_os = "linux")]
    {
        use tracing::{info, warn};
        use std::process::Command;
        
        // 1. Try to find the Xorg process and extract its -auth parameter
        let output = Command::new("ps")
            .args(["xww", "-e", "-o", "command"])
            .output();
            
        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            let mut found_auth = None;
            let mut found_display = None;
            
            for line in stdout.lines() {
                if line.contains("Xorg") || line.contains("Xwayland") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    for i in 0..parts.len() {
                        if parts[i] == "-auth" && i + 1 < parts.len() {
                            found_auth = Some(parts[i + 1].to_string());
                        }
                        if (parts[i] == "-display" || parts[i] == ":0" || parts[i] == ":1") && parts[i].starts_with(':') {
                            found_display = Some(parts[i].to_string());
                        }
                    }
                }
                
                // Sometimes x11vnc or similar tools expose it explicitly
                if line.contains("-auth") && line.contains("-display") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    for i in 0..parts.len() {
                        if parts[i] == "-auth" && i + 1 < parts.len() {
                            found_auth = Some(parts[i + 1].to_string());
                        }
                        if parts[i] == "-display" && i + 1 < parts.len() {
                            found_display = Some(parts[i + 1].to_string());
                        }
                    }
                }
            }
            
            // Default to :0 if we found Xorg but no explicit display argument
            let display_env = found_display.unwrap_or_else(|| ":0".to_string());
            
            if let Some(auth) = found_auth {
                info!("Hijacking GUI session! Found DISPLAY={} XAUTHORITY={}", display_env, auth);
                std::env::set_var("DISPLAY", display_env);
                std::env::set_var("XAUTHORITY", auth);
            } else {
                warn!("Could not find XAUTHORITY in running processes. Assuming no active X11 GUI.");
                // Try fallback for Wayland (very basic)
                if std::env::var("WAYLAND_DISPLAY").is_err() {
                    // Wayland usually requires standard user execution, but we try a blind fallback just in case
                    std::env::set_var("WAYLAND_DISPLAY", "wayland-0");
                }
            }
        }
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        tracing::info!("Session hijacking not required for this OS.");
    }
}
