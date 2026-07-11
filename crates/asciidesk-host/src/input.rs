use enigo::{Enigo, Mouse, Keyboard, Coordinate, Button, Key, Direction, Settings};
use tracing::{info, warn};
use std::sync::Mutex;
use std::sync::OnceLock;

static ENIGO: OnceLock<Mutex<Enigo>> = OnceLock::new();

fn get_enigo() -> std::sync::MutexGuard<'static, Enigo> {
    ENIGO.get_or_init(|| {
        Mutex::new(Enigo::new(&Settings::default()).unwrap_or_else(|e| {
            warn!("Failed to initialize Enigo: {:?}", e);
            // Create a dummy/fallback Enigo if it fails?
            // Enigo::new might fail on headless without our hijacking
            panic!("Enigo init failed");
        }))
    }).lock().unwrap()
}

pub fn handle_mouse_input(x: i32, y: i32, button: u8, state: u8) {
    let mut enigo = get_enigo();
    
    // Move
    let _ = enigo.move_mouse(x, y, Coordinate::Abs);
    
    // Click
    let enigo_btn = match button {
        0 => Some(Button::Left),
        1 => Some(Button::Right),
        2 => Some(Button::Middle),
        _ => None,
    };
    
    if let Some(btn) = enigo_btn {
        let dir = match state {
            0 => Direction::Press,
            1 => Direction::Release,
            _ => Direction::Click,
        };
        let _ = enigo.button(btn, dir);
    }
}

pub fn handle_mouse_scroll(delta_x: i32, delta_y: i32) {
    let mut enigo = get_enigo();
    if delta_y != 0 {
        let _ = enigo.scroll(delta_y, enigo::Axis::Vertical);
    }
    if delta_x != 0 {
        let _ = enigo.scroll(delta_x, enigo::Axis::Horizontal);
    }
}

pub fn handle_keyboard_input(keycode: u32, state: u8) {
    let mut enigo = get_enigo();
    // Simplified mapping. crossterm keycodes to enigo keys
    // We will just assume it's sent as a char for now or basic mapping
    // To do it perfectly, we need a robust mapping from cross-platform keycodes
    // For now we will accept a u32 that represents the Unicode scalar
    if let Some(c) = std::char::from_u32(keycode) {
        let _ = enigo.text(&c.to_string());
    }
}
