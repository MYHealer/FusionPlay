//! airkan keyCode → RemoteKey 映射
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::RemoteKey;

/// Android KeyEvent keyCode 常量
pub mod code {
    pub const DPAD_UP: i32 = 19;
    pub const DPAD_DOWN: i32 = 20;
    pub const DPAD_LEFT: i32 = 21;
    pub const DPAD_RIGHT: i32 = 22;
    pub const DPAD_CENTER: i32 = 23;
    pub const VOLUME_UP: i32 = 24;
    pub const VOLUME_DOWN: i32 = 25;
    pub const POWER: i32 = 26;
    pub const ENTER: i32 = 66;
}

/// 按键动作（TLV subcode=2）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyAction {
    pub key_code: i32,
    pub action: i32, // 0=DOWN 1=UP
}

/// 把 keyCode 映射为语义动作；未映射返回 Unknown。
pub fn keymap(key_code: i32, action: i32) -> RemoteKey {
    let k = match key_code {
        code::DPAD_UP => RemoteKey::Next,
        code::DPAD_DOWN => RemoteKey::Prev,
        code::DPAD_LEFT => RemoteKey::SeekBack,
        code::DPAD_RIGHT => RemoteKey::SeekForward,
        code::DPAD_CENTER | code::ENTER => RemoteKey::PlayPause,
        code::VOLUME_UP => RemoteKey::VolUp,
        code::VOLUME_DOWN => RemoteKey::VolDown,
        code::POWER => RemoteKey::Power,
        _ => RemoteKey::Unknown {
            key_code: key_code as u32,
            key_action: action as u32,
        },
    };
    k
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RemoteKey;

    #[test]
    fn map_known() {
        assert_eq!(keymap(code::DPAD_UP, 0), RemoteKey::Next);
        assert_eq!(keymap(code::DPAD_DOWN, 0), RemoteKey::Prev);
        assert_eq!(keymap(code::ENTER, 0), RemoteKey::PlayPause);
        assert_eq!(keymap(code::VOLUME_UP, 0), RemoteKey::VolUp);
        assert_eq!(keymap(code::POWER, 0), RemoteKey::Power);
    }

    #[test]
    fn map_unknown() {
        assert_eq!(keymap(999, 0), RemoteKey::Unknown { key_code: 999, key_action: 0 });
    }
}