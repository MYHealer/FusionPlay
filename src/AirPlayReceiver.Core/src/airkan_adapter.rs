//! airkan 遥控事件 → MiPlay ReceiverController 的适配层
//!
//! host（Android JNI）在成功启动 MiPlay 接收器后，把一个可被克隆的
//! [`ReceiverController`] 交给本适配器。airkan 服务器线程收到按键时回调
//! [`RemoteControlEvents::on_key`]，这里把它们映射成对本地播放器/音量的操作。

use airkan::RemoteControlEvents;
use fusionplay_miplay_sdk::MediaAction;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// 每次按键的本地音量步进（百分比）。
const VOLUME_STEP: i32 = 5;
/// 本地音量初始值（百分比）。
const INITIAL_VOLUME: u32 = 50;

/// 把 airkan 按键翻译成 FusionPlay 对 MiPlay 播放器的控制。
///
/// `controller` 通过 `Arc` 共享，供多路 airkan 连接同时安全调用；`volume`
/// 用原子自增自减跟踪本地音量，规避每次读取系统音量的繁琐。
pub(crate) struct AirkanAdapter {
    controller: Arc<ReceiverController>,
    volume: AtomicU32,
}

impl AirkanAdapter {
    /// 用一个共享的 MiPlay 控制器构造适配器。
    pub(crate) fn new(controller: Arc<ReceiverController>) -> Self {
        Self {
            controller,
            volume: AtomicU32::new(INITIAL_VOLUME),
        }
    }
}

impl AirkanAdapter {
    fn adjust_volume(&self, delta: i32) {
        let current = self.volume.load(Ordering::Relaxed) as i32;
        let next = (current + delta).clamp(0, 100) as u32;
        self.volume.store(next, Ordering::Relaxed);
        let _ = self.controller.set_volume(next as u8);
    }
}

impl RemoteControlEvents for AirkanAdapter {
    fn on_key(&self, key: airkan::RemoteKey) {
        match key {
            // 音量加/减：在本地跟踪的百分比基础上步进并写回。
            airkan::RemoteKey::VolUp => self.adjust_volume(VOLUME_STEP),
            airkan::RemoteKey::VolDown => self.adjust_volume(-VOLUME_STEP),
            // 暂停/播放：本地输出挂起即为暂停，恢复即为播放。
            airkan::RemoteKey::PlayPause => {
                // 不区分暂停/播放，统一走 resume；若已在播放则由 MiPlay 侧幂等处理。
                self.controller.resume_output();
            }
            // 切歌：反控手机跳到上一首/下一首。
            airkan::RemoteKey::Next => {
                let _ = self.controller.send(MediaAction::Next);
            }
            airkan::RemoteKey::Prev => {
                let _ = self.controller.send(MediaAction::Previous);
            }
            // 进度快进/快退：需要当前进度，暂无则跳过，避免乱跳。
            airkan::RemoteKey::SeekForward | airkan::RemoteKey::SeekBack | airkan::RemoteKey::Power | airkan::RemoteKey::Unknown { .. } => {
                // 暂不处理：Seek 需当前进度，Power 与未知键无明确语义。
            }
        }
    }

    fn on_status(&self, _up: bool) {
        // 连接状态变化当前无需额外动作，保留为空以便日后扩展。
    }
}