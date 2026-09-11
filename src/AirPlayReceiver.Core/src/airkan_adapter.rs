//! airkan 遥控事件 → MiPlay ReceiverController 的适配层
//!
//! host（Android JNI）在成功启动 MiPlay 接收器后，把一个可被克隆的
//! [`ReceiverController`] 交给本适配器。airkan 服务器线程收到按键时回调
//! [`RemoteControlEvents::on_key`]，这里把它们映射成对本地播放器/音量的操作。

use airkan::RemoteControlEvents;
use fusionplay_miplay_sdk::{MediaAction, ReceiverController};

use std::sync::Arc;

/// 把 airkan 按键翻译成 FusionPlay 对 MiPlay 播放器的控制。
pub(crate) struct AirkanAdapter {
    controller: Arc<ReceiverController>,
    on_volume: Arc<dyn Fn(i32) + Send + Sync>,
    on_exit: Arc<dyn Fn() + Send + Sync>,
}

impl AirkanAdapter {
    /// 用一个共享的 MiPlay 控制器 + JNI 回调构造适配器。
    pub(crate) fn new(
        controller: Arc<ReceiverController>,
        on_volume: Arc<dyn Fn(i32) + Send + Sync>,
        on_exit: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self { controller, on_volume, on_exit }
    }
}

impl RemoteControlEvents for AirkanAdapter {
    fn on_key(&self, key: airkan::RemoteKey) {
        match key {
            airkan::RemoteKey::VolUp => (self.on_volume)(1),
            airkan::RemoteKey::VolDown => (self.on_volume)(-1),
            airkan::RemoteKey::PlayPause => {
                self.controller.resume_output();
            }
            airkan::RemoteKey::Next => {
                let _ = self.controller.send(MediaAction::Next);
            }
            airkan::RemoteKey::Prev => {
                let _ = self.controller.send(MediaAction::Previous);
            }
            airkan::RemoteKey::Power => {
                (self.on_exit)();
            }
            airkan::RemoteKey::SeekForward | airkan::RemoteKey::SeekBack | airkan::RemoteKey::Unknown { .. } => {
                // Seek 需要当前播放进度，暂不实现。
            }
        }
    }

    fn on_status(&self, _up: bool) {}
}
