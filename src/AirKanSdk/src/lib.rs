//! airkan — 小米妙享/互联遥控协议 设备端实现（纯 Rust，零依赖）
//!
//! 让设备被小米手机遥控。协议逆向自 airkan（干净实现，clean-room）。
//!
//! 双端口：
//!   - 6095: HTTP 认证(getVersion/requestAuth/cancelAuth/completeAuth)
//!   - 6091: TCP 遥控长连(版本协商/心跳/按键帧)
//!
//! 使用方式：宿主实现 [`RemoteControlEvents`]，调用 [`AirkanServer::start`]。
//! 按键通过事件回调交给宿主（控制本地播放器/音量等）。
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod proto;
pub mod server;
pub mod keymap;

pub use keymap::KeyAction;
pub use proto::{AirkanFrame, parse_key_frame};
pub use server::AirkanServer;

use std::net::Ipv4Addr;

/// 上报版本：必须 > 0x01000000 手机才认为设备可遥控
pub const REPORT_VERSION: u32 = 0x0100_0008;

/// 默认 HTTP 认证端口
pub const HTTP_PORT: u16 = 6095;
/// 默认 TCP 遥控端口
pub const RC_PORT: u16 = 6091;

/// 遥控按键事件（宿主在回调里控制本地播放器/音量）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteKey {
    /// 上：下一曲
    Next,
    /// 下：上一曲
    Prev,
    /// 左：进度后退
    SeekBack,
    /// 右：进度快进
    SeekForward,
    /// OK/中间：暂停/播放(300ms 消抖 toggle)
    PlayPause,
    /// 音量加
    VolUp,
    /// 音量减
    VolDown,
    /// 电源/待机
    Power,
    /// 未知按键（保留原始 keyCode/keyAction）
    Unknown { key_code: u32, key_action: u32 },
}

/// 宿主回调集合。
///
/// 所有回调在 airkan 的服务线程上下文调用，宿主需自行保证线程安全。
pub trait RemoteControlEvents: Send + Sync + 'static {
    /// 收到一个按键（down 动作，已做 PlayPause 消抖）
    fn on_key(&self, key: RemoteKey);
    /// 连接状态变化
    fn on_status(&self, up: bool);
}

/// 无操作实现（测试/不需要回调时用）
pub struct NoOpEvents;
impl RemoteControlEvents for NoOpEvents {
    fn on_key(&self, _key: RemoteKey) {}
    fn on_status(&self, _up: bool) {}
}

/// 便捷：从 IP + 指定设备标识构造一个 AirkanServer。
///
/// this_tv_id 覆盖 tv_id；默认用 "airkantv" + 设备号。
pub fn server(local_ip: Ipv4Addr, device_id: String, tv_id: String, events: impl RemoteControlEvents) -> AirkanServer {
    AirkanServer::new(local_ip, HTTP_PORT, RC_PORT, device_id, tv_id, events)
}