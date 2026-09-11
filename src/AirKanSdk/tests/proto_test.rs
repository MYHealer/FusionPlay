//! airkan 协议单测：帧/TLV/版本/心跳 + 畸形帧防御
//! SPDX-License-Identifier: Apache-2.0

use airkan::proto::*;
use airkan::REPORT_VERSION;

/// 构造一个按键帧（与手机 airkan_remote.py 相同语义）
fn build_key_frame(key_code: i32, action: i32) -> Vec<u8> {
    let mut tlv = Vec::new();
    fn tlv_int(tlv: &mut Vec<u8>, sc: u8, v: i32) {
        tlv.push(sc);
        tlv.extend_from_slice(&v.to_be_bytes());
    }
    tlv_int(&mut tlv, 1, 0); // metaState
    tlv_int(&mut tlv, 2, action); // action
    tlv_int(&mut tlv, 3, key_code); // keyCode
    tlv_int(&mut tlv, 4, 0); // scanCode
    tlv_int(&mut tlv, 5, 0); // repeatCount
    tlv_int(&mut tlv, 6, 0); // flags
    tlv.push(7); // downTime 8B
    tlv.extend_from_slice(&0u64.to_be_bytes());
    tlv.push(8); // eventTime 8B
    tlv.extend_from_slice(&0u64.to_be_bytes());
    tlv_int(&mut tlv, 10, 0); // deviceId
    tlv_int(&mut tlv, 11, 0); // source

    let mut out = Vec::new();
    out.push(1); // code=1 request
    out.extend_from_slice(&1u32.to_be_bytes());
    let dlen = tlv.len() as u16;
    out.extend_from_slice(&dlen.to_be_bytes());
    out.extend_from_slice(&tlv);

    let payload_len = out.len() as u16;
    let mut frame = vec![ty::KEY];
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(&out);
    frame
}

#[test]
fn parse_vol_up() {
    let frame = build_key_frame(24, 0);
    let f = parse_key_frame(&frame).unwrap();
    assert_eq!(f.frame_type, ty::KEY);
    assert_eq!(f.key_code, 24);
    assert_eq!(f.key_action, 0);
    assert_eq!(f.code, 1);
}

#[test]
fn parse_power_full_tlv() {
    let frame = build_key_frame(26, 1); // POWER up
    let f = parse_key_frame(&frame).unwrap();
    assert_eq!(f.key_code, 26);
    assert_eq!(f.key_action, 1);
}

#[test]
fn reject_short_frame() {
    assert!(parse_key_frame(&[4, 0, 0, 1, 2]).is_err());
}

#[test]
fn reject_bad_data_len() {
    // 声称 data_len 很大，但实际没那么多字节
    let mut frame = build_key_frame(24, 0);
    frame[8] = 0xFF; // data_len high byte 夸大
    frame[9] = 0xFF;
    assert!(parse_key_frame(&frame).is_err());
}

#[test]
fn version_resp_format() {
    let vr = build_version_resp(REPORT_VERSION);
    assert_eq!(vr[0], 0x05);
    assert_eq!(vr[3], 0x02); // code=2
    assert_eq!(vr[4], 0x01); // subcode=1
    assert_eq!(u32::from_be_bytes([vr[5], vr[6], vr[7], vr[8]]), REPORT_VERSION);
}

#[test]
fn heartbeat_format() {
    assert_eq!(build_heartbeat(), [2, 0, 0]);
}

#[test]
fn take_frame_coalesced() {
    // 心跳 + 版本包粘一起
    let hb = build_heartbeat();
    let ver = build_version_resp(REPORT_VERSION);
    let mut coalesced = Vec::new();
    coalesced.extend_from_slice(&hb);
    coalesced.extend_from_slice(&ver);

    let (t1, _f1) = try_take_frame(&coalesced).unwrap().unwrap();
    assert_eq!(t1, ty::HEARTBEAT);
    let (t2, _f2) = try_take_frame(&coalesced[3..]).unwrap().unwrap();
    assert_eq!(t2, ty::VERSION);
}

#[test]
fn take_frame_partial() {
    let frame = build_key_frame(24, 0);
    // 只给半帧 → 应返回 None（等更多）
    let half = &frame[..frame.len() - 3];
    assert!(try_take_frame(half).unwrap().is_none());
}

#[test]
fn take_frame_rejects_oversized() {
    let mut frame = build_key_frame(24, 0);
    frame[1] = 0x06; // len 夸大超过 1500 上限
    frame[2] = 0x00; // 0600 = 1536 > 1500
    assert!(try_take_frame(&frame).is_err());
}

#[test]
fn keymap_mapping() {
    use airkan::keymap::{code, keymap};
    use airkan::RemoteKey;
    assert_eq!(keymap(code::DPAD_UP, 0), RemoteKey::Next);
    assert_eq!(keymap(code::DPAD_DOWN, 0), RemoteKey::Prev);
    assert_eq!(keymap(code::DPAD_LEFT, 0), RemoteKey::SeekBack);
    assert_eq!(keymap(code::DPAD_RIGHT, 0), RemoteKey::SeekForward);
    assert_eq!(keymap(code::ENTER, 0), RemoteKey::PlayPause);
    assert_eq!(keymap(code::DPAD_CENTER, 0), RemoteKey::PlayPause);
    assert_eq!(keymap(code::VOLUME_UP, 0), RemoteKey::VolUp);
    assert_eq!(keymap(code::VOLUME_DOWN, 0), RemoteKey::VolDown);
    assert_eq!(keymap(code::POWER, 0), RemoteKey::Power);
    assert_eq!(keymap(999, 0), RemoteKey::Unknown { key_code: 999, key_action: 0 });
}