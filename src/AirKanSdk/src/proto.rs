//! airkan 协议编解码
//!
//! 帧格式（逆向自 com.duokan.airkan.rc_sdk）：
//!
//! ```text
//! RCHeader: [type:1B][len:2B BE]
//!   type=2 心跳；type=4 按键；type=5 版本协商
//! 按键帧 = RCHeader + SendKeyHeader(7B) + TLV...
//!   SendKeyHeader: [code:1B][id:4B BE][data_len:2B BE]
//!   TLV: [subcode:1B][value]  (subcode 7/8 是 8B(long)，其余 5B)
//! ```
//!
//! SPDX-License-Identifier: Apache-2.0

/// 帧类型
pub mod ty {
    pub const HEARTBEAT: u8 = 2;
    pub const KEY: u8 = 4;
    pub const VERSION: u8 = 5;
}

/// 版本响应（设备→手机，9 字节）：
/// `[0x05][0x00][0x06][0x02][0x01] + ver(4B BE)`
/// code 必须=2(响应)，否则手机按请求解析返回 null，握手永不完成。
pub fn build_version_resp(ver: u32) -> [u8; 9] {
    [
        0x05,
        0x00,
        0x06,
        0x02, // code=2 RESPONSE
        0x01, // TLV subcode=1 → version
        (ver >> 24) as u8,
        (ver >> 16) as u8,
        (ver >> 8) as u8,
        ver as u8,
    ]
}

/// 心跳帧：3 字节固定 `{0x02,0x00,0x00}`
pub fn build_heartbeat() -> [u8; 3] {
    [ty::HEARTBEAT, 0x00, 0x00]
}

/// 解析出的按键帧
#[derive(Clone, Debug, Default)]
pub struct AirkanFrame {
    pub frame_type: u8,
    pub code: u8,
    pub seq_id: u32,
    pub data_len: u16,
    pub key_code: i32,   // TLV subcode=3
    pub key_action: i32, // TLV subcode=2: 0=DOWN 1=UP
}

/// 解析一个 type=4 按键帧。
/// 返回 Err 当帧不完整/畸形（io::ErrorKind::InvalidData）。
pub fn parse_key_frame(buf: &[u8]) -> Result<AirkanFrame, std::io::Error> {
    use std::io::{Error, ErrorKind};
    if buf.len() < 10 {
        return Err(Error::new(ErrorKind::InvalidData, "key frame too short (<10)"));
    }
    let mut f = AirkanFrame::default();
    f.frame_type = buf[0];
    f.code = buf[3];
    f.seq_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    f.data_len = u16::from_be_bytes([buf[8], buf[9]]);
    f.key_code = -1;
    f.key_action = -1;

    // data_len 越界检查
    let end = 10usize
        .checked_add(f.data_len as usize)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "data_len overflow"))?;
    if end > buf.len() {
        return Err(Error::new(ErrorKind::InvalidData, "key frame data_len exceeds buffer"));
    }

    // 解析 TLV
    let mut off = 10usize;
    while off + 5 <= end {
        let sc = buf[off];
        let v = i32::from_be_bytes([buf[off + 1], buf[off + 2], buf[off + 3], buf[off + 4]]);
        if sc == 2 {
            f.key_action = v;
        } else if sc == 3 {
            f.key_code = v;
        }
        off += if sc == 7 || sc == 8 { 9 } else { 5 };
    }
    Ok(f)
}

/// 读取一条完整帧：根据 RCHeader 的 len 判断。返回 (type, 完整帧)。
/// 用于服务端的累积缓冲解析。
pub fn try_take_frame(buf: &[u8]) -> Result<Option<(u8, &[u8])>, std::io::Error> {
    use std::io::{Error, ErrorKind};
    if buf.len() < 3 {
        return Ok(None); // 半包，至少要头
    }
    let mlen = u16::from_be_bytes([buf[1], buf[2]]) as usize;
    let need = 3usize + mlen;
    if need > 1500 {
        return Err(Error::new(ErrorKind::InvalidData, "frame len too large"));
    }
    if buf.len() < need {
        return Ok(None); // 等更多数据
    }
    Ok(Some((buf[0], &buf[0..need])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::REPORT_VERSION;

    /// 构造一个按键帧（与手机发送格式一致）
    fn build_key_frame_manual(key_code: i32, action: i32) -> Vec<u8> {
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
        tlv.push(7); // downTime (8B)
        tlv.extend_from_slice(&0u64.to_be_bytes());
        tlv.push(8); // eventTime (8B)
        tlv.extend_from_slice(&0u64.to_be_bytes());
        tlv_int(&mut tlv, 10, 0); // deviceId
        tlv_int(&mut tlv, 11, 0); // source

        let mut out = Vec::new();
        out.push(1); // code=1 (request)
        out.extend_from_slice(&1u32.to_be_bytes()); // id
        let dlen = tlv.len() as u16;
        out.extend_from_slice(&dlen.to_be_bytes());
        out.extend_from_slice(&tlv);

        let payload_len = out.len() as u16;
        let mut frame = Vec::new();
        frame.push(ty::KEY);
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.extend_from_slice(&out);
        frame
    }

    #[test]
    fn parse_vol_up() {
        let frame = build_key_frame_manual(24, 0);
        let f = parse_key_frame(&frame).unwrap();
        assert_eq!(f.frame_type, ty::KEY);
        assert_eq!(f.key_code, 24);
        assert_eq!(f.key_action, 0);
        assert_eq!(f.code, 1);
    }

    #[test]
    fn reject_short_frame() {
        let bad = [4u8, 0, 0, 1, 2];
        assert!(parse_key_frame(&bad).is_err());
    }

    #[test]
    fn version_resp_format() {
        let vr = build_version_resp(0x0100_0008);
        assert_eq!(vr, [0x05, 0x00, 0x06, 0x02, 0x01, 0x01, 0x00, 0x00, 0x08]);
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
        let (t1, f1) = try_take_frame(&coalesced).unwrap().unwrap();
        assert_eq!(t1, ty::HEARTBEAT);
        assert_eq!(f1.len(), 3);
        let rest = &coalesced[f1.len()..];
        let (t2, _f2) = try_take_frame(rest).unwrap().unwrap();
        assert_eq!(t2, ty::VERSION);
    }
}