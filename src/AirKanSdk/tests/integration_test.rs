//! airkan 端到端集成测试：起真实 server，模拟手机走完整流程
//!   HTTP 认证(6095) → TCP 连接(6091) → 版本协商 → 发按键帧 → 校验回调
//! SPDX-License-Identifier: Apache-2.0

use airkan::{AirkanServer, RemoteControlEvents, RemoteKey, REPORT_VERSION};
use std::io::{Read, Write};
use std::net::{TcpStream, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// 收集回调的宿主
struct Collector {
    keys: Arc<AtomicUsize>,
    last_key: Arc<std::sync::Mutex<Option<RemoteKey>>>,
    status_up: Arc<AtomicUsize>,
}
impl Collector {
    fn new() -> Self {
        Collector {
            keys: Arc::new(AtomicUsize::new(0)),
            last_key: Arc::new(std::sync::Mutex::new(None)),
            status_up: Arc::new(AtomicUsize::new(0)),
        }
    }
}
impl RemoteControlEvents for Collector {
    fn on_key(&self, key: RemoteKey) {
        self.keys.fetch_add(1, Ordering::SeqCst);
        *self.last_key.lock().unwrap() = Some(key);
        eprintln!("[collector] on_key: {key:?}");
    }
    fn on_status(&self, up: bool) {
        if up {
            self.status_up.fetch_add(1, Ordering::SeqCst);
            eprintln!("[collector] on_status: up");
        } else {
            eprintln!("[collector] on_status: down");
        }
    }
}

/// 构造按键帧
fn build_key_frame(key_code: i32, action: i32) -> Vec<u8> {
    let mut tlv = Vec::new();
    fn tlv_int(tlv: &mut Vec<u8>, sc: u8, v: i32) {
        tlv.push(sc);
        tlv.extend_from_slice(&v.to_be_bytes());
    }
    tlv_int(&mut tlv, 1, 0);
    tlv_int(&mut tlv, 2, action);
    tlv_int(&mut tlv, 3, key_code);
    tlv_int(&mut tlv, 4, 0);
    tlv_int(&mut tlv, 5, 0);
    tlv_int(&mut tlv, 6, 0);
    tlv.push(7);
    tlv.extend_from_slice(&0u64.to_be_bytes());
    tlv.push(8);
    tlv.extend_from_slice(&0u64.to_be_bytes());
    tlv_int(&mut tlv, 10, 0);
    tlv_int(&mut tlv, 11, 0);

    let mut out = vec![1u8]; // code=1
    out.extend_from_slice(&1u32.to_be_bytes());
    let dlen = tlv.len() as u16;
    out.extend_from_slice(&dlen.to_be_bytes());
    out.extend_from_slice(&tlv);

    let mut frame = vec![4u8]; // type=4 KEY
    let plen = out.len() as u16;
    frame.extend_from_slice(&plen.to_be_bytes());
    frame.extend_from_slice(&out);
    frame
}

#[test]
fn full_airkan_flow() {
    // 独立端口避免与其它测试并行冲突
    let (http_port, rc_port) = (16195, 16191);
    // 1. 起 server
    let collector = Collector::new();
    let keys = Arc::clone(&collector.keys);
    let last = Arc::clone(&collector.last_key);
    let _server = AirkanServer::new(
        Ipv4Addr::LOCALHOST,
        http_port,
        rc_port,
        "sdk_test".into(),
        "esp32test000000".into(),
        collector,
    );

    std::thread::sleep(Duration::from_millis(300));

    // 2. HTTP 认证 (http_port) — requestAuth
    {
        let mut stream = TcpStream::connect(("127.0.0.1", http_port)).unwrap();
        let req = format!(
            "GET /requestAuth?device_id=phone123&version_code=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();
        eprintln!("[test] auth resp:\n{resp}");
        assert!(resp.contains("60000"), "requestAuth code");
        assert!(resp.contains("tv_id"), "requestAuth has tv_id");
    }

    // 3. TCP 遥控 (rc_port) — 版本协商 + 按键
    {
        let mut stream = TcpStream::connect(("127.0.0.1", rc_port)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

        // 发版本包 type=5, len=5 (subcode + 4B) → 与安卓手机一致
        let ver = [5u8, 0, 5, 1, 0x01, 0x00, 0x00, 0x08];
        stream.write_all(&ver).unwrap();
        // 读版本响应（9B）
        let mut vr = [0u8; 9];
        stream.read_exact(&mut vr).unwrap();
        eprintln!("[test] version resp: {vr:02x?}");
        assert_eq!(vr[0], 0x05);
        assert_eq!(vr[3], 0x02); // code=2
        assert_eq!(u32::from_be_bytes([vr[5], vr[6], vr[7], vr[8]]), REPORT_VERSION);

        // 发按键帧（VOL_UP=24 DOWN）
        let frame = build_key_frame(24, 0);
        stream.write_all(&frame).unwrap();
        stream.flush().unwrap();
        std::thread::sleep(Duration::from_millis(200));
    }

    // 4. 校验回调
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        keys.load(Ordering::SeqCst) >= 1,
        "should have received >=1 key, got {}",
        keys.load(Ordering::SeqCst)
    );
    let got = last.lock().unwrap().unwrap();
    assert_eq!(got, RemoteKey::VolUp, "expected VolUp, got {got:?}");
    eprintln!("[test] PASS: received {got:?}");
}

#[test]
fn http_auth_404_for_controller() {
    let collector = Collector::new();
    let _server = AirkanServer::new(
        Ipv4Addr::LOCALHOST,
        17195, // 独立端口
        17191,
        "sdk_test".into(),
        "esp32test000000".into(),
        collector,
    );
    std::thread::sleep(Duration::from_millis(300));

    let mut stream = TcpStream::connect(("127.0.0.1", 17195)).unwrap();
    stream
        .write_all(b"GET /controller?action=getsources HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    assert!(resp.contains("404"), "controller should 404: {resp}");
}