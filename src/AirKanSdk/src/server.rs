//! airkan 服务器：6095 HTTP 认证 + 6091 TCP 遥控长连
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::keymap::keymap;
use crate::proto::{self, build_heartbeat, build_version_resp, parse_key_frame, try_take_frame};
use crate::{RemoteControlEvents, RemoteKey, REPORT_VERSION};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// airkan 服务器句柄。创建后 spawn 两个线程分别服务 6095(HTTP) 和 6091(RC)。
pub struct AirkanServer {
    shutdown: Arc<AtomicBool>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl AirkanServer {
    /// 创建并启动服务器（非阻塞，立即返回）。
    pub fn new(
        local_ip: Ipv4Addr,
        http_port: u16,
        rc_port: u16,
        device_id: String,
        tv_id: String,
        events: impl RemoteControlEvents,
    ) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let events: Arc<dyn RemoteControlEvents> = Arc::new(events);

        // HTTP 认证线程 (6095)
        let e_http = Arc::clone(&events);
        let dev_id = device_id.clone();
        let tvid = tv_id.clone();
        let sh1 = Arc::clone(&shutdown);
        let http_thread = thread::Builder::new()
            .name("airkan-http".into())
            .spawn(move || {
                serve_http(local_ip, http_port, &dev_id, &tvid, e_http.as_ref(), &sh1);
            })
            .expect("spawn airkan-http");

        // RC 遥控线程 (6091)：每连接一个子线程
        let e_rc = Arc::clone(&events);
        let sh2 = Arc::clone(&shutdown);
        let rc_thread = thread::Builder::new()
            .name("airkan-rc".into())
            .spawn(move || {
                serve_rc(local_ip, rc_port, e_rc, &sh2);
            })
            .expect("spawn airkan-rc");

        AirkanServer {
            shutdown,
            threads: vec![http_thread, rc_thread],
        }
    }

    /// 请求停止两个服务线程（非阻塞）。
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }
}

impl Drop for AirkanServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

// ─────────────────────────────── HTTP 认证 (6095) ───────────────────────────────

fn serve_http(
    local_ip: Ipv4Addr,
    port: u16,
    device_id: &str,
    tv_id: &str,
    events: &dyn RemoteControlEvents,
    shutdown: &AtomicBool,
) {
    let addr = SocketAddr::from((local_ip, port));
    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("airkan-http: bind {addr} failed: {e}");
            return;
        }
    };
    listener
        .set_nonblocking(true)
        .expect("set http listener nonblocking");
    eprintln!("airkan-http: listening {addr}");

    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut stream, _peer)) => {
                let mut buf = [0u8; 1024];
                let n = match stream.read(&mut buf) {
                    Ok(n) if n > 0 => n,
                    _ => continue,
                };
                let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                let reply = handle_http_request(&req, device_id, tv_id, events);
                let _ = stream.write_all(reply.as_bytes());
                let _ = stream.flush();
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(_) => thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn handle_http_request(
    req: &str,
    device_id: &str,
    tv_id: &str,
    events: &dyn RemoteControlEvents,
) -> String {
    let line = req.lines().next().unwrap_or("");
    let path = extract_uri_path(line);

    let (body, notify_auth) = if path.contains("/getInfo") && path.contains("getVersion") {
        (
            format!(
                "{{\"status\":0,\"msg\":\"ok\",\"data\":{{\"version\":{}}}}}",
                REPORT_VERSION
            ),
            false,
        )
    } else if path.contains("/requestAuth") {
        let req_dev = query_value(&path, "device_id").unwrap_or("").to_string();
        let echo_dev = if req_dev.is_empty() { device_id } else { &req_dev };
        (
            format!(
                "{{\"code\":60000,\"msg\":\"ok\",\"resp_data\":{{\"device_id\":\"{}\",\"tv_id\":\"{}\",\
                 \"public_key\":\"\",\"verify_code_additional\":\"\",\"versionCode\":\"1\"}}}}",
                echo_dev, tv_id
            ),
            true,
        )
    } else if path.contains("/cancelAuth") {
        ("{\"code\":60000,\"msg\":\"ok\"}".to_string(), false)
    } else if path.contains("/completeAuth") {
        (
            format!(
                "{{\"code\":60000,\"msg\":\"ok\",\"resp_data\":{{\"tv_id\":\"{}\"}}}}",
                tv_id
            ),
            false,
        )
    } else {
        return "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string();
    };

    if notify_auth {
        events.on_status(true);
    }

    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn extract_uri_path(line: &str) -> String {
    let mut parts = line.split_whitespace();
    let _ = parts.next();
    parts.next().unwrap_or("").to_string()
}

fn query_value<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    let key = format!("{}=", name);
    let idx = query.find(&key)?;
    let val_start = idx + key.len();
    let rest = &query[val_start..];
    let end = rest.find(['&', ' ', '\r', '\n']).unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    Some(&rest[..end])
}

// ─────────────────────────────── TCP 遥控长连 (6091) ───────────────────────────────

fn serve_rc(
    local_ip: Ipv4Addr,
    port: u16,
    events: Arc<dyn RemoteControlEvents>,
    shutdown: &Arc<AtomicBool>,
) {
    let addr = SocketAddr::from((local_ip, port));
    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("airkan-rc: bind {addr} failed: {e}");
            return;
        }
    };
    listener
        .set_nonblocking(true)
        .expect("set rc listener nonblocking");
    eprintln!("airkan-rc: listening {addr}");

    let mut conn_id = 0u64;
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                conn_id += 1;
                let e = Arc::clone(&events);
                thread::Builder::new()
                    .name(format!("airkan-rc-conn-{conn_id}"))
                    .spawn(move || {
                        handle_rc_connection(stream, e);
                    })
                    .ok();
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(_) => thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn handle_rc_connection(mut stream: TcpStream, events: Arc<dyn RemoteControlEvents>) {
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok();

    let mut buf: Vec<u8> = Vec::new();
    let mut last_heartbeat = Instant::now();
    let mut handshake_done = false;
    let mut ok_last: Option<Instant> = None;
    let mut rbuf = [0u8; 1024];

    loop {
        // 主动喂心跳（每 4s），保持手机看门狗不过期
        if last_heartbeat.elapsed() >= Duration::from_secs(4) {
            let hb = build_heartbeat();
            if stream.write_all(&hb).is_err() {
                break;
            }
            last_heartbeat = Instant::now();
        }

        let n = match stream.read(&mut rbuf) {
            Ok(0) => break, // 对端关闭（EOF）
            Ok(n) => n,
            Err(e) => match e.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                    // 超时：无数据，回循环顶部喂心跳
                    continue;
                }
                _ => break, // 其它错误视为断开
            },
        };
        buf.extend_from_slice(&rbuf[..n]);

        // 逐条解析完整帧
        loop {
            let next = try_take_frame(&buf);
            let (ftype, frame) = match next {
                Ok(Some(x)) => x,
                Ok(None) => break,
                Err(_) => {
                    buf.clear();
                    break;
                }
            };
            let consumed = frame.len();
            // 复制帧（避免借用冲突），再消费原缓冲
            let owned: Vec<u8> = frame.to_vec();
            buf.drain(..consumed);
            match ftype {
                proto::ty::VERSION if !handshake_done => {
                    let vr = build_version_resp(REPORT_VERSION);
                    if stream.write_all(&vr).is_err() {
                        break;
                    }
                    handshake_done = true;
                    events.on_status(true);
                }
                proto::ty::KEY => {
                    if let Ok(f) = parse_key_frame(&owned) {
                        dispatch_key(&f, &mut ok_last, events.as_ref());
                    }
                }
                proto::ty::HEARTBEAT => { /* 手机心跳，仅记录 */ }
                _ => {}
            }
        }
    }
    // 连接结束
    events.on_status(false);
}

fn dispatch_key(f: &crate::proto::AirkanFrame, ok_last: &mut Option<Instant>, events: &dyn RemoteControlEvents) {
    if f.code != 1 || f.key_action != 0 {
        return; // 仅按下
    }
    let key = keymap(f.key_code, f.key_action);
    // PlayPause 消抖（300ms）
    if key == RemoteKey::PlayPause {
        if let Some(t) = *ok_last {
            if t.elapsed() < Duration::from_millis(300) {
                return;
            }
        }
        *ok_last = Some(Instant::now());
    }
    events.on_key(key);
}