//! Tiny HTTP/1.1 server on std only: one thread per connection, strict size and time limits.

use crate::api;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const MAX_REQUEST: usize = 8 * 1024;
const MAX_CONNS: usize = 64;

const INDEX: &str = include_str!("../web/index.html");
const APP_JS: &str = include_str!("../web/app.js");
const FAVICON: &str = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 32 32\"><rect width=\"32\" height=\"32\" rx=\"7\" fill=\"#38bdf8\"/><path d=\"M11 14v-3a5 5 0 0 1 10 0v3m-12 0h14v11H9z\" fill=\"none\" stroke=\"#06202e\" stroke-width=\"2.4\" stroke-linejoin=\"round\"/></svg>";
const STYLE: &str = include_str!("../web/style.css");

pub fn parse_request_line(head: &str) -> Option<(&str, &str, &str)> {
    let line = head.lines().next()?;
    let mut it = line.split(' ');
    let (m, target, ver) = (it.next()?, it.next()?, it.next()?);
    if !ver.starts_with("HTTP/1.") || it.next().is_some() {
        return None;
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    Some((m, path, query))
}

pub fn route(method: &str, path: &str, query: &str) -> (u16, &'static str, Vec<u8>) {
    if method != "GET" {
        return (405, "text/plain", b"method not allowed".to_vec());
    }
    match path {
        "/" => (200, "text/html; charset=utf-8", INDEX.as_bytes().to_vec()),
        "/app.js" => (
            200,
            "text/javascript; charset=utf-8",
            APP_JS.as_bytes().to_vec(),
        ),
        "/favicon.svg" => (200, "image/svg+xml", FAVICON.as_bytes().to_vec()),
        "/style.css" => (200, "text/css; charset=utf-8", STYLE.as_bytes().to_vec()),
        p if p.starts_with("/api/") => {
            let (s, body) = api::handle(p, query);
            (s, "application/json", body.into_bytes())
        }
        _ => (404, "text/plain", b"not found".to_vec()),
    }
}

fn status_text(s: u16) -> &'static str {
    match s {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    }
}

fn handle(mut s: TcpStream) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
        if buf.len() > MAX_REQUEST {
            let _ = s.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
            return;
        }
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let (status, ctype, body) = match parse_request_line(&head) {
        Some((m, p, q)) => route(m, p, q),
        None => (400, "text/plain", b"bad request".to_vec()),
    };
    let resp = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n",
        status_text(status),
        body.len()
    );
    let _ = s.write_all(resp.as_bytes());
    let _ = s.write_all(&body);
}

pub fn serve(listener: TcpListener) {
    let active = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming().flatten() {
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNS {
            active.fetch_sub(1, Ordering::SeqCst);
            continue; // shed load instead of queueing
        }
        let a = Arc::clone(&active);
        std::thread::spawn(move || {
            handle(conn);
            a.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(addr: &str, raw: &str) -> String {
        let mut c = TcpStream::connect(addr).unwrap();
        c.write_all(raw.as_bytes()).unwrap();
        let mut out = String::new();
        let _ = c.read_to_string(&mut out);
        out
    }

    fn start() -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        std::thread::spawn(move || serve(l));
        addr
    }

    #[test]
    fn request_line_parsing() {
        assert_eq!(
            parse_request_line("GET /a?x=1 HTTP/1.1\r\n"),
            Some(("GET", "/a", "x=1"))
        );
        assert!(parse_request_line("GET /a").is_none());
        assert!(parse_request_line("GET /a HTTP/2 extra").is_none());
        assert!(parse_request_line("").is_none());
    }

    #[test]
    fn serves_ui_api_and_security_headers() {
        let a = start();
        let r = get(&a, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(
            r.starts_with("HTTP/1.1 200")
                && r.contains("Crypto Lab")
                && r.contains("default-src 'self'")
        );
        let r = get(&a, "GET /api/hash?text=abc HTTP/1.1\r\n\r\n");
        assert!(r.contains("ba7816bf8f01cfea"));
        assert!(get(&a, "POST / HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 405"));
        assert!(get(&a, "GET /nope HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 404"));
        assert!(get(&a, "garbage\r\n\r\n").starts_with("HTTP/1.1 400"));
    }

    #[test]
    fn oversized_headers_are_rejected() {
        let a = start();
        let big = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(20_000));
        assert!(get(&a, &big).starts_with("HTTP/1.1 431"));
    }
}
