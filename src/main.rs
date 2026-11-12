use crypto_lab::http;
use std::net::{IpAddr, TcpListener};

fn main() {
    let mut addr = "127.0.0.1:8100".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-addr" | "--addr" => addr = args.next().unwrap_or_else(|| usage()),
            _ => usage(),
        }
    }
    let host = addr
        .rsplit_once(':')
        .map(|x| x.0)
        .unwrap_or("")
        .trim_matches(|c| c == '[' || c == ']');
    if !host
        .parse::<IpAddr>()
        .map(|i| i.is_loopback())
        .unwrap_or(false)
    {
        eprintln!("refusing to bind {addr}: this lab runs attacks on demand, keep it on loopback");
        std::process::exit(2);
    }
    let l = TcpListener::bind(&addr).unwrap_or_else(|e| {
        eprintln!("cannot bind {addr}: {e}");
        std::process::exit(1)
    });
    println!("Crypto Lab on http://{addr}");
    http::serve(l);
}

fn usage() -> ! {
    eprintln!("usage: crypto-lab [-addr 127.0.0.1:8100]");
    std::process::exit(2)
}
