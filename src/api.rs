//! Pure request handling: (path, query) in, (status, JSON) out. No sockets here, so it is unit-testable.

use crate::aes::{cbc_encrypt, ecb_encrypt, Aes128};
use crate::attacks::*;
use crate::hex::encode;
use crate::sha256::{hmac_sha256, sha256};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const MAX_TEXT: usize = 480;

pub fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn json_list(items: &[String]) -> String {
    format!("[{}]", items.join(","))
}

pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(v) => {
                    out.push(v);
                    i += 2;
                }
                Err(_) => out.push(b'%'),
            },
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (percent_decode(k) == name).then(|| percent_decode(v))
    })
}

struct Rng(u64);
impl Rng {
    fn new() -> Self {
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
        Rng(t ^ 0x9e3779b97f4a7c15)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    fn bytes16(&mut self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&self.next().to_le_bytes());
        b[8..].copy_from_slice(&self.next().to_le_bytes());
        b
    }
}

fn text_param(q: &str, name: &str, default: &str) -> Result<String, String> {
    let t = query_param(q, name).unwrap_or_else(|| default.to_string());
    if t.len() > MAX_TEXT {
        return Err(format!("{name} is limited to {MAX_TEXT} bytes"));
    }
    Ok(t)
}

fn err(status: u16, msg: &str) -> (u16, String) {
    (status, format!("{{\"error\":{}}}", json_str(msg)))
}

pub fn handle(path: &str, query: &str) -> (u16, String) {
    let r = match path {
        "/api/hash" => hash(query),
        "/api/ecb" => ecb(query),
        "/api/padding-oracle" => padding_oracle(query),
        "/api/length-extension" => length_ext(query),
        "/api/rsa" => rsa(query),
        _ => return err(404, "not found"),
    };
    match r {
        Ok(j) => (200, j),
        Err(e) => err(400, &e),
    }
}

fn hash(q: &str) -> Result<String, String> {
    let text = text_param(q, "text", "hello")?;
    let key = text_param(q, "key", "key")?;
    let h = sha256(text.as_bytes());
    let mut flipped = text.as_bytes().to_vec();
    if flipped.is_empty() {
        flipped.push(0);
    } else {
        flipped[0] ^= 1;
    }
    let h2 = sha256(&flipped);
    let diff: u32 = h
        .iter()
        .zip(h2.iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum();
    Ok(format!(
        "{{\"sha256\":\"{}\",\"hmac\":\"{}\",\"flipped_sha256\":\"{}\",\"bits_changed\":{}}}",
        encode(&h),
        encode(&hmac_sha256(key.as_bytes(), text.as_bytes())),
        encode(&h2),
        diff
    ))
}

fn ecb(q: &str) -> Result<String, String> {
    let text = text_param(q, "text", &"ATTACK AT DAWN!!".repeat(6))?;
    let mut rng = Rng::new();
    let aes = Aes128::new(&rng.bytes16());
    let iv = rng.bytes16();
    let blocks = |v: Vec<u8>| {
        json_list(
            &v.chunks(16)
                .map(|c| format!("\"{}\"", encode(c)))
                .collect::<Vec<_>>(),
        )
    };
    Ok(format!(
        "{{\"ecb\":{},\"cbc\":{}}}",
        blocks(ecb_encrypt(&aes, text.as_bytes())),
        blocks(cbc_encrypt(&aes, &iv, text.as_bytes()))
    ))
}

fn padding_oracle(q: &str) -> Result<String, String> {
    let msg = text_param(q, "msg", "transfer 1000 EUR to account 4242")?;
    let mut rng = Rng::new();
    let aes = Aes128::new(&rng.bytes16());
    let iv = rng.bytes16();
    let ct = cbc_encrypt(&aes, &iv, msg.as_bytes());
    let t = Instant::now();
    let r = padding_oracle_attack(&iv, &ct, server_oracle(&aes)).ok_or("attack failed")?;
    Ok(format!(
        "{{\"iv\":\"{}\",\"ciphertext\":\"{}\",\"blocks\":{},\"recovered\":{},\"queries\":{},\"ms\":{},\"matches\":{}}}",
        encode(&iv),
        encode(&ct),
        ct.len() / 16,
        json_str(&String::from_utf8_lossy(&r.plaintext)),
        r.queries,
        t.elapsed().as_millis(),
        r.plaintext == msg.as_bytes()
    ))
}

fn printable(b: &[u8]) -> String {
    b.iter()
        .map(|&c| {
            if (0x20..0x7f).contains(&c) {
                (c as char).to_string()
            } else {
                format!("\\x{c:02x}")
            }
        })
        .collect()
}

fn length_ext(q: &str) -> Result<String, String> {
    let msg = text_param(q, "msg", "user=alice&role=reader")?;
    let append = text_param(q, "append", "&role=admin")?;
    let mut rng = Rng::new();
    let secret_len = 8 + (rng.next() % 17) as usize;
    let secret: Vec<u8> = (0..secret_len)
        .map(|_| b'a' + (rng.next() % 26) as u8)
        .collect();
    let mac = naive_mac(&secret, msg.as_bytes());
    let forged = length_extension(msg.as_bytes(), &mac, append.as_bytes(), 64, |m, t| {
        naive_mac(&secret, m) == *t
    });
    let resists = hmac_is_not_extendable(&secret, msg.as_bytes(), append.as_bytes());
    Ok(match forged {
        Some(f) => format!(
            "{{\"original_mac\":\"{}\",\"forged_message\":{},\"forged_mac\":\"{}\",\"secret_len\":{},\"tries\":{},\"server_accepts\":true,\"hmac_resists\":{}}}",
            encode(&mac),
            json_str(&printable(&f.message)),
            encode(&f.mac),
            f.secret_len,
            f.tries,
            resists
        ),
        None => "{\"server_accepts\":false}".to_string(),
    })
}

fn rsa(q: &str) -> Result<String, String> {
    let mut rng = Rng::new();
    let n = match query_param(q, "n") {
        Some(s) => {
            let n: u64 = s
                .trim()
                .parse()
                .map_err(|_| "n must be an unsigned integer below 2^63")?;
            if n >= 1 << 63 {
                return Err("n must be below 2^63".into());
            }
            n
        }
        None => {
            let p = next_prime((1u64 << 30) + rng.next() % (1 << 29));
            let q = next_prime(p + 2 + rng.next() % 20_000);
            p * q
        }
    };
    let t = Instant::now();
    match fermat_factor(n, 5_000_000) {
        None => Ok(format!("{{\"n\":{n},\"factored\":false,\"note\":\"Fermat gave up: the factors are not close together\"}}")),
        Some(f) => {
            let (pubk, d) = rsa_from_primes(f.p, f.q).ok_or("not a valid RSA modulus")?;
            let m = 424242 % pubk.n;
            let c = powmod(m, pubk.e, pubk.n);
            Ok(format!(
                "{{\"n\":{},\"e\":{},\"factored\":true,\"p\":{},\"q\":{},\"iterations\":{},\"d\":{},\"demo_message\":{},\"demo_cipher\":{},\"decrypted\":{},\"us\":{}}}",
                n, pubk.e, f.p, f.q, f.iterations, d, m, c, powmod(c, d, pubk.n), t.elapsed().as_micros()
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decoding_edge_cases() {
        assert_eq!(percent_decode("a%20b+c%2"), "a b c%2");
        assert_eq!(percent_decode("%zz%41"), "%zzA");
        assert_eq!(percent_decode("%"), "%");
        assert_eq!(percent_decode("%e2%82%ac"), "€");
        assert_eq!(query_param("a=1&b=%26x", "b").as_deref(), Some("&x"));
        assert_eq!(query_param("a=1", "c"), None);
    }

    #[test]
    fn json_escaping_is_safe() {
        assert_eq!(json_str("a\"b\\c\n\u{1}"), "\"a\\\"b\\\\c\\n\\u0001\"");
    }

    #[test]
    fn hash_endpoint_matches_known_vector_and_shows_avalanche() {
        let (s, j) = handle("/api/hash", "text=abc");
        assert_eq!(s, 200);
        assert!(j.contains("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        let bits: u32 = j
            .split("\"bits_changed\":")
            .nth(1)
            .unwrap()
            .trim_end_matches('}')
            .parse()
            .unwrap();
        assert!(
            (90..=166).contains(&bits),
            "about half of 256 bits flip: {bits}"
        );
    }

    #[test]
    fn ecb_endpoint_shows_repeated_blocks_only_in_ecb() {
        let (_, j) = handle(
            "/api/ecb",
            "text=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        let (ecb, cbc) = j.split_once("\"cbc\":").unwrap();
        let blocks = |s: &str| -> Vec<String> {
            s.split('"')
                .filter(|x| x.len() == 32)
                .map(String::from)
                .collect()
        };
        let (e, c) = (blocks(ecb), blocks(cbc));
        assert_eq!(e[0], e[1]);
        assert_ne!(c[0], c[1]);
    }

    #[test]
    fn padding_oracle_endpoint_recovers_message() {
        let (s, j) = handle("/api/padding-oracle", "msg=hello%20world%20%22quoted%22");
        assert_eq!(s, 200);
        assert!(
            j.contains("\"recovered\":\"hello world \\\"quoted\\\"\"")
                && j.contains("\"matches\":true")
        );
    }

    #[test]
    fn length_extension_endpoint_forges_and_hmac_resists() {
        let (s, j) = handle(
            "/api/length-extension",
            "msg=user%3Dbob&append=%26admin%3D1",
        );
        assert_eq!(s, 200);
        assert!(
            j.contains("\"server_accepts\":true")
                && j.contains("\"hmac_resists\":true")
                && j.contains("&admin=1")
        );
    }

    #[test]
    fn rsa_endpoint_generated_and_user_supplied() {
        let (s, j) = handle("/api/rsa", "");
        assert_eq!(s, 200);
        assert!(j.contains("\"factored\":true") && j.contains("\"decrypted\":424242"));
        let (_, j) = handle("/api/rsa", "n=1000000016000000063");
        assert!(j.contains("\"factored\":true"), "{j}");
        for bad in [
            "n=abc",
            "n=-5",
            "n=99999999999999999999",
            "n=9223372036854775808",
        ] {
            assert_eq!(handle("/api/rsa", bad).0, 400, "{bad}");
        }
        let (s, j) = handle("/api/rsa", "n=7");
        assert!(s == 200 && j.contains("\"factored\":false") || s == 400);
    }

    #[test]
    fn limits_and_routing() {
        assert_eq!(
            handle("/api/hash", &format!("text={}", "a".repeat(MAX_TEXT + 1))).0,
            400
        );
        assert_eq!(handle("/api/nope", "").0, 404);
    }
}
