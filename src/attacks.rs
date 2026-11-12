//! Three classic cryptographic attacks that work against real mistakes.

use crate::aes::{cbc_decrypt, Aes128, BLOCK};
use crate::sha256::{padding, sha256, Sha256};

// ---------------------------------------------------------------- padding oracle

pub struct OracleResult {
    pub plaintext: Vec<u8>,
    pub queries: usize,
}

/// Decrypts `ct` (CBC, PKCS#7) without the key, using only `oracle(iv, ct) -> padding valid?`.
/// Vaudenay, "Security Flaws Induced by CBC Padding" (2002).
pub fn padding_oracle_attack<F: FnMut(&[u8; 16], &[u8]) -> bool>(
    iv: &[u8; 16],
    ct: &[u8],
    mut oracle: F,
) -> Option<OracleResult> {
    if ct.is_empty() || !ct.len().is_multiple_of(BLOCK) {
        return None;
    }
    let mut plain = Vec::new();
    let mut queries = 0usize;
    let mut prev = *iv;
    for block in ct.chunks_exact(BLOCK) {
        let target: [u8; 16] = block.try_into().ok()?;
        let mut inter = [0u8; 16]; // intermediate state: D(target)
        for pos in (0..16).rev() {
            let pad = (16 - pos) as u8;
            let mut found = None;
            for guess in 0..=255u8 {
                let mut forged = [0u8; 16];
                for k in pos + 1..16 {
                    forged[k] = inter[k] ^ pad;
                }
                forged[pos] = guess;
                queries += 1;
                if oracle(&forged, &target) {
                    // A hit on the last byte may be a longer valid padding (e.g. ...02 02).
                    // Flip the previous byte: a real 0x01 padding survives, a false positive does not.
                    if pos == 15 {
                        let mut check = forged;
                        check[14] ^= 0xff;
                        queries += 1;
                        if !oracle(&check, &target) {
                            continue;
                        }
                    }
                    found = Some(guess);
                    break;
                }
            }
            inter[pos] = found? ^ pad;
        }
        for i in 0..16 {
            plain.push(inter[i] ^ prev[i]);
        }
        prev = target;
    }
    let n = *plain.last()? as usize;
    if n == 0 || n > BLOCK || n > plain.len() {
        return None;
    }
    plain.truncate(plain.len() - n);
    Some(OracleResult {
        plaintext: plain,
        queries,
    })
}

/// The vulnerable server side: reports only whether the padding was valid.
pub fn server_oracle<'a>(aes: &'a Aes128) -> impl FnMut(&[u8; 16], &[u8]) -> bool + 'a {
    move |iv, ct| cbc_decrypt(aes, iv, ct).is_some()
}

// ---------------------------------------------------------------- length extension

pub struct Forgery {
    pub secret_len: usize,
    pub message: Vec<u8>,
    pub mac: [u8; 32],
    pub tries: usize,
}

/// Naive MAC: sha256(secret || message). Broken by design.
pub fn naive_mac(secret: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(secret);
    h.update(msg);
    h.finalize()
}

/// Given only `msg`, `mac` and a verifier, forges a valid MAC for `msg || padding || append`.
/// The attacker does not know the secret length, so it tries every plausible one.
pub fn length_extension<F: FnMut(&[u8], &[u8; 32]) -> bool>(
    msg: &[u8],
    mac: &[u8; 32],
    append: &[u8],
    max_secret_len: usize,
    mut verify: F,
) -> Option<Forgery> {
    for secret_len in 1..=max_secret_len {
        let glue = padding((secret_len + msg.len()) as u64);
        let processed = (secret_len + msg.len() + glue.len()) as u64;
        let mut h = Sha256::from_digest(mac, processed);
        h.update(append);
        let forged_mac = h.finalize();
        let mut forged_msg = msg.to_vec();
        forged_msg.extend_from_slice(&glue);
        forged_msg.extend_from_slice(append);
        if verify(&forged_msg, &forged_mac) {
            return Some(Forgery {
                secret_len,
                message: forged_msg,
                mac: forged_mac,
                tries: secret_len,
            });
        }
    }
    None
}

/// The fix: HMAC is not extendable.
pub fn hmac_is_not_extendable(secret: &[u8], msg: &[u8], append: &[u8]) -> bool {
    let mac = crate::sha256::hmac_sha256(secret, msg);
    length_extension(msg, &mac, append, 32, |m, t| {
        crate::sha256::hmac_sha256(secret, m) == *t
    })
    .is_none()
}

// ---------------------------------------------------------------- RSA / Fermat

pub fn mulmod(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 * b as u128) % m as u128) as u64
}

pub fn powmod(mut b: u64, mut e: u64, m: u64) -> u64 {
    let mut r = 1u64 % m;
    b %= m;
    while e > 0 {
        if e & 1 == 1 {
            r = mulmod(r, b, m);
        }
        b = mulmod(b, b, m);
        e >>= 1;
    }
    r
}

pub fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    for p in [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if n.is_multiple_of(p) {
            return n == p;
        }
    }
    let (mut d, mut s) = (n - 1, 0);
    while d % 2 == 0 {
        d /= 2;
        s += 1;
    }
    'w: for a in [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let mut x = powmod(a, d, n);
        if x == 1 || x == n - 1 {
            continue;
        }
        for _ in 0..s - 1 {
            x = mulmod(x, x, n);
            if x == n - 1 {
                continue 'w;
            }
        }
        return false;
    }
    true
}

pub fn next_prime(mut n: u64) -> u64 {
    if n.is_multiple_of(2) {
        n += 1;
    }
    while !is_prime(n) {
        n += 2;
    }
    n
}

pub fn isqrt(n: u64) -> u64 {
    let mut x = (n as f64).sqrt() as u64;
    while (x as u128) * (x as u128) > n as u128 {
        x -= 1;
    }
    while ((x + 1) as u128) * ((x + 1) as u128) <= n as u128 {
        x += 1;
    }
    x
}

pub struct Factored {
    pub p: u64,
    pub q: u64,
    pub iterations: u64,
}

/// Fermat's method: fast when the two primes are close, which is a key generation bug.
pub fn fermat_factor(n: u64, max_iter: u64) -> Option<Factored> {
    if n < 4 || n.is_multiple_of(2) {
        return None;
    }
    let mut a = isqrt(n);
    if a * a != n {
        a += 1;
    }
    for i in 0..max_iter {
        let b2 = (a as u128 * a as u128).checked_sub(n as u128)?;
        let b = isqrt_u128(b2);
        if b * b == b2 {
            let (p, q) = ((a as u128 - b) as u64, (a as u128 + b) as u64);
            if p > 1 {
                return Some(Factored {
                    p,
                    q,
                    iterations: i + 1,
                });
            }
        }
        a += 1;
    }
    None
}

fn isqrt_u128(n: u128) -> u128 {
    let mut x = (n as f64).sqrt() as u128;
    while x * x > n {
        x -= 1;
    }
    while (x + 1) * (x + 1) <= n {
        x += 1;
    }
    x
}

pub fn modinv(a: u64, m: u64) -> Option<u64> {
    let (mut t, mut nt, mut r, mut nr) = (0i128, 1i128, m as i128, a as i128 % m as i128);
    while nr != 0 {
        let q = r / nr;
        (t, nt) = (nt, t - q * nt);
        (r, nr) = (nr, r - q * nr);
    }
    if r != 1 {
        return None;
    }
    Some((if t < 0 { t + m as i128 } else { t }) as u64)
}

pub struct Rsa {
    pub n: u64,
    pub e: u64,
}

/// Builds a toy RSA key from two primes. Returns the public key and the private exponent.
pub fn rsa_from_primes(p: u64, q: u64) -> Option<(Rsa, u64)> {
    let phi = (p - 1) as u128 * (q - 1) as u128;
    let phi = u64::try_from(phi).ok()?;
    let e = 65537;
    let d = modinv(e, phi)?;
    Some((
        Rsa {
            n: p.checked_mul(q)?,
            e,
        },
        d,
    ))
}

#[allow(dead_code)]
pub fn digest_hex(data: &[u8]) -> String {
    crate::hex::encode(&sha256(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::cbc_encrypt;

    #[test]
    fn padding_oracle_recovers_plaintext_without_the_key() {
        let aes = Aes128::new(&[0x42; 16]);
        let iv = [0x24; 16];
        for msg in [
            &b""[..],
            b"A",
            b"attack at dawn!!",
            b"The quick brown fox jumps over the lazy dog, twice.",
        ] {
            let ct = cbc_encrypt(&aes, &iv, msg);
            let r = padding_oracle_attack(&iv, &ct, server_oracle(&aes)).expect("attack succeeds");
            assert_eq!(r.plaintext, msg);
            assert!(r.queries <= ct.len() / 16 * (16 * 256 + 16));
        }
    }

    #[test]
    fn padding_oracle_handles_the_02_02_false_positive() {
        // Plaintext ending in 0x02 makes the first hit at the last byte ambiguous for some guesses.
        let aes = Aes128::new(&[3; 16]);
        let iv = [0; 16];
        let msg = [b'x', 2u8];
        let ct = cbc_encrypt(&aes, &iv, &msg);
        assert_eq!(
            padding_oracle_attack(&iv, &ct, server_oracle(&aes))
                .unwrap()
                .plaintext,
            msg
        );
    }

    #[test]
    fn padding_oracle_rejects_malformed_input() {
        assert!(padding_oracle_attack(&[0; 16], &[], |_, _| true).is_none());
        assert!(padding_oracle_attack(&[0; 16], &[1; 17], |_, _| true).is_none());
        assert!(padding_oracle_attack(&[0; 16], &[1; 16], |_, _| false).is_none());
    }

    #[test]
    fn length_extension_forges_a_valid_mac() {
        let secret = b"s3cr3t-key-of-unknown-length";
        let msg = b"user=alice&role=reader";
        let mac = naive_mac(secret, msg);
        let f = length_extension(msg, &mac, b"&role=admin", 64, |m, t| {
            naive_mac(secret, m) == *t
        })
        .expect("forged");
        assert_eq!(f.secret_len, secret.len());
        assert!(f.message.ends_with(b"&role=admin"));
        assert!(f.message.starts_with(msg));
        assert_eq!(naive_mac(secret, &f.message), f.mac);
    }

    #[test]
    fn length_extension_fails_if_secret_is_longer_than_search_range() {
        let secret = [7u8; 40];
        let mac = naive_mac(&secret, b"m");
        assert!(
            length_extension(b"m", &mac, b"x", 32, |m, t| naive_mac(&secret, m) == *t).is_none()
        );
    }

    #[test]
    fn hmac_resists_length_extension() {
        assert!(hmac_is_not_extendable(
            b"secret",
            b"user=alice",
            b"&admin=1"
        ));
    }

    #[test]
    fn primes_and_modular_arithmetic() {
        assert!(is_prime(2) && is_prime(97) && is_prime(1_000_000_007));
        assert!(!is_prime(1) && !is_prime(1_000_000_007 * 3) && !is_prime(561));
        assert_eq!(next_prime(100), 101);
        assert_eq!(powmod(4, 13, 497), 445);
        assert_eq!(modinv(3, 11), Some(4));
        assert_eq!(modinv(2, 4), None);
        assert_eq!(isqrt(99), 9);
        assert_eq!(isqrt(u64::MAX), 4294967295);
    }

    #[test]
    fn fermat_breaks_close_primes_and_the_key_decrypts() {
        let p = next_prime(1_000_000_000);
        let q = next_prime(p + 5000);
        let (pubk, d) = rsa_from_primes(p, q).unwrap();
        let f = fermat_factor(pubk.n, 1_000_000).expect("close primes fall fast");
        assert_eq!((f.p, f.q), (p, q));
        assert!(f.iterations < 1000);
        let (_, d2) = rsa_from_primes(f.p, f.q).unwrap();
        assert_eq!(d, d2);
        let c = powmod(123456789, pubk.e, pubk.n);
        assert_eq!(powmod(c, d2, pubk.n), 123456789);
    }

    #[test]
    fn fermat_gives_up_on_distant_primes_and_bad_input() {
        let n = next_prime(1_000_003) * next_prime(2_000_000_011);
        assert!(fermat_factor(n, 1000).is_none());
        assert!(fermat_factor(4, 10).is_none());
        assert!(fermat_factor(1, 10).is_none());
        assert!(fermat_factor(10, 10).is_none());
    }
}
