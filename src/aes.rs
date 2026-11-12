//! AES-128 (FIPS 197) and CBC mode with PKCS#7 padding, from scratch. Educational only:
//! not constant-time. The S-box is derived at runtime from GF(2^8) inversion.

pub const BLOCK: usize = 16;

fn xtime(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 }
}

fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    p
}

fn sboxes() -> ([u8; 256], [u8; 256]) {
    let mut s = [0u8; 256];
    let mut inv = [0u8; 256];
    for x in 0..=255u8 {
        let i = if x == 0 {
            0
        } else {
            (1..=255u8).find(|&y| gmul(x, y) == 1).unwrap_or(0)
        };
        let v =
            i ^ i.rotate_left(1) ^ i.rotate_left(2) ^ i.rotate_left(3) ^ i.rotate_left(4) ^ 0x63;
        s[x as usize] = v;
        inv[v as usize] = x;
    }
    (s, inv)
}

pub struct Aes128 {
    rk: [[u8; 16]; 11],
    s: [u8; 256],
    inv: [u8; 256],
}

impl Aes128 {
    pub fn new(key: &[u8; 16]) -> Self {
        let (s, inv) = sboxes();
        let mut w = [[0u8; 4]; 44];
        for i in 0..4 {
            w[i].copy_from_slice(&key[i * 4..i * 4 + 4]);
        }
        let mut rcon = 1u8;
        for i in 4..44 {
            let mut t = w[i - 1];
            if i % 4 == 0 {
                t = [
                    s[t[1] as usize] ^ rcon,
                    s[t[2] as usize],
                    s[t[3] as usize],
                    s[t[0] as usize],
                ];
                rcon = xtime(rcon);
            }
            for j in 0..4 {
                w[i][j] = w[i - 4][j] ^ t[j];
            }
        }
        let mut rk = [[0u8; 16]; 11];
        for (r, k) in rk.iter_mut().enumerate() {
            for c in 0..4 {
                k[c * 4..c * 4 + 4].copy_from_slice(&w[r * 4 + c]);
            }
        }
        Aes128 { rk, s, inv }
    }

    fn add(st: &mut [u8; 16], k: &[u8; 16]) {
        for i in 0..16 {
            st[i] ^= k[i];
        }
    }

    pub fn encrypt_block(&self, b: &[u8; 16]) -> [u8; 16] {
        let mut st = *b;
        Self::add(&mut st, &self.rk[0]);
        for r in 1..=10 {
            for x in st.iter_mut() {
                *x = self.s[*x as usize];
            }
            let t = st;
            for c in 0..4 {
                for row in 0..4 {
                    st[c * 4 + row] = t[((c + row) % 4) * 4 + row];
                }
            }
            if r != 10 {
                for c in 0..4 {
                    let a = [st[c * 4], st[c * 4 + 1], st[c * 4 + 2], st[c * 4 + 3]];
                    st[c * 4] = xtime(a[0]) ^ (xtime(a[1]) ^ a[1]) ^ a[2] ^ a[3];
                    st[c * 4 + 1] = a[0] ^ xtime(a[1]) ^ (xtime(a[2]) ^ a[2]) ^ a[3];
                    st[c * 4 + 2] = a[0] ^ a[1] ^ xtime(a[2]) ^ (xtime(a[3]) ^ a[3]);
                    st[c * 4 + 3] = (xtime(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ xtime(a[3]);
                }
            }
            Self::add(&mut st, &self.rk[r]);
        }
        st
    }

    pub fn decrypt_block(&self, b: &[u8; 16]) -> [u8; 16] {
        let mut st = *b;
        Self::add(&mut st, &self.rk[10]);
        for r in (0..10).rev() {
            let t = st;
            for c in 0..4 {
                for row in 0..4 {
                    st[((c + row) % 4) * 4 + row] = t[c * 4 + row];
                }
            }
            for x in st.iter_mut() {
                *x = self.inv[*x as usize];
            }
            Self::add(&mut st, &self.rk[r]);
            if r != 0 {
                for c in 0..4 {
                    let a = [st[c * 4], st[c * 4 + 1], st[c * 4 + 2], st[c * 4 + 3]];
                    st[c * 4] = gmul(a[0], 14) ^ gmul(a[1], 11) ^ gmul(a[2], 13) ^ gmul(a[3], 9);
                    st[c * 4 + 1] =
                        gmul(a[0], 9) ^ gmul(a[1], 14) ^ gmul(a[2], 11) ^ gmul(a[3], 13);
                    st[c * 4 + 2] =
                        gmul(a[0], 13) ^ gmul(a[1], 9) ^ gmul(a[2], 14) ^ gmul(a[3], 11);
                    st[c * 4 + 3] =
                        gmul(a[0], 11) ^ gmul(a[1], 13) ^ gmul(a[2], 9) ^ gmul(a[3], 14);
                }
            }
        }
        st
    }
}

pub fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let n = BLOCK - data.len() % BLOCK;
    let mut v = data.to_vec();
    v.extend(std::iter::repeat_n(n as u8, n));
    v
}

pub fn pkcs7_unpad(data: &[u8]) -> Option<Vec<u8>> {
    let n = *data.last()? as usize;
    if n == 0
        || n > BLOCK
        || n > data.len()
        || data[data.len() - n..].iter().any(|&b| b as usize != n)
    {
        return None;
    }
    Some(data[..data.len() - n].to_vec())
}

pub fn cbc_encrypt(aes: &Aes128, iv: &[u8; 16], plain: &[u8]) -> Vec<u8> {
    let mut prev = *iv;
    let mut out = Vec::new();
    for chunk in pkcs7_pad(plain).chunks_exact(BLOCK) {
        let mut b = [0u8; 16];
        for i in 0..16 {
            b[i] = chunk[i] ^ prev[i];
        }
        prev = aes.encrypt_block(&b);
        out.extend_from_slice(&prev);
    }
    out
}

/// Returns None when the padding is invalid. A server that reveals this difference is a padding oracle.
pub fn cbc_decrypt(aes: &Aes128, iv: &[u8; 16], ct: &[u8]) -> Option<Vec<u8>> {
    if ct.is_empty() || !ct.len().is_multiple_of(BLOCK) {
        return None;
    }
    let mut prev = *iv;
    let mut out = Vec::new();
    for chunk in ct.chunks_exact(BLOCK) {
        let c: [u8; 16] = chunk.try_into().ok()?;
        let d = aes.decrypt_block(&c);
        for i in 0..16 {
            out.push(d[i] ^ prev[i]);
        }
        prev = c;
    }
    pkcs7_unpad(&out)
}

pub fn ecb_encrypt(aes: &Aes128, plain: &[u8]) -> Vec<u8> {
    pkcs7_pad(plain)
        .chunks_exact(BLOCK)
        .flat_map(|c| aes.encrypt_block(c.try_into().expect("16 byte chunk")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::{decode, encode};

    fn arr(h: &str) -> [u8; 16] {
        decode(h).unwrap().try_into().unwrap()
    }

    #[test]
    fn fips197_appendix_c() {
        let aes = Aes128::new(&arr("000102030405060708090a0b0c0d0e0f"));
        let ct = aes.encrypt_block(&arr("00112233445566778899aabbccddeeff"));
        assert_eq!(encode(&ct), "69c4e0d86a7b0430d8cdb78070b4c55a");
        assert_eq!(
            encode(&aes.decrypt_block(&ct)),
            "00112233445566778899aabbccddeeff"
        );
    }

    #[test]
    fn fips197_appendix_b() {
        let aes = Aes128::new(&arr("2b7e151628aed2a6abf7158809cf4f3c"));
        assert_eq!(
            encode(&aes.encrypt_block(&arr("3243f6a8885a308d313198a2e0370734"))),
            "3925841d02dc09fbdc118597196a0b32"
        );
    }

    #[test]
    fn nist_sp800_38a_cbc() {
        let aes = Aes128::new(&arr("2b7e151628aed2a6abf7158809cf4f3c"));
        let iv = arr("000102030405060708090a0b0c0d0e0f");
        let pt =
            decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51").unwrap();
        let ct = cbc_encrypt(&aes, &iv, &pt);
        assert_eq!(
            encode(&ct[..32]),
            "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
        );
    }

    #[test]
    fn cbc_roundtrip_all_lengths() {
        let aes = Aes128::new(&[7; 16]);
        for n in 0..70 {
            let pt: Vec<u8> = (0..n as u8).collect();
            let ct = cbc_encrypt(&aes, &[9; 16], &pt);
            assert_eq!(cbc_decrypt(&aes, &[9; 16], &ct).unwrap(), pt);
        }
    }

    #[test]
    fn padding_validation() {
        assert!(pkcs7_unpad(&[1, 2, 3, 4]).is_none());
        assert!(pkcs7_unpad(&[]).is_none());
        assert!(pkcs7_unpad(&[0]).is_none());
        assert!(pkcs7_unpad(&[17; 17]).is_none());
        assert_eq!(pkcs7_unpad(&[9, 2, 2]).unwrap(), vec![9]);
        assert_eq!(pkcs7_unpad(&[16; 16]).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn ecb_leaks_repetition_and_cbc_does_not() {
        let aes = Aes128::new(&[1; 16]);
        let pt = [b'A'; 48];
        let e = ecb_encrypt(&aes, &pt);
        assert_eq!(e[..16], e[16..32]);
        let c = cbc_encrypt(&aes, &[2; 16], &pt);
        assert_ne!(c[..16], c[16..32]);
    }
}
