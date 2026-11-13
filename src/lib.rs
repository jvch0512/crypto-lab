// Newer clippy (1.99+) suggests `as_chunks` for constant-size `chunks_exact`, which is not stable on older toolchains.
// `unknown_lints` keeps older clippy versions quiet about a lint they do not have yet.
#![allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
pub mod aes;
pub mod api;
pub mod attacks;
pub mod hex;
pub mod http;
pub mod sha256;
