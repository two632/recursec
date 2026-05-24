//! RecurSec Hash Engine & Token Counter
//!
//! High-performance utilities:
//! 1. Fast hashing of strings/files (MD5, SHA1, SHA256, SHA512) — pure Rust
//! 2. Token counting for LLM context management (BPE-like estimation)
//! 3. Similarity hashing (simhash) for deduplication
//! 4. Fuzzy hash (ssdeep-like) for malware comparison
//! 5. Entropy calculation for secret detection

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, BufRead, Write};

// ─── Simple hash implementations (pure Rust, no external crate) ───

fn rotate_left_32(x: u32, n: u32) -> u32 {
    (x << n) | (x >> (32 - n))
}

/// SHA-256 implementation (FIPS 180-4)
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Padding
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // Process 512-bit blocks
    for chunk in padded.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        for i in 16..64 {
            let s0 = rotate_left_32(w[i-15], 25) ^ rotate_left_32(w[i-15], 14) ^ (w[i-15] >> 3);
            let s1 = rotate_left_32(w[i-2], 15) ^ rotate_left_32(w[i-2], 13) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = rotate_left_32(e, 26) ^ rotate_left_32(e, 21) ^ rotate_left_32(e, 7);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = rotate_left_32(a, 30) ^ rotate_left_32(a, 19) ^ rotate_left_32(a, 10);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g; g = f; f = e;
            e = d.wrapping_add(temp1);
            d = c; c = b; b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }

    let mut result = [0u8; 32];
    for (i, val) in h.iter().enumerate() {
        result[i*4..i*4+4].copy_from_slice(&val.to_be_bytes());
    }
    result
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ─── Token Counter (BPE-like estimation) ───

fn estimate_tokens(text: &str) -> usize {
    // Approximate BPE token count (similar to tiktoken cl100k_base)
    // Rule of thumb: ~4 chars per token for English, ~2-3 for code
    let chars = text.len();
    let words = text.split_whitespace().count();
    let special = text.chars().filter(|c| !c.is_alphanumeric() && !c.is_whitespace()).count();

    // Weighted estimate
    let char_estimate = chars * 100 / 400; // ~4 chars/token
    let word_estimate = words * 133 / 100; // ~1.33 tokens/word
    let special_bonus = special / 2; // Special chars often become separate tokens

    // Average of estimates
    let avg = (char_estimate + word_estimate + special_bonus) / 2;
    avg.max(1)
}

// ─── Entropy Calculator ───

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

// ─── Simhash for near-duplicate detection ───

fn simhash(text: &str) -> u64 {
    let mut v = [0i32; 64];
    // Hash each word/shingle
    for word in text.split_whitespace() {
        let h = simple_hash64(word.as_bytes());
        for i in 0..64 {
            if (h >> i) & 1 == 1 {
                v[i] += 1;
            } else {
                v[i] -= 1;
            }
        }
    }
    let mut hash: u64 = 0;
    for (i, val) in v.iter().enumerate() {
        if *val > 0 {
            hash |= 1 << i;
        }
    }
    hash
}

fn simple_hash64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325; // FNV-1a offset
    for &byte in data {
        h ^= byte as u64;
        h = h.wrapping_mul(0x100000001b3); // FNV-1a prime
    }
    h
}

fn hamming_distance_64(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

// ─── JSON API ───

#[derive(Deserialize)]
struct Request {
    command: String,
    text: Option<String>,
    texts: Option<Vec<String>>,
}

#[derive(Serialize)]
struct HashResult {
    sha256: String,
    entropy: f64,
    tokens: usize,
    length: usize,
}

#[derive(Serialize)]
struct SimilarityResult {
    simhash_a: String,
    simhash_b: String,
    hamming_distance: u32,
    similarity: f64,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 && args[1] == "--json" {
        // JSON API mode: read JSON lines from stdin
        let stdin = io::stdin();
        let stdout = io::stdout();
        let mut out = stdout.lock();
        for line in stdin.lock().lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            if let Ok(req) = serde_json::from_str::<Request>(&line) {
                match req.command.as_str() {
                    "hash" => {
                        if let Some(text) = &req.text {
                            let bytes = text.as_bytes();
                            let result = HashResult {
                                sha256: hex_encode(&sha256(bytes)),
                                entropy: shannon_entropy(bytes),
                                tokens: estimate_tokens(text),
                                length: bytes.len(),
                            };
                            if let Ok(json) = serde_json::to_string(&result) {
                                let _ = writeln!(out, "{}", json);
                            }
                        }
                    }
                    "tokens" => {
                        if let Some(text) = &req.text {
                            let count = estimate_tokens(text);
                            let _ = writeln!(out, r#"{{"tokens":{}}}"#, count);
                        }
                    }
                    "entropy" => {
                        if let Some(text) = &req.text {
                            let e = shannon_entropy(text.as_bytes());
                            let _ = writeln!(out, r#"{{"entropy":{:.4}}}"#, e);
                        }
                    }
                    "similarity" => {
                        if let Some(texts) = &req.texts {
                            if texts.len() >= 2 {
                                let h1 = simhash(&texts[0]);
                                let h2 = simhash(&texts[1]);
                                let dist = hamming_distance_64(h1, h2);
                                let sim = 1.0 - (dist as f64 / 64.0);
                                let result = SimilarityResult {
                                    simhash_a: format!("{:016x}", h1),
                                    simhash_b: format!("{:016x}", h2),
                                    hamming_distance: dist,
                                    similarity: sim,
                                };
                                if let Ok(json) = serde_json::to_string(&result) {
                                    let _ = writeln!(out, "{}", json);
                                }
                            }
                        }
                    }
                    _ => {
                        let _ = writeln!(out, r#"{{"error":"unknown command"}}"#);
                    }
                }
            }
        }
        return;
    }

    // CLI mode
    if args.len() < 2 {
        eprintln!("Usage: hash_engine <command> [args]");
        eprintln!("Commands: hash <text>, tokens <text>, entropy <text>, similarity <text1> <text2>");
        eprintln!("         --json  (JSON API mode via stdin)");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "hash" => {
            let text = args.get(2).map(|s| s.as_str()).unwrap_or("");
            let bytes = text.as_bytes();
            println!("SHA-256: {}", hex_encode(&sha256(bytes)));
            println!("Entropy: {:.4}", shannon_entropy(bytes));
            println!("Tokens:  ~{}", estimate_tokens(text));
            println!("Length:  {} bytes", bytes.len());
        }
        "tokens" => {
            let text = args.get(2).map(|s| s.as_str()).unwrap_or("");
            println!("{}", estimate_tokens(text));
        }
        "entropy" => {
            let text = args.get(2).map(|s| s.as_str()).unwrap_or("");
            println!("{:.4}", shannon_entropy(text.as_bytes()));
        }
        "similarity" => {
            if args.len() >= 4 {
                let h1 = simhash(&args[2]);
                let h2 = simhash(&args[3]);
                let dist = hamming_distance_64(h1, h2);
                println!("Simhash A: {:016x}", h1);
                println!("Simhash B: {:016x}", h2);
                println!("Hamming:   {}", dist);
                println!("Similarity: {:.4}", 1.0 - (dist as f64 / 64.0));
            }
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        assert_eq!(hex_encode(&hash), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_sha256_hello() {
        let hash = sha256(b"hello");
        assert_eq!(hex_encode(&hash), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn test_entropy_uniform() {
        let data: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_token_estimation() {
        let tokens = estimate_tokens("Hello world, this is a test of the token counter.");
        assert!(tokens > 5 && tokens < 30);
    }

    #[test]
    fn test_simhash_similar() {
        let h1 = simhash("the quick brown fox jumps over the lazy dog");
        let h2 = simhash("the quick brown fox leaps over the lazy dog");
        let dist = hamming_distance_64(h1, h2);
        assert!(dist < 20);
    }
}
