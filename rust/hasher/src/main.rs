// RecurSec Hash Utility — Hash identification, generation, and dictionary attack.
//
// Modes:
// - identify: Identify hash type from string
// - generate: Generate hash from input
// - crack: Dictionary attack against a hash
// - batch: Identify/crack multiple hashes from file
//
// Usage:
//   hasher identify <hash>
//   hasher generate <algorithm> <input>
//   hasher crack <hash> -w <wordlist>
//   hasher batch -i <hashes_file> -w <wordlist>

use std::io::{self, BufRead, Write, BufWriter};
use std::collections::HashMap;
use std::time::Instant;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
struct HashIdentification {
    hash: String,
    possible_types: Vec<String>,
    length: usize,
    charset: String,
}

#[derive(Debug, Clone, Serialize)]
struct CrackResult {
    hash: String,
    hash_type: String,
    plaintext: String,
    found: bool,
    attempts: u64,
    duration_ms: u64,
}

// Simple hash implementations (no external crypto deps)

fn md5_hash(input: &[u8]) -> String {
    // MD5 implementation (RFC 1321)
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xefcdab89;
    let mut h2: u32 = 0x98badcfe;
    let mut h3: u32 = 0x10325476;

    let s: [u32; 64] = [
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
    ];

    let k: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    // Pre-process: add padding
    let orig_len = input.len();
    let bit_len = (orig_len as u64) * 8;
    let mut msg = input.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    // Process each 512-bit chunk
    for chunk_start in (0..msg.len()).step_by(64) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            let offset = chunk_start + i * 4;
            m[i] = u32::from_le_bytes([
                msg[offset], msg[offset + 1], msg[offset + 2], msg[offset + 3],
            ]);
        }

        let (mut a, mut b, mut c, mut d) = (h0, h1, h2, h3);

        for i in 0..64usize {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };

            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                (a.wrapping_add(f).wrapping_add(k[i]).wrapping_add(m[g]))
                    .rotate_left(s[i]),
            );
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
    }

    format!("{:08x}{:08x}{:08x}{:08x}",
        h0.swap_bytes(), h1.swap_bytes(), h2.swap_bytes(), h3.swap_bytes())
}

fn sha1_hash(input: &[u8]) -> String {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let orig_len = input.len();
    let bit_len = (orig_len as u64) * 8;
    let mut msg = input.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk_start in (0..msg.len()).step_by(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            let offset = chunk_start + i * 4;
            w[i] = u32::from_be_bytes([
                msg[offset], msg[offset + 1], msg[offset + 2], msg[offset + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };

            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    format!("{:08x}{:08x}{:08x}{:08x}{:08x}", h0, h1, h2, h3, h4)
}

fn sha256_hash(input: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let orig_len = input.len();
    let bit_len = (orig_len as u64) * 8;
    let mut msg = input.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk_start in (0..msg.len()).step_by(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            let offset = chunk_start + i * 4;
            w[i] = u32::from_be_bytes([
                msg[offset], msg[offset + 1], msg[offset + 2], msg[offset + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut wv = h;

        for i in 0..64 {
            let s1 = wv[4].rotate_right(6) ^ wv[4].rotate_right(11) ^ wv[4].rotate_right(25);
            let ch = (wv[4] & wv[5]) ^ ((!wv[4]) & wv[6]);
            let temp1 = wv[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(k[i]).wrapping_add(w[i]);
            let s0 = wv[0].rotate_right(2) ^ wv[0].rotate_right(13) ^ wv[0].rotate_right(22);
            let maj = (wv[0] & wv[1]) ^ (wv[0] & wv[2]) ^ (wv[1] & wv[2]);
            let temp2 = s0.wrapping_add(maj);

            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3].wrapping_add(temp1);
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = temp1.wrapping_add(temp2);
        }

        for i in 0..8 {
            h[i] = h[i].wrapping_add(wv[i]);
        }
    }

    h.iter().map(|v| format!("{:08x}", v)).collect()
}

fn identify_hash(hash: &str) -> HashIdentification {
    let len = hash.len();
    let is_hex = hash.chars().all(|c| c.is_ascii_hexdigit());
    let is_base64 = hash.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');

    let charset = if is_hex { "hex" } else if is_base64 { "base64" } else { "mixed" };

    let mut types = Vec::new();

    if is_hex {
        match len {
            32 => { types.push("MD5".into()); types.push("NTLM".into()); }
            40 => { types.push("SHA-1".into()); types.push("MySQL5".into()); }
            56 => { types.push("SHA-224".into()); }
            64 => { types.push("SHA-256".into()); types.push("SHA3-256".into()); }
            96 => { types.push("SHA-384".into()); types.push("SHA3-384".into()); }
            128 => { types.push("SHA-512".into()); types.push("SHA3-512".into()); types.push("Whirlpool".into()); }
            _ => {}
        }
    }

    // Check for common hash prefixes
    if hash.starts_with("$1$") { types.push("MD5crypt".into()); }
    if hash.starts_with("$2$") || hash.starts_with("$2a$") || hash.starts_with("$2b$") { types.push("bcrypt".into()); }
    if hash.starts_with("$5$") { types.push("SHA-256crypt".into()); }
    if hash.starts_with("$6$") { types.push("SHA-512crypt".into()); }
    if hash.starts_with("$apr1$") { types.push("Apache MD5".into()); }
    if hash.starts_with("$argon2") { types.push("Argon2".into()); }
    if hash.starts_with("$pbkdf2") { types.push("PBKDF2".into()); }
    if hash.starts_with("{SHA}") { types.push("LDAP SHA".into()); }
    if hash.starts_with("{SSHA}") { types.push("LDAP SSHA".into()); }

    if hash.contains(':') && len > 32 {
        types.push("hash:salt format".into());
    }

    if types.is_empty() {
        types.push("Unknown".into());
    }

    HashIdentification {
        hash: hash.to_string(),
        possible_types: types,
        length: len,
        charset: charset.into(),
    }
}

fn crack_hash(hash: &str, wordlist_path: &str) -> CrackResult {
    let hash_lower = hash.to_lowercase();
    let hash_type = match hash.len() {
        32 => "md5",
        40 => "sha1",
        64 => "sha256",
        _ => "unknown",
    };

    let file = match std::fs::File::open(wordlist_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Cannot open wordlist: {}", e);
            return CrackResult {
                hash: hash.into(), hash_type: hash_type.into(),
                plaintext: String::new(), found: false, attempts: 0, duration_ms: 0,
            };
        }
    };

    let reader = io::BufReader::new(file);
    let start = Instant::now();
    let mut attempts = 0u64;

    for line in reader.lines() {
        let word = match line {
            Ok(w) => w,
            Err(_) => continue,
        };
        let trimmed = word.trim();
        if trimmed.is_empty() { continue; }

        attempts += 1;

        let computed = match hash_type {
            "md5" => md5_hash(trimmed.as_bytes()),
            "sha1" => sha1_hash(trimmed.as_bytes()),
            "sha256" => sha256_hash(trimmed.as_bytes()),
            _ => continue,
        };

        if computed == hash_lower {
            return CrackResult {
                hash: hash.into(), hash_type: hash_type.into(),
                plaintext: trimmed.into(), found: true,
                attempts, duration_ms: start.elapsed().as_millis() as u64,
            };
        }
    }

    CrackResult {
        hash: hash.into(), hash_type: hash_type.into(),
        plaintext: String::new(), found: false,
        attempts, duration_ms: start.elapsed().as_millis() as u64,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("RecurSec Hash Utility");
        eprintln!();
        eprintln!("Usage:");
        eprintln!("  hasher identify <hash>");
        eprintln!("  hasher generate <md5|sha1|sha256> <input>");
        eprintln!("  hasher crack <hash> -w <wordlist>");
        eprintln!("  hasher batch -i <hashes_file> [-w <wordlist>]");
        std::process::exit(1);
    }

    let mode = &args[1];

    match mode.as_str() {
        "identify" | "id" => {
            if args.len() < 3 {
                eprintln!("Usage: hasher identify <hash>");
                std::process::exit(1);
            }
            let result = identify_hash(&args[2]);
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
        }
        "generate" | "gen" => {
            if args.len() < 4 {
                eprintln!("Usage: hasher generate <md5|sha1|sha256> <input>");
                std::process::exit(1);
            }
            let algo = &args[2];
            let input = &args[3];
            let hash = match algo.as_str() {
                "md5" => md5_hash(input.as_bytes()),
                "sha1" => sha1_hash(input.as_bytes()),
                "sha256" => sha256_hash(input.as_bytes()),
                _ => {
                    eprintln!("Unknown algorithm: {} (supported: md5, sha1, sha256)", algo);
                    std::process::exit(1);
                }
            };
            println!("{}", hash);
        }
        "crack" => {
            if args.len() < 3 {
                eprintln!("Usage: hasher crack <hash> -w <wordlist>");
                std::process::exit(1);
            }
            let hash = &args[2];
            let mut wordlist = "";
            let mut i = 3;
            while i < args.len() {
                if args[i] == "-w" { i += 1; if i < args.len() { wordlist = &args[i]; } }
                i += 1;
            }
            if wordlist.is_empty() {
                eprintln!("Wordlist required: -w <wordlist>");
                std::process::exit(1);
            }
            let result = crack_hash(hash, wordlist);
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
        }
        "batch" => {
            let mut input = "";
            let mut wordlist = "";
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "-i" => { i += 1; if i < args.len() { input = &args[i]; } }
                    "-w" => { i += 1; if i < args.len() { wordlist = &args[i]; } }
                    _ => {}
                }
                i += 1;
            }
            if input.is_empty() {
                eprintln!("Usage: hasher batch -i <hashes_file> [-w <wordlist>]");
                std::process::exit(1);
            }

            let file = std::fs::File::open(input).expect("Cannot open hashes file");
            let reader = io::BufReader::new(file);

            for line in reader.lines() {
                let hash = match line {
                    Ok(h) => h.trim().to_string(),
                    Err(_) => continue,
                };
                if hash.is_empty() { continue; }

                if wordlist.is_empty() {
                    let id = identify_hash(&hash);
                    println!("{}", serde_json::to_string(&id).unwrap());
                } else {
                    let result = crack_hash(&hash, wordlist);
                    println!("{}", serde_json::to_string(&result).unwrap());
                }
            }
        }
        _ => {
            eprintln!("Unknown mode: {}", mode);
            std::process::exit(1);
        }
    }
}
