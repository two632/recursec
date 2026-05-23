// RecurSec HTTP Fuzzer — Fast parameter and path fuzzer.
//
// Modes:
// - dir: Directory/path brute-force
// - param: Parameter value fuzzing
// - header: Header value fuzzing
// - method: HTTP method fuzzing
//
// Usage:
//   fuzzer dir -u http://target/ -w wordlist.txt [-t threads] [-mc 200,301]
//   fuzzer param -u http://target/?FUZZ=test -w payloads.txt
//   fuzzer header -u http://target/ -H "X-Custom: FUZZ" -w wordlist.txt

use std::collections::HashMap;
use std::io::{self, BufRead, Write, BufWriter};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
struct FuzzResult {
    url: String,
    status: u16,
    length: usize,
    word: String,
    redirect: String,
    duration_ms: u64,
}

#[derive(Debug, Clone)]
struct FuzzConfig {
    base_url: String,
    wordlist: String,
    threads: usize,
    timeout_ms: u64,
    match_codes: Vec<u16>,
    filter_codes: Vec<u16>,
    filter_size: Option<usize>,
    mode: String,
    method: String,
    headers: Vec<(String, String)>,
    follow_redirects: bool,
    json_output: bool,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        FuzzConfig {
            base_url: String::new(),
            wordlist: String::new(),
            threads: 10,
            timeout_ms: 5000,
            match_codes: vec![200, 201, 204, 301, 302, 307, 401, 403],
            filter_codes: vec![],
            filter_size: None,
            mode: "dir".into(),
            method: "GET".into(),
            headers: vec![],
            follow_redirects: false,
            json_output: false,
        }
    }
}

fn parse_url(url: &str) -> Option<(String, String, u16, String)> {
    let url = if url.starts_with("http://") {
        &url[7..]
    } else if url.starts_with("https://") {
        // Note: We only support HTTP in this minimal fuzzer
        eprintln!("Warning: HTTPS not supported in minimal mode, using HTTP");
        &url[8..]
    } else {
        url
    };

    let (host_port, path) = if let Some(pos) = url.find('/') {
        (&url[..pos], &url[pos..])
    } else {
        (url, "/")
    };

    let (host, port) = if let Some(pos) = host_port.rfind(':') {
        let port_str = &host_port[pos + 1..];
        match port_str.parse::<u16>() {
            Ok(p) => (&host_port[..pos], p),
            Err(_) => (host_port, 80),
        }
    } else {
        (host_port, 80)
    };

    Some(("http".into(), host.to_string(), port, path.to_string()))
}

fn send_http_request(host: &str, port: u16, method: &str, path: &str, headers: &[(String, String)], timeout_ms: u64) -> Option<(u16, usize, String)> {
    let addr = format!("{}:{}", host, port);
    let stream = TcpStream::connect_timeout(
        &addr.parse().ok()?,
        Duration::from_millis(timeout_ms),
    ).ok()?;

    stream.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok()?;
    stream.set_write_timeout(Some(Duration::from_millis(timeout_ms))).ok()?;

    let mut request = format!("{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n", method, path, host);
    for (key, value) in headers {
        request.push_str(&format!("{}: {}\r\n", key, value));
    }
    request.push_str("\r\n");

    let mut stream_w = stream.try_clone().ok()?;
    std::io::Write::write_all(&mut stream_w, request.as_bytes()).ok()?;

    let mut response = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match std::io::Read::read(&mut stream_w, &mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }

    let response_str = String::from_utf8_lossy(&response);

    // Parse status code
    let status_line = response_str.lines().next()?;
    let status: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;

    // Parse content length / body length
    let body_start = response_str.find("\r\n\r\n").unwrap_or(response_str.len());
    let body_len = response_str.len() - body_start - 4;

    // Find Location header for redirects
    let mut redirect = String::new();
    for line in response_str.lines() {
        if line.to_lowercase().starts_with("location:") {
            redirect = line[9..].trim().to_string();
            break;
        }
    }

    Some((status, body_len, redirect))
}

fn fuzz_word(config: &FuzzConfig, word: &str) -> Option<FuzzResult> {
    let (_, host, port, base_path) = parse_url(&config.base_url)?;

    let path = match config.mode.as_str() {
        "dir" => {
            let clean_word = word.trim_start_matches('/');
            if base_path.ends_with('/') {
                format!("{}{}", base_path, clean_word)
            } else {
                format!("{}/{}", base_path, clean_word)
            }
        }
        "param" => base_path.replace("FUZZ", word),
        _ => base_path.replace("FUZZ", word),
    };

    let headers: Vec<(String, String)> = config.headers.iter().map(|(k, v)| {
        (k.clone(), v.replace("FUZZ", word))
    }).collect();

    let start = Instant::now();
    let (status, length, redirect) = send_http_request(
        &host, port, &config.method, &path, &headers, config.timeout_ms,
    )?;
    let duration = start.elapsed().as_millis() as u64;

    // Apply filters
    if !config.match_codes.is_empty() && !config.match_codes.contains(&status) {
        return None;
    }
    if config.filter_codes.contains(&status) {
        return None;
    }
    if let Some(fs) = config.filter_size {
        if length == fs {
            return None;
        }
    }

    Some(FuzzResult {
        url: format!("http://{}:{}{}", host, port, path),
        status,
        length,
        word: word.to_string(),
        redirect,
        duration_ms: duration,
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("RecurSec HTTP Fuzzer");
        eprintln!();
        eprintln!("Usage:");
        eprintln!("  fuzzer dir -u <url> -w <wordlist> [-t threads] [-mc codes]");
        eprintln!("  fuzzer param -u <url_with_FUZZ> -w <payloads>");
        eprintln!("  fuzzer header -u <url> -H 'Header: FUZZ' -w <wordlist>");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  -u <url>       Target URL (use FUZZ as placeholder)");
        eprintln!("  -w <wordlist>  Wordlist file");
        eprintln!("  -t <n>         Threads (default: 10)");
        eprintln!("  -mc <codes>    Match status codes (comma-separated)");
        eprintln!("  -fc <codes>    Filter status codes");
        eprintln!("  -fs <size>     Filter response size");
        eprintln!("  -H <header>    Custom header");
        eprintln!("  -X <method>    HTTP method (default: GET)");
        eprintln!("  --json         JSON output");
        std::process::exit(1);
    }

    let mut config = FuzzConfig::default();
    config.mode = args[1].clone();

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "-u" => { i += 1; if i < args.len() { config.base_url = args[i].clone(); } }
            "-w" => { i += 1; if i < args.len() { config.wordlist = args[i].clone(); } }
            "-t" => { i += 1; if i < args.len() { config.threads = args[i].parse().unwrap_or(10); } }
            "-mc" => {
                i += 1;
                if i < args.len() {
                    config.match_codes = args[i].split(',')
                        .filter_map(|s| s.parse().ok())
                        .collect();
                }
            }
            "-fc" => {
                i += 1;
                if i < args.len() {
                    config.filter_codes = args[i].split(',')
                        .filter_map(|s| s.parse().ok())
                        .collect();
                }
            }
            "-fs" => {
                i += 1;
                if i < args.len() { config.filter_size = args[i].parse().ok(); }
            }
            "-H" => {
                i += 1;
                if i < args.len() {
                    if let Some(pos) = args[i].find(':') {
                        config.headers.push((
                            args[i][..pos].trim().to_string(),
                            args[i][pos+1..].trim().to_string(),
                        ));
                    }
                }
            }
            "-X" => { i += 1; if i < args.len() { config.method = args[i].clone(); } }
            "--json" => { config.json_output = true; }
            _ => {}
        }
        i += 1;
    }

    if config.base_url.is_empty() || config.wordlist.is_empty() {
        eprintln!("Error: -u and -w are required");
        std::process::exit(1);
    }

    // Load wordlist
    let file = std::fs::File::open(&config.wordlist).expect("Cannot open wordlist");
    let reader = io::BufReader::new(file);
    let words: Vec<String> = reader.lines()
        .filter_map(|l| l.ok())
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    let total = words.len();
    eprintln!("RecurSec Fuzzer — {} words, {} threads", total, config.threads);
    eprintln!("Target: {}", config.base_url);
    eprintln!();

    let config = Arc::new(config);
    let results: Arc<Mutex<Vec<FuzzResult>>> = Arc::new(Mutex::new(Vec::new()));
    let progress = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let start = Instant::now();

    // Distribute words across threads
    let chunk_size = (total + config.threads - 1) / config.threads;
    let mut handles = vec![];

    for chunk in words.chunks(chunk_size) {
        let chunk = chunk.to_vec();
        let config = Arc::clone(&config);
        let results = Arc::clone(&results);
        let progress = Arc::clone(&progress);

        let handle = thread::spawn(move || {
            for word in chunk {
                if let Some(result) = fuzz_word(&config, &word) {
                    if config.json_output {
                        let json = serde_json::to_string(&result).unwrap_or_default();
                        println!("{}", json);
                    } else {
                        println!(
                            "[{}] {} - {} bytes - {} ({}ms)",
                            result.status, result.url, result.length,
                            if result.redirect.is_empty() { "-" } else { &result.redirect },
                            result.duration_ms,
                        );
                    }
                    results.lock().unwrap().push(result);
                }
                progress.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let elapsed = start.elapsed();
    let final_results = results.lock().unwrap();
    eprintln!();
    eprintln!("Done: {} results from {} requests in {:.1}s ({:.0} req/s)",
        final_results.len(), total, elapsed.as_secs_f64(),
        total as f64 / elapsed.as_secs_f64(),
    );
}
