//! RecurSec Parallel Port Scanner
//! High-performance TCP port scanner using async I/O.
//!
//! Features:
//! - Thread pool with configurable worker count
//! - Non-blocking TCP connect with timeout
//! - Service fingerprinting
//! - JSON output for agent consumption
//! - Batch scanning of port ranges
//!
//! Usage: port_scanner --host 10.0.0.1 --ports 1-65535 --threads 256 --timeout 500

use std::env;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct ScanConfig {
    host: String,
    port_start: u16,
    port_end: u16,
    threads: usize,
    timeout_ms: u64,
    json_output: bool,
    grab_banner: bool,
}

#[derive(Clone)]
struct PortResult {
    port: u16,
    open: bool,
    service: String,
    banner: String,
    latency_ms: f64,
}

fn get_service(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        135 => "msrpc",
        139 => "netbios",
        143 => "imap",
        161 => "snmp",
        389 => "ldap",
        443 => "https",
        445 => "smb",
        465 => "smtps",
        587 => "submission",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1521 => "oracle",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        6443 => "k8s-api",
        8080 => "http-proxy",
        8443 => "https-alt",
        9200 => "elasticsearch",
        27017 => "mongodb",
        _ => "unknown",
    }
}

fn scan_port(host: &str, port: u16, timeout: Duration, grab_banner: bool) -> PortResult {
    let addr_str = format!("{}:{}", host, port);
    let service = get_service(port).to_string();

    let addrs: Vec<SocketAddr> = match addr_str.to_socket_addrs() {
        Ok(a) => a.collect(),
        Err(_) => {
            return PortResult {
                port,
                open: false,
                service,
                banner: String::new(),
                latency_ms: 0.0,
            };
        }
    };

    if addrs.is_empty() {
        return PortResult {
            port,
            open: false,
            service,
            banner: String::new(),
            latency_ms: 0.0,
        };
    }

    let start = Instant::now();
    match TcpStream::connect_timeout(&addrs[0], timeout) {
        Ok(mut stream) => {
            let latency = start.elapsed().as_secs_f64() * 1000.0;
            let mut banner = String::new();

            if grab_banner {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));

                // Try to read banner
                let mut buf = [0u8; 256];
                match stream.read(&mut buf) {
                    Ok(n) if n > 0 => {
                        banner = buf[..n]
                            .iter()
                            .map(|&b| {
                                if b >= 32 && b < 127 {
                                    b as char
                                } else {
                                    '.'
                                }
                            })
                            .collect();
                    }
                    _ => {
                        // Try sending HTTP probe for web ports
                        if port == 80 || port == 8080 || port == 443 || port == 8443 {
                            let probe = b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n";
                            if stream.write_all(probe).is_ok() {
                                let mut resp = [0u8; 256];
                                if let Ok(n) = stream.read(&mut resp) {
                                    if n > 0 {
                                        banner = resp[..n]
                                            .iter()
                                            .map(|&b| {
                                                if b >= 32 && b < 127 {
                                                    b as char
                                                } else {
                                                    '.'
                                                }
                                            })
                                            .collect();
                                    }
                                }
                            }
                        }
                    }
                }
            }

            PortResult {
                port,
                open: true,
                service,
                banner,
                latency_ms: latency,
            }
        }
        Err(_) => PortResult {
            port,
            open: false,
            service,
            banner: String::new(),
            latency_ms: 0.0,
        },
    }
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => out.push('.'),
            c => out.push(c),
        }
    }
    out
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut config = ScanConfig {
        host: String::new(),
        port_start: 1,
        port_end: 1024,
        threads: 256,
        timeout_ms: 1000,
        json_output: false,
        grab_banner: false,
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--host" => {
                if i + 1 < args.len() {
                    config.host = args[i + 1].clone();
                    i += 1;
                }
            }
            "--ports" => {
                if i + 1 < args.len() {
                    let parts: Vec<&str> = args[i + 1].split('-').collect();
                    if parts.len() == 2 {
                        config.port_start = parts[0].parse().unwrap_or(1);
                        config.port_end = parts[1].parse().unwrap_or(1024);
                    }
                    i += 1;
                }
            }
            "--threads" => {
                if i + 1 < args.len() {
                    config.threads = args[i + 1].parse().unwrap_or(256);
                    i += 1;
                }
            }
            "--timeout" => {
                if i + 1 < args.len() {
                    config.timeout_ms = args[i + 1].parse().unwrap_or(1000);
                    i += 1;
                }
            }
            "--json" => config.json_output = true,
            "--banner" => config.grab_banner = true,
            _ => {}
        }
        i += 1;
    }

    if config.host.is_empty() {
        eprintln!(
            "Usage: {} --host <target> [--ports 1-65535] [--threads 256] [--timeout 1000] [--json] [--banner]",
            args[0]
        );
        std::process::exit(1);
    }

    let total_ports = (config.port_end as u32) - (config.port_start as u32) + 1;
    let results: Arc<Mutex<Vec<PortResult>>> = Arc::new(Mutex::new(Vec::new()));
    let timeout = Duration::from_millis(config.timeout_ms);

    if !config.json_output {
        eprintln!(
            "Scanning {} ports {}-{} with {} threads (timeout {}ms)",
            config.host, config.port_start, config.port_end, config.threads, config.timeout_ms
        );
    }

    let start = Instant::now();

    // Partition ports into chunks for threads
    let ports_per_thread = (total_ports as usize + config.threads - 1) / config.threads;
    let mut handles = Vec::new();

    let mut current = config.port_start;
    while current <= config.port_end {
        let chunk_end = std::cmp::min(
            current as u32 + ports_per_thread as u32 - 1,
            config.port_end as u32,
        ) as u16;
        let host = config.host.clone();
        let results_clone = Arc::clone(&results);
        let grab_banner = config.grab_banner;
        let chunk_start = current;

        let handle = thread::spawn(move || {
            let mut local_results = Vec::new();
            for port in chunk_start..=chunk_end {
                let result = scan_port(&host, port, timeout, grab_banner);
                if result.open {
                    local_results.push(result);
                }
            }
            let mut global = results_clone.lock().unwrap();
            global.extend(local_results);
        });
        handles.push(handle);

        current = if chunk_end == u16::MAX {
            break;
        } else {
            chunk_end + 1
        };
    }

    for handle in handles {
        let _ = handle.join();
    }

    let elapsed = start.elapsed();
    let results = results.lock().unwrap();
    let mut sorted_results: Vec<_> = results.iter().cloned().collect();
    sorted_results.sort_by_key(|r| r.port);

    if config.json_output {
        print!("{{\"host\":\"{}\",\"open_ports\":[", escape_json(&config.host));
        for (idx, r) in sorted_results.iter().enumerate() {
            if idx > 0 {
                print!(",");
            }
            print!(
                "{{\"port\":{},\"service\":\"{}\",\"latency_ms\":{:.1}",
                r.port, r.service, r.latency_ms
            );
            if !r.banner.is_empty() {
                print!(",\"banner\":\"{}\"", escape_json(&r.banner));
            }
            print!("}}");
        }
        println!(
            "],\"total_scanned\":{},\"elapsed_ms\":{:.0}}}",
            total_ports,
            elapsed.as_secs_f64() * 1000.0
        );
    } else {
        println!("Scan results for {}:", config.host);
        println!("{:<8} {:<6} {:<15} {:<12} {}", "PORT", "STATE", "SERVICE", "LATENCY", "BANNER");
        for r in &sorted_results {
            println!(
                "{:<8} {:<6} {:<15} {:<12.1}ms {}",
                r.port, "open", r.service, r.latency_ms, r.banner
            );
        }
        println!(
            "\n{} ports open out of {} scanned in {:.1}ms",
            sorted_results.len(),
            total_ports,
            elapsed.as_secs_f64() * 1000.0
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_lookup() {
        assert_eq!(get_service(22), "ssh");
        assert_eq!(get_service(80), "http");
        assert_eq!(get_service(443), "https");
        assert_eq!(get_service(3306), "mysql");
        assert_eq!(get_service(12345), "unknown");
    }

    #[test]
    fn test_json_escape() {
        assert_eq!(escape_json("hello"), "hello");
        assert_eq!(escape_json(r#"he"llo"#), r#"he\"llo"#);
        assert_eq!(escape_json("line\nnew"), "line\\nnew");
    }

    #[test]
    fn test_scan_closed_port() {
        let result = scan_port("127.0.0.1", 1, Duration::from_millis(100), false);
        assert!(!result.open);
        assert_eq!(result.port, 1);
    }
}
