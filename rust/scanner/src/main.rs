// RecurSec Rust Port Scanner — Async TCP port scanner with service detection.
//
// Uses threading for concurrent scanning with configurable concurrency.
// Outputs structured JSON for agent consumption.
//
// Features:
// - Concurrent scanning with thread pool
// - Configurable timeout per connection
// - Service fingerprinting via banner grab
// - Top ports mode (scans most common ports first)
// - JSON output for agent integration
// - Rate limiting support

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
struct ScanResult {
    host: String,
    ip: String,
    ports_scanned: u32,
    open_ports: Vec<PortInfo>,
    closed_ports: u32,
    filtered_ports: u32,
    scan_time_s: f64,
}

#[derive(Debug, Clone, Serialize)]
struct PortInfo {
    port: u16,
    state: String,
    service: String,
    banner: String,
    version: String,
}

// Top 100 most common ports
const TOP_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 161, 389, 443, 445, 465, 514, 587, 636, 993,
    995, 1080, 1433, 1521, 1723, 1883, 2049, 2181, 2375, 3306,
    3389, 3690, 4369, 4443, 5000, 5432, 5672, 5900, 5984, 6379,
    6443, 6660, 6667, 7001, 8000, 8008, 8080, 8081, 8443, 8888,
    9090, 9092, 9200, 9300, 9418, 10000, 11211, 15672, 27017, 27018,
    28017, 50000, 50070,
];

fn get_service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp", 22 => "ssh", 23 => "telnet", 25 => "smtp",
        53 => "dns", 80 => "http", 110 => "pop3", 111 => "rpcbind",
        135 => "msrpc", 139 => "netbios-ssn", 143 => "imap",
        161 => "snmp", 389 => "ldap", 443 => "https", 445 => "smb",
        465 => "smtps", 514 => "syslog", 587 => "submission",
        636 => "ldaps", 993 => "imaps", 995 => "pop3s",
        1080 => "socks", 1433 => "mssql", 1521 => "oracle",
        1723 => "pptp", 1883 => "mqtt", 2049 => "nfs",
        2181 => "zookeeper", 2375 => "docker", 3306 => "mysql",
        3389 => "rdp", 5000 => "upnp", 5432 => "postgresql",
        5672 => "amqp", 5900 => "vnc", 5984 => "couchdb",
        6379 => "redis", 6443 => "kubernetes",
        6660 | 6667 => "irc", 7001 => "weblogic",
        8000 | 8008 | 8080 | 8081 => "http-alt",
        8443 => "https-alt", 8888 => "http-alt",
        9090 => "prometheus", 9092 => "kafka",
        9200 | 9300 => "elasticsearch",
        9418 => "git", 11211 => "memcached",
        15672 => "rabbitmq-mgmt", 27017 | 27018 => "mongodb",
        50000 => "jenkins",
        _ => "unknown",
    }
}

fn identify_service_from_banner(banner: &str) -> (&str, &str) {
    let lower = banner.to_lowercase();

    if lower.contains("openssh") || lower.contains("ssh-") {
        let version = extract_version(banner, "OpenSSH");
        return ("ssh", version);
    }
    if lower.contains("apache") {
        let version = extract_version(banner, "Apache");
        return ("http", version);
    }
    if lower.contains("nginx") {
        let version = extract_version(banner, "nginx");
        return ("http", version);
    }
    if lower.contains("mysql") || lower.contains("mariadb") {
        return ("mysql", "");
    }
    if lower.contains("postgresql") {
        return ("postgresql", "");
    }
    if lower.contains("redis") {
        return ("redis", "");
    }
    if lower.contains("ftp") || lower.contains("vsftpd") || lower.contains("proftpd") {
        return ("ftp", "");
    }
    if lower.contains("smtp") || lower.contains("postfix") || lower.contains("exim") {
        return ("smtp", "");
    }
    if lower.contains("imap") || lower.contains("dovecot") {
        return ("imap", "");
    }
    if lower.contains("microsoft") || lower.contains("windows") {
        return ("windows-service", "");
    }
    if lower.starts_with("http/") || lower.contains("http/1") {
        return ("http", "");
    }
    ("unknown", "")
}

fn extract_version<'a>(banner: &'a str, _prefix: &str) -> &'a str {
    // Return first few chars after identifying the service
    let trimmed = banner.trim();
    if trimmed.len() > 80 { &trimmed[..80] } else { trimmed }
}

fn scan_port(ip: &str, port: u16, timeout_ms: u64, grab_banner: bool) -> Option<PortInfo> {
    let addr_str = format!("{}:{}", ip, port);
    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return None,
    };

    let timeout = Duration::from_millis(timeout_ms);

    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(mut stream) => {
            let mut info = PortInfo {
                port,
                state: "open".to_string(),
                service: get_service_name(port).to_string(),
                banner: String::new(),
                version: String::new(),
            };

            if grab_banner {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(1500)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));

                // Send probe for HTTP ports
                if matches!(port, 80 | 443 | 8000 | 8008 | 8080 | 8081 | 8443 | 8888) {
                    let _ = stream.write_all(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n");
                } else {
                    // Generic probe
                    let _ = stream.write_all(b"\r\n");
                }

                let mut buf = [0u8; 2048];
                match stream.read(&mut buf) {
                    Ok(n) if n > 0 => {
                        let banner_raw = String::from_utf8_lossy(&buf[..n]);
                        // Clean non-printable characters
                        let banner: String = banner_raw.chars().map(|c| {
                            if c.is_ascii_graphic() || c == ' ' || c == '\n' || c == '\r' || c == '\t' {
                                c
                            } else {
                                '.'
                            }
                        }).collect();

                        let (detected_service, detected_version) = identify_service_from_banner(&banner);
                        if detected_service != "unknown" {
                            info.service = detected_service.to_string();
                        }
                        if !detected_version.is_empty() {
                            info.version = detected_version.to_string();
                        }
                        // Truncate banner
                        info.banner = if banner.len() > 200 { banner[..200].to_string() } else { banner };
                    }
                    _ => {}
                }
            }

            Some(info)
        }
        Err(_) => None,
    }
}

fn resolve_host(host: &str) -> Result<String, String> {
    let addr_str = format!("{}:0", host);
    match addr_str.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                Ok(addr.ip().to_string())
            } else {
                Err(format!("Could not resolve {}", host))
            }
        }
        Err(e) => Err(format!("DNS resolution failed for {}: {}", host, e)),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("RecurSec Scanner — Async TCP port scanner");
        eprintln!();
        eprintln!("Usage: scanner <host> [options]");
        eprintln!("Options:");
        eprintln!("  -p <ports>      Port range (e.g., 1-1024, 80,443,8080)");
        eprintln!("  --top           Scan top 63 common ports");
        eprintln!("  -t <ms>         Timeout per port in ms (default: 2000)");
        eprintln!("  -c <n>          Concurrency / threads (default: 100)");
        eprintln!("  --banner        Enable banner grabbing");
        eprintln!("  --json          JSON output (default)");
        eprintln!("  --text          Human-readable text output");
        std::process::exit(1);
    }

    let host = &args[1];
    let mut ports: Vec<u16> = Vec::new();
    let mut timeout_ms: u64 = 2000;
    let mut concurrency: usize = 100;
    let mut grab_banner = false;
    let mut json_output = true;
    let mut top_ports = false;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "-p" => {
                i += 1;
                if i < args.len() {
                    ports = parse_ports(&args[i]);
                }
            }
            "--top" => top_ports = true,
            "-t" => {
                i += 1;
                if i < args.len() {
                    timeout_ms = args[i].parse().unwrap_or(2000);
                }
            }
            "-c" => {
                i += 1;
                if i < args.len() {
                    concurrency = args[i].parse().unwrap_or(100);
                }
            }
            "--banner" => grab_banner = true,
            "--json" => json_output = true,
            "--text" => json_output = false,
            _ => {}
        }
        i += 1;
    }

    if ports.is_empty() && !top_ports {
        // Default: top ports
        top_ports = true;
    }

    if top_ports {
        ports = TOP_PORTS.to_vec();
    }

    // Resolve host
    let ip = match resolve_host(host) {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    let start = Instant::now();
    let total_ports = ports.len() as u32;

    // Scan using thread pool
    let open_ports: Arc<Mutex<Vec<PortInfo>>> = Arc::new(Mutex::new(Vec::new()));
    let chunks: Vec<Vec<u16>> = ports.chunks(concurrency).map(|c| c.to_vec()).collect();

    for chunk in &chunks {
        let mut handles = Vec::new();
        for &port in chunk {
            let ip_clone = ip.clone();
            let open_ports_clone = Arc::clone(&open_ports);
            let handle = thread::spawn(move || {
                if let Some(info) = scan_port(&ip_clone, port, timeout_ms, grab_banner) {
                    let mut ports = open_ports_clone.lock().unwrap();
                    ports.push(info);
                }
            });
            handles.push(handle);
        }
        for handle in handles {
            let _ = handle.join();
        }
    }

    let mut open = open_ports.lock().unwrap().clone();
    open.sort_by_key(|p| p.port);

    let scan_time = start.elapsed().as_secs_f64();
    let open_count = open.len() as u32;

    let result = ScanResult {
        host: host.clone(),
        ip: ip.clone(),
        ports_scanned: total_ports,
        open_ports: open,
        closed_ports: total_ports - open_count,
        filtered_ports: 0,
        scan_time_s: scan_time,
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
    } else {
        println!("Scan {} ({}) — {} ports in {:.2}s", host, ip, total_ports, scan_time);
        println!("Open ports: {}", open_count);
        println!();
        for p in &result.open_ports {
            print!("  {:>5}/tcp  open  {:<15}", p.port, p.service);
            if !p.banner.is_empty() {
                let first_line = p.banner.lines().next().unwrap_or("");
                print!("  {}", if first_line.len() > 60 { &first_line[..60] } else { first_line });
            }
            println!();
        }
    }
}

fn parse_ports(spec: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() == 2 {
                let start: u16 = range[0].parse().unwrap_or(0);
                let end: u16 = range[1].parse().unwrap_or(0);
                if start > 0 && end >= start {
                    for p in start..=end {
                        ports.push(p);
                    }
                }
            }
        } else if let Ok(p) = part.parse::<u16>() {
            if p > 0 {
                ports.push(p);
            }
        }
    }
    ports
}
