//! RecurSec Pattern Engine — high-performance multi-pattern matching.
//!
//! Scans text against thousands of security patterns simultaneously.
//! Used for:
//! 1. Vulnerability signature matching in tool output
//! 2. Secret detection in code (API keys, tokens, credentials)
//! 3. Indicator of Compromise (IoC) matching
//! 4. Technology fingerprinting
//! 5. Log analysis pattern matching
//! 6. False positive filtering

use regex::RegexSet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::time::Instant;

/// A security pattern with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Pattern {
    id: String,
    name: String,
    category: String,
    regex: String,
    severity: String,
    description: String,
    false_positive_hint: String,
}

/// A match found in the input.
#[derive(Debug, Serialize, Deserialize)]
struct Match {
    pattern_id: String,
    pattern_name: String,
    category: String,
    severity: String,
    line_number: usize,
    line_content: String,
    column: usize,
}

/// Result of scanning text.
#[derive(Debug, Serialize, Deserialize)]
struct ScanResult {
    matches: Vec<Match>,
    lines_scanned: usize,
    patterns_checked: usize,
    duration_ms: u64,
    stats: HashMap<String, usize>,
}

/// Built-in security patterns for secret detection.
fn builtin_secret_patterns() -> Vec<Pattern> {
    vec![
        Pattern {
            id: "SEC-001".into(), name: "AWS Access Key".into(),
            category: "secrets".into(), regex: r"(?i)AKIA[0-9A-Z]{16}".into(),
            severity: "critical".into(), description: "AWS access key ID".into(),
            false_positive_hint: "Check if in example/test code".into(),
        },
        Pattern {
            id: "SEC-002".into(), name: "AWS Secret Key".into(),
            category: "secrets".into(), regex: r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*[A-Za-z0-9/+=]{40}".into(),
            severity: "critical".into(), description: "AWS secret access key".into(),
            false_positive_hint: "".into(),
        },
        Pattern {
            id: "SEC-003".into(), name: "GitHub Token".into(),
            category: "secrets".into(), regex: r"gh[pousr]_[A-Za-z0-9_]{36,255}".into(),
            severity: "critical".into(), description: "GitHub personal access token".into(),
            false_positive_hint: "".into(),
        },
        Pattern {
            id: "SEC-004".into(), name: "Generic API Key".into(),
            category: "secrets".into(), regex: r#"(?i)(api[_\-]?key|apikey)\s*[=:]\s*["']?[A-Za-z0-9\-_]{20,}"#.into(),
            severity: "high".into(), description: "Generic API key pattern".into(),
            false_positive_hint: "May match config templates".into(),
        },
        Pattern {
            id: "SEC-005".into(), name: "Private Key".into(),
            category: "secrets".into(), regex: r"-----BEGIN\s+(RSA|EC|DSA|OPENSSH)?\s*PRIVATE KEY-----".into(),
            severity: "critical".into(), description: "Private key in PEM format".into(),
            false_positive_hint: "".into(),
        },
        Pattern {
            id: "SEC-006".into(), name: "JWT Token".into(),
            category: "secrets".into(), regex: r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}".into(),
            severity: "high".into(), description: "JSON Web Token".into(),
            false_positive_hint: "Check if expired/test token".into(),
        },
        Pattern {
            id: "SEC-007".into(), name: "Slack Token".into(),
            category: "secrets".into(), regex: r"xox[baprs]-[0-9]{10,}-[A-Za-z0-9\-]{10,}".into(),
            severity: "critical".into(), description: "Slack API token".into(),
            false_positive_hint: "".into(),
        },
        Pattern {
            id: "SEC-008".into(), name: "Google API Key".into(),
            category: "secrets".into(), regex: r"AIza[0-9A-Za-z\-_]{35}".into(),
            severity: "high".into(), description: "Google API key".into(),
            false_positive_hint: "Check if restricted".into(),
        },
        Pattern {
            id: "SEC-009".into(), name: "Password in URL".into(),
            category: "secrets".into(), regex: r"[a-zA-Z]+://[^/\s:]+:[^/\s:]+@[^/\s]+".into(),
            severity: "critical".into(), description: "Credentials embedded in URL".into(),
            false_positive_hint: "".into(),
        },
        Pattern {
            id: "SEC-010".into(), name: "Hardcoded Password".into(),
            category: "secrets".into(), regex: r#"(?i)(password|passwd|pwd)\s*[=:]\s*["'][^"']{8,}["']"#.into(),
            severity: "high".into(), description: "Hardcoded password".into(),
            false_positive_hint: "May match password validation".into(),
        },
    ]
}

/// Built-in patterns for vulnerability detection in tool output.
fn builtin_vuln_patterns() -> Vec<Pattern> {
    vec![
        Pattern {
            id: "VULN-001".into(), name: "SQL Injection Indicator".into(),
            category: "vulnerability".into(), regex: r"(?i)(sql\s*injection|sqli|union\s+select|or\s+1\s*=\s*1|syntax\s+error.*sql)".into(),
            severity: "critical".into(), description: "SQL injection vulnerability indicator".into(),
            false_positive_hint: "Verify with manual testing".into(),
        },
        Pattern {
            id: "VULN-002".into(), name: "XSS Indicator".into(),
            category: "vulnerability".into(), regex: r"(?i)(cross[- ]site\s*scripting|xss|<script>|javascript:|on(error|load|click)\s*=)".into(),
            severity: "high".into(), description: "Cross-site scripting indicator".into(),
            false_positive_hint: "Check if reflected or stored".into(),
        },
        Pattern {
            id: "VULN-003".into(), name: "Command Injection".into(),
            category: "vulnerability".into(), regex: r"(?i)(command\s*injection|os\s*command|shell\s*injection|;.*cat\s+/etc/passwd)".into(),
            severity: "critical".into(), description: "OS command injection".into(),
            false_positive_hint: "".into(),
        },
        Pattern {
            id: "VULN-004".into(), name: "Path Traversal".into(),
            category: "vulnerability".into(), regex: r"(?i)(path\s*traversal|directory\s*traversal|\.\.\/|\.\.\\|/etc/passwd|/etc/shadow)".into(),
            severity: "high".into(), description: "Path/directory traversal".into(),
            false_positive_hint: "".into(),
        },
        Pattern {
            id: "VULN-005".into(), name: "SSRF Indicator".into(),
            category: "vulnerability".into(), regex: r"(?i)(ssrf|server[- ]side\s*request|169\.254\.169\.254|metadata\.google|100\.100\.100\.200)".into(),
            severity: "critical".into(), description: "Server-side request forgery".into(),
            false_positive_hint: "".into(),
        },
        Pattern {
            id: "VULN-006".into(), name: "Open Redirect".into(),
            category: "vulnerability".into(), regex: r"(?i)(open\s*redirect|url\s*redirect|redirect[_\-]?to\s*=\s*http)".into(),
            severity: "medium".into(), description: "Open redirect vulnerability".into(),
            false_positive_hint: "Check if within same domain".into(),
        },
        Pattern {
            id: "VULN-007".into(), name: "Information Disclosure".into(),
            category: "vulnerability".into(), regex: r"(?i)(information\s*disclosure|sensitive\s*data|stack\s*trace|debug\s*mode|phpinfo)".into(),
            severity: "medium".into(), description: "Information disclosure".into(),
            false_positive_hint: "Check sensitivity level".into(),
        },
        Pattern {
            id: "VULN-008".into(), name: "Authentication Bypass".into(),
            category: "vulnerability".into(), regex: r"(?i)(auth(entication)?\s*bypass|access\s*control|broken\s*auth|privilege\s*escalation)".into(),
            severity: "critical".into(), description: "Authentication/authorization bypass".into(),
            false_positive_hint: "".into(),
        },
        Pattern {
            id: "VULN-009".into(), name: "Deserialization".into(),
            category: "vulnerability".into(), regex: r"(?i)(deserialization|insecure\s*unserialize|pickle\s*load|readobject|xmldecoder)".into(),
            severity: "critical".into(), description: "Insecure deserialization".into(),
            false_positive_hint: "".into(),
        },
        Pattern {
            id: "VULN-010".into(), name: "Weak Crypto".into(),
            category: "vulnerability".into(), regex: r"(?i)(md5|sha1|des|rc4|ecb\s*mode|weak\s*(cipher|crypto|hash|algorithm))".into(),
            severity: "medium".into(), description: "Weak cryptographic algorithm".into(),
            false_positive_hint: "Check if used for security".into(),
        },
    ]
}

/// Built-in IoC patterns.
fn builtin_ioc_patterns() -> Vec<Pattern> {
    vec![
        Pattern {
            id: "IOC-001".into(), name: "IPv4 Address".into(),
            category: "ioc".into(), regex: r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b".into(),
            severity: "info".into(), description: "IPv4 address".into(),
            false_positive_hint: "Check if internal/private".into(),
        },
        Pattern {
            id: "IOC-002".into(), name: "Email Address".into(),
            category: "ioc".into(), regex: r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b".into(),
            severity: "info".into(), description: "Email address".into(),
            false_positive_hint: "".into(),
        },
        Pattern {
            id: "IOC-003".into(), name: "URL".into(),
            category: "ioc".into(), regex: r#"https?://[^\s<>"']+"#.into(),
            severity: "info".into(), description: "URL/URI".into(),
            false_positive_hint: "".into(),
        },
        Pattern {
            id: "IOC-004".into(), name: "MD5 Hash".into(),
            category: "ioc".into(), regex: r"\b[a-fA-F0-9]{32}\b".into(),
            severity: "info".into(), description: "MD5 hash".into(),
            false_positive_hint: "May match other hex strings".into(),
        },
        Pattern {
            id: "IOC-005".into(), name: "SHA256 Hash".into(),
            category: "ioc".into(), regex: r"\b[a-fA-F0-9]{64}\b".into(),
            severity: "info".into(), description: "SHA256 hash".into(),
            false_positive_hint: "".into(),
        },
    ]
}

/// Pattern engine that compiles and matches patterns.
struct PatternEngine {
    patterns: Vec<Pattern>,
    regex_set: RegexSet,
}

impl PatternEngine {
    fn new(patterns: Vec<Pattern>) -> Result<Self, regex::Error> {
        let regexes: Vec<&str> = patterns.iter().map(|p| p.regex.as_str()).collect();
        let regex_set = RegexSet::new(&regexes)?;
        Ok(PatternEngine { patterns, regex_set })
    }

    fn scan_line(&self, line: &str, line_number: usize) -> Vec<Match> {
        let matching_indices: Vec<usize> = self.regex_set.matches(line).into_iter().collect();
        matching_indices
            .into_iter()
            .map(|idx| {
                let pattern = &self.patterns[idx];
                Match {
                    pattern_id: pattern.id.clone(),
                    pattern_name: pattern.name.clone(),
                    category: pattern.category.clone(),
                    severity: pattern.severity.clone(),
                    line_number,
                    line_content: if line.len() > 200 {
                        format!("{}...", &line[..200])
                    } else {
                        line.to_string()
                    },
                    column: 0,
                }
            })
            .collect()
    }

    fn scan_text(&self, text: &str) -> ScanResult {
        let start = Instant::now();
        let mut all_matches = Vec::new();
        let mut stats: HashMap<String, usize> = HashMap::new();
        let mut lines_scanned = 0;

        for (i, line) in text.lines().enumerate() {
            lines_scanned += 1;
            let matches = self.scan_line(line, i + 1);
            for m in &matches {
                *stats.entry(m.category.clone()).or_insert(0) += 1;
                *stats.entry(m.severity.clone()).or_insert(0) += 1;
            }
            all_matches.extend(matches);
        }

        ScanResult {
            matches: all_matches,
            lines_scanned,
            patterns_checked: self.patterns.len(),
            duration_ms: start.elapsed().as_millis() as u64,
            stats,
        }
    }
}

#[derive(Deserialize)]
struct ScanRequest {
    text: Option<String>,
    categories: Option<Vec<String>>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Collect all built-in patterns
    let mut all_patterns = Vec::new();
    all_patterns.extend(builtin_secret_patterns());
    all_patterns.extend(builtin_vuln_patterns());
    all_patterns.extend(builtin_ioc_patterns());

    // Filter by category if requested
    let categories: Vec<String> = args.iter()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .cloned()
        .collect();

    if !categories.is_empty() {
        all_patterns.retain(|p| categories.contains(&p.category));
    }

    let engine = match PatternEngine::new(all_patterns) {
        Ok(e) => e,
        Err(err) => {
            eprintln!("Failed to compile patterns: {}", err);
            std::process::exit(1);
        }
    };

    // Check for --json mode (read JSON requests from stdin)
    if args.iter().any(|a| a == "--json") {
        let stdin = io::stdin();
        let stdout = io::stdout();
        let mut out = stdout.lock();
        for line in stdin.lock().lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            if let Ok(req) = serde_json::from_str::<ScanRequest>(&line) {
                if let Some(text) = req.text {
                    let result = engine.scan_text(&text);
                    if let Ok(json) = serde_json::to_string(&result) {
                        let _ = writeln!(out, "{}", json);
                    }
                }
            }
        }
        return;
    }

    // Default: read text from stdin, scan, output results
    let mut input = String::new();
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        match line {
            Ok(l) => {
                input.push_str(&l);
                input.push('\n');
            }
            Err(_) => break,
        }
    }

    let result = engine.scan_text(&input);

    if args.iter().any(|a| a == "--summary") {
        println!("Lines scanned: {}", result.lines_scanned);
        println!("Patterns checked: {}", result.patterns_checked);
        println!("Matches found: {}", result.matches.len());
        println!("Duration: {}ms", result.duration_ms);
        for (key, count) in &result.stats {
            println!("  {}: {}", key, count);
        }
    } else {
        match serde_json::to_string_pretty(&result) {
            Ok(json) => println!("{}", json),
            Err(err) => eprintln!("Failed to serialize: {}", err),
        }
    }
}
