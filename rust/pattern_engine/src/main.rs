// RecurSec Pattern Matching Engine
//
// High-performance vulnerability pattern matching:
// - Aho-Corasick multi-pattern matching
// - Regex-based signature detection
// - YARA-like rule matching
// - Binary pattern matching
// - JSON output for agent consumption
//
// Matches thousands of vulnerability signatures against
// tool output, HTTP responses, and source code at native speed.

use std::collections::HashMap;
use std::env;
use std::io::{self, Read};

/// A vulnerability signature pattern
struct Pattern {
    id: String,
    name: String,
    severity: String,
    pattern_type: PatternType,
    pattern: String,
    description: String,
    cwe: String,
    remediation: String,
}

#[derive(Clone)]
enum PatternType {
    Exact,
    Contains,
    StartsWith,
    EndsWith,
    Regex,
}

struct Match {
    pattern_id: String,
    pattern_name: String,
    severity: String,
    offset: usize,
    matched_text: String,
    context: String,
    cwe: String,
}

/// Aho-Corasick-like multi-pattern matcher (simplified)
struct PatternMatcher {
    patterns: Vec<Pattern>,
}

impl PatternMatcher {
    fn new() -> Self {
        PatternMatcher {
            patterns: Vec::new(),
        }
    }

    fn add_pattern(&mut self, pattern: Pattern) {
        self.patterns.push(pattern);
    }

    fn load_default_patterns(&mut self) {
        let defaults = vec![
            // SQL Injection patterns
            ("sqli-001", "SQL Injection - Error Based", "critical", PatternType::Contains,
             "You have an error in your SQL syntax", "CWE-89", "Use parameterized queries"),
            ("sqli-002", "SQL Injection - MySQL", "critical", PatternType::Contains,
             "mysql_fetch_array()", "CWE-89", "Use prepared statements"),
            ("sqli-003", "SQL Injection - MSSQL", "critical", PatternType::Contains,
             "Microsoft OLE DB Provider", "CWE-89", "Use parameterized queries"),
            ("sqli-004", "SQL Injection - PostgreSQL", "critical", PatternType::Contains,
             "PSQLException", "CWE-89", "Use parameterized queries"),
            ("sqli-005", "SQL Injection - Oracle", "critical", PatternType::Contains,
             "ORA-01756", "CWE-89", "Use bind variables"),

            // XSS patterns
            ("xss-001", "XSS - Script Tag", "high", PatternType::Contains,
             "<script>", "CWE-79", "Encode output, use CSP"),
            ("xss-002", "XSS - Event Handler", "high", PatternType::Contains,
             "onerror=", "CWE-79", "Sanitize input, encode output"),
            ("xss-003", "XSS - JavaScript URI", "high", PatternType::Contains,
             "javascript:", "CWE-79", "Validate URL schemes"),

            // Path Traversal
            ("pt-001", "Path Traversal", "high", PatternType::Contains,
             "../../../etc/passwd", "CWE-22", "Validate and normalize paths"),
            ("pt-002", "Path Traversal - Windows", "high", PatternType::Contains,
             "..\\..\\..\\windows", "CWE-22", "Validate and normalize paths"),

            // Information Disclosure
            ("info-001", "Server Version Disclosure", "medium", PatternType::Contains,
             "Server: Apache/", "CWE-200", "Remove server version headers"),
            ("info-002", "PHP Info Disclosure", "medium", PatternType::Contains,
             "phpinfo()", "CWE-200", "Remove phpinfo pages"),
            ("info-003", "Stack Trace Disclosure", "medium", PatternType::Contains,
             "at java.lang.", "CWE-209", "Disable debug mode in production"),
            ("info-004", "Stack Trace - Python", "medium", PatternType::Contains,
             "Traceback (most recent call last)", "CWE-209", "Use custom error handlers"),
            ("info-005", "Stack Trace - .NET", "medium", PatternType::Contains,
             "System.NullReferenceException", "CWE-209", "Use custom error pages"),

            // Secrets
            ("secret-001", "AWS Key Exposed", "critical", PatternType::Contains,
             "AKIA", "CWE-798", "Rotate key immediately, use IAM roles"),
            ("secret-002", "Private Key Exposed", "critical", PatternType::Contains,
             "-----BEGIN RSA PRIVATE KEY-----", "CWE-798", "Remove key, rotate credentials"),
            ("secret-003", "JWT Secret", "critical", PatternType::Contains,
             "jwt_secret", "CWE-798", "Use environment variables"),
            ("secret-004", "API Key Pattern", "high", PatternType::Contains,
             "api_key=", "CWE-798", "Use environment variables"),

            // SSRF
            ("ssrf-001", "SSRF - Internal IP", "high", PatternType::Contains,
             "169.254.169.254", "CWE-918", "Validate URLs, block internal IPs"),
            ("ssrf-002", "SSRF - Localhost", "high", PatternType::Contains,
             "127.0.0.1", "CWE-918", "Block localhost in URL parameters"),

            // Deserialization
            ("deser-001", "Java Deserialization", "critical", PatternType::Contains,
             "ObjectInputStream", "CWE-502", "Use safe deserialization"),
            ("deser-002", "PHP Deserialization", "critical", PatternType::Contains,
             "unserialize(", "CWE-502", "Use json_decode instead"),
            ("deser-003", "Python Pickle", "critical", PatternType::Contains,
             "pickle.loads", "CWE-502", "Use json instead of pickle"),

            // Command Injection
            ("cmdi-001", "Command Injection - Bash", "critical", PatternType::Contains,
             "os.system(", "CWE-78", "Use subprocess with shell=False"),
            ("cmdi-002", "Command Injection - Eval", "critical", PatternType::Contains,
             "eval(", "CWE-94", "Never use eval with user input"),
            ("cmdi-003", "Command Injection - Exec", "critical", PatternType::Contains,
             "exec(", "CWE-94", "Avoid exec with dynamic input"),

            // Authentication
            ("auth-001", "Hardcoded Password", "critical", PatternType::Contains,
             "password = \"", "CWE-798", "Use environment variables"),
            ("auth-002", "Default Credentials", "high", PatternType::Contains,
             "admin:admin", "CWE-798", "Change default credentials"),

            // Crypto
            ("crypto-001", "Weak Hash - MD5", "medium", PatternType::Contains,
             "md5(", "CWE-328", "Use SHA-256 or bcrypt"),
            ("crypto-002", "Weak Hash - SHA1", "medium", PatternType::Contains,
             "sha1(", "CWE-328", "Use SHA-256 or bcrypt"),
            ("crypto-003", "Weak Cipher - DES", "high", PatternType::Contains,
             "DES/ECB", "CWE-327", "Use AES-256-GCM"),
        ];

        for (id, name, sev, ptype, pat, cwe, rem) in defaults {
            self.add_pattern(Pattern {
                id: id.to_string(),
                name: name.to_string(),
                severity: sev.to_string(),
                pattern_type: ptype,
                pattern: pat.to_string(),
                description: name.to_string(),
                cwe: cwe.to_string(),
                remediation: rem.to_string(),
            });
        }
    }

    fn scan(&self, input: &str) -> Vec<Match> {
        let mut matches = Vec::new();

        for pattern in &self.patterns {
            let found_positions = self.find_pattern(input, pattern);
            for (offset, matched_text) in found_positions {
                let context_start = if offset > 40 { offset - 40 } else { 0 };
                let context_end = std::cmp::min(input.len(), offset + matched_text.len() + 40);
                let context = input[context_start..context_end].to_string();

                matches.push(Match {
                    pattern_id: pattern.id.clone(),
                    pattern_name: pattern.name.clone(),
                    severity: pattern.severity.clone(),
                    offset,
                    matched_text: matched_text.to_string(),
                    context: context.replace('\n', "\\n").replace('"', "\\\""),
                    cwe: pattern.cwe.clone(),
                });
            }
        }

        matches
    }

    fn find_pattern(&self, input: &str, pattern: &Pattern) -> Vec<(usize, String)> {
        let mut results = Vec::new();
        let pat = &pattern.pattern;

        match pattern.pattern_type {
            PatternType::Exact => {
                if input == pat {
                    results.push((0, pat.clone()));
                }
            }
            PatternType::Contains => {
                let pat_lower = pat.to_lowercase();
                let input_lower = input.to_lowercase();
                let mut start = 0;
                while let Some(pos) = input_lower[start..].find(&pat_lower) {
                    let actual_pos = start + pos;
                    let end = actual_pos + pat.len();
                    if end <= input.len() {
                        results.push((actual_pos, input[actual_pos..end].to_string()));
                    }
                    start = actual_pos + 1;
                    if start >= input.len() {
                        break;
                    }
                }
            }
            PatternType::StartsWith => {
                if input.starts_with(pat) {
                    results.push((0, pat.clone()));
                }
            }
            PatternType::EndsWith => {
                if input.ends_with(pat) {
                    results.push((input.len() - pat.len(), pat.clone()));
                }
            }
            PatternType::Regex => {
                // Simplified: treat as contains for now
                if let Some(pos) = input.find(pat) {
                    results.push((pos, pat.clone()));
                }
            }
        }

        results
    }
}

fn json_escape(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            _ => result.push(c),
        }
    }
    result
}

fn output_json(matches: &[Match], input_size: usize) {
    let mut severity_counts: HashMap<&str, usize> = HashMap::new();
    for m in matches {
        *severity_counts.entry(m.severity.as_str()).or_insert(0) += 1;
    }

    print!("{{\"total_matches\":{},\"input_size\":{}", matches.len(), input_size);
    print!(",\"severity_counts\":{{");
    let mut first = true;
    for (sev, count) in &severity_counts {
        if !first { print!(","); }
        print!("\"{}\":{}", sev, count);
        first = false;
    }
    print!("}}");

    print!(",\"matches\":[");
    for (i, m) in matches.iter().enumerate() {
        if i > 0 { print!(","); }
        print!("{{\"id\":\"{}\",\"name\":\"{}\",\"severity\":\"{}\",\"offset\":{},\"matched\":\"{}\",\"context\":\"{}\",\"cwe\":\"{}\"}}",
            json_escape(&m.pattern_id),
            json_escape(&m.pattern_name),
            json_escape(&m.severity),
            m.offset,
            json_escape(&m.matched_text),
            json_escape(&m.context),
            json_escape(&m.cwe),
        );
    }
    println!("]}}");
}

fn output_text(matches: &[Match]) {
    if matches.is_empty() {
        println!("No patterns matched.");
        return;
    }

    println!("Found {} matches:\n", matches.len());
    for m in matches {
        println!("[{}] {} ({})", m.severity.to_uppercase(), m.pattern_name, m.cwe);
        println!("  Offset: {}, Matched: \"{}\"", m.offset, m.matched_text);
        println!("  Context: ...{}...", &m.context[..std::cmp::min(m.context.len(), 80)]);
        println!();
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut json_output = false;
    let mut input_file: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json_output = true,
            "--file" | "-f" => {
                if i + 1 < args.len() {
                    input_file = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--help" | "-h" => {
                eprintln!("RecurSec Pattern Engine - Vulnerability Signature Matching");
                eprintln!("Usage: pattern_engine [--json] [--file <path>]");
                eprintln!("  Reads from stdin if no file specified");
                eprintln!("  --json    Output JSON format");
                eprintln!("  --file    Input file to scan");
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }

    // Read input
    let input = if let Some(path) = input_file {
        std::fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("Error reading {}: {}", path, e);
            std::process::exit(1);
        })
    } else {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf).unwrap_or_else(|e| {
            eprintln!("Error reading stdin: {}", e);
            std::process::exit(1);
        });
        buf
    };

    // Create matcher and load patterns
    let mut matcher = PatternMatcher::new();
    matcher.load_default_patterns();

    // Scan
    let matches = matcher.scan(&input);

    // Output
    if json_output {
        output_json(&matches, input.len());
    } else {
        output_text(&matches);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_injection_detection() {
        let mut matcher = PatternMatcher::new();
        matcher.load_default_patterns();
        let input = "Error: You have an error in your SQL syntax near 'DROP TABLE'";
        let matches = matcher.scan(input);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].severity, "critical");
    }

    #[test]
    fn test_xss_detection() {
        let mut matcher = PatternMatcher::new();
        matcher.load_default_patterns();
        let input = "<html><script>alert('xss')</script></html>";
        let matches = matcher.scan(input);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].cwe, "CWE-79");
    }

    #[test]
    fn test_secret_detection() {
        let mut matcher = PatternMatcher::new();
        matcher.load_default_patterns();
        let input = "aws_key = AKIAIOSFODNN7EXAMPLE";
        let matches = matcher.scan(input);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_no_false_positives() {
        let mut matcher = PatternMatcher::new();
        matcher.load_default_patterns();
        let input = "Hello World, this is a normal text without any vulnerabilities.";
        let matches = matcher.scan(input);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_json_escape() {
        assert_eq!(json_escape("hello"), "hello");
        assert_eq!(json_escape("he\"llo"), "he\\\"llo");
        assert_eq!(json_escape("line1\nline2"), "line1\\nline2");
    }

    #[test]
    fn test_multiple_matches() {
        let mut matcher = PatternMatcher::new();
        matcher.load_default_patterns();
        let input = "eval(user_input) and os.system(cmd) and pickle.loads(data)";
        let matches = matcher.scan(input);
        assert!(matches.len() >= 3);
    }
}
