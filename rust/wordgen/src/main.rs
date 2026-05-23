// RecurSec Wordlist Generator — Fast password and wordlist generation.
//
// Modes:
// - charset: Generate all combinations of charset up to given length
// - mutate: Apply mutations to input wordlist (l33t, case, append numbers)
// - combine: Combine multiple wordlists
// - pattern: Generate from pattern specification
// - stats: Analyze wordlist statistics
//
// Usage:
//   wordgen charset -c abc123 -min 1 -max 4
//   wordgen mutate -i wordlist.txt
//   wordgen pattern -p "?l?l?l?d?d?d"
//   wordgen stats -i wordlist.txt

use std::collections::HashMap;
use std::io::{self, BufRead, Write, BufWriter};

use serde::Serialize;

#[derive(Debug, Serialize)]
struct WordlistStats {
    total_words: usize,
    unique_words: usize,
    min_length: usize,
    max_length: usize,
    avg_length: f64,
    charset_size: usize,
    contains_upper: bool,
    contains_lower: bool,
    contains_digits: bool,
    contains_special: bool,
    length_distribution: HashMap<usize, usize>,
    top_passwords: Vec<(String, usize)>,
}

// Leetspeak substitutions
fn leet_substitutions() -> Vec<(char, Vec<char>)> {
    vec![
        ('a', vec!['@', '4']),
        ('e', vec!['3']),
        ('i', vec!['1', '!']),
        ('o', vec!['0']),
        ('s', vec!['$', '5']),
        ('t', vec!['7']),
        ('l', vec!['1']),
        ('b', vec!['8']),
        ('g', vec!['9']),
    ]
}

// Common number suffixes for mutations
const NUMBER_SUFFIXES: &[&str] = &[
    "1", "12", "123", "1234", "2024", "2025", "2026",
    "!", "!!", "!@#", "@", "#", "$",
    "01", "69", "99", "007", "666", "777", "000",
];

// Common password suffixes
const COMMON_SUFFIXES: &[&str] = &[
    "!", "@", "#", "$", "%",
    "1", "2", "3", "12", "123", "1234", "12345",
    "!", "!!", "!!!", "@!", "#1",
    "2024", "2025", "2026",
];

fn generate_charset(charset: &str, min_len: usize, max_len: usize) {
    let chars: Vec<char> = charset.chars().collect();
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());

    for length in min_len..=max_len {
        generate_combinations(&chars, length, &mut String::new(), &mut writer);
    }
}

fn generate_combinations(chars: &[char], remaining: usize, current: &mut String, writer: &mut BufWriter<io::StdoutLock>) {
    if remaining == 0 {
        let _ = writeln!(writer, "{}", current);
        return;
    }
    for &c in chars {
        current.push(c);
        generate_combinations(chars, remaining - 1, current, writer);
        current.pop();
    }
}

fn mutate_wordlist(input: &str) {
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());

    let file = std::fs::File::open(input).expect("Cannot open input file");
    let reader = io::BufReader::new(file);

    let leet = leet_substitutions();

    for line in reader.lines() {
        let word = match line {
            Ok(w) => w.trim().to_string(),
            Err(_) => continue,
        };

        if word.is_empty() {
            continue;
        }

        // Original
        let _ = writeln!(writer, "{}", word);

        // Uppercase first letter
        if let Some(first) = word.chars().next() {
            let capitalized: String = first.to_uppercase().chain(word.chars().skip(1)).collect();
            if capitalized != word {
                let _ = writeln!(writer, "{}", capitalized);
            }
        }

        // All uppercase
        let upper = word.to_uppercase();
        if upper != word {
            let _ = writeln!(writer, "{}", upper);
        }

        // All lowercase
        let lower = word.to_lowercase();
        if lower != word {
            let _ = writeln!(writer, "{}", lower);
        }

        // Toggle case (first letter lower, rest upper)
        if word.len() > 1 {
            let toggled: String = word.chars().enumerate().map(|(i, c)| {
                if i == 0 { c.to_lowercase().next().unwrap_or(c) }
                else { c.to_uppercase().next().unwrap_or(c) }
            }).collect();
            if toggled != word {
                let _ = writeln!(writer, "{}", toggled);
            }
        }

        // Append numbers/symbols
        for suffix in NUMBER_SUFFIXES {
            let _ = writeln!(writer, "{}{}", word, suffix);
        }

        // Prepend numbers
        for prefix in &["1", "123", "!"] {
            let _ = writeln!(writer, "{}{}", prefix, word);
        }

        // Simple l33t speak
        let lower_word = word.to_lowercase();
        let mut leetified = lower_word.clone();
        for (from, to_chars) in &leet {
            if lower_word.contains(*from) {
                for to_char in to_chars {
                    leetified = lower_word.replace(*from, &to_char.to_string());
                    let _ = writeln!(writer, "{}", leetified);
                }
            }
        }

        // Reverse
        let reversed: String = word.chars().rev().collect();
        if reversed != word {
            let _ = writeln!(writer, "{}", reversed);
        }

        // Double the word
        let _ = writeln!(writer, "{}{}", word, word);

        // Word + common suffixes with capitalized first
        if let Some(first) = word.chars().next() {
            let cap: String = first.to_uppercase().chain(word.chars().skip(1)).collect();
            for suffix in COMMON_SUFFIXES {
                let _ = writeln!(writer, "{}{}", cap, suffix);
            }
        }
    }
}

fn generate_pattern(pattern: &str) {
    // Pattern chars:
    // ?l = lowercase letter
    // ?u = uppercase letter
    // ?d = digit
    // ?s = special char
    // ?a = any printable
    // literal chars are used as-is

    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());

    let mut charsets: Vec<Vec<char>> = Vec::new();
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '?' && i + 1 < chars.len() {
            let charset = match chars[i + 1] {
                'l' => ('a'..='z').collect::<Vec<char>>(),
                'u' => ('A'..='Z').collect::<Vec<char>>(),
                'd' => ('0'..='9').collect::<Vec<char>>(),
                's' => "!@#$%^&*()-_=+[]{}|;:',.<>?/~`".chars().collect::<Vec<char>>(),
                'a' => {
                    let mut all: Vec<char> = ('a'..='z').collect();
                    all.extend('A'..='Z');
                    all.extend('0'..='9');
                    all.extend("!@#$%^&*()".chars());
                    all
                }
                _ => vec![chars[i + 1]],
            };
            charsets.push(charset);
            i += 2;
        } else {
            charsets.push(vec![chars[i]]);
            i += 1;
        }
    }

    // Estimate total combinations
    let total: u64 = charsets.iter().map(|cs| cs.len() as u64).product();
    if total > 100_000_000 {
        eprintln!("Warning: pattern generates {} combinations (>100M), this may take a while", total);
    }

    generate_pattern_recursive(&charsets, 0, &mut String::new(), &mut writer);
}

fn generate_pattern_recursive(
    charsets: &[Vec<char>],
    pos: usize,
    current: &mut String,
    writer: &mut BufWriter<io::StdoutLock>,
) {
    if pos == charsets.len() {
        let _ = writeln!(writer, "{}", current);
        return;
    }
    for &c in &charsets[pos] {
        current.push(c);
        generate_pattern_recursive(charsets, pos + 1, current, writer);
        current.pop();
    }
}

fn analyze_wordlist(input: &str) {
    let file = std::fs::File::open(input).expect("Cannot open input file");
    let reader = io::BufReader::new(file);

    let mut total = 0usize;
    let mut lengths: HashMap<usize, usize> = HashMap::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut min_len = usize::MAX;
    let mut max_len = 0usize;
    let mut total_len = 0usize;
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_special = false;
    let mut charset: std::collections::HashSet<char> = std::collections::HashSet::new();

    for line in reader.lines() {
        let word = match line {
            Ok(w) => w.trim().to_string(),
            Err(_) => continue,
        };
        if word.is_empty() {
            continue;
        }

        total += 1;
        let len = word.len();
        total_len += len;
        if len < min_len { min_len = len; }
        if len > max_len { max_len = len; }
        *lengths.entry(len).or_insert(0) += 1;
        *seen.entry(word.clone()).or_insert(0) += 1;

        for c in word.chars() {
            charset.insert(c);
            if c.is_uppercase() { has_upper = true; }
            if c.is_lowercase() { has_lower = true; }
            if c.is_ascii_digit() { has_digit = true; }
            if !c.is_alphanumeric() { has_special = true; }
        }
    }

    // Top passwords
    let mut password_counts: Vec<(String, usize)> = seen.into_iter().collect();
    password_counts.sort_by(|a, b| b.1.cmp(&a.1));
    password_counts.truncate(20);

    let stats = WordlistStats {
        total_words: total,
        unique_words: password_counts.len().max(total), // approximate
        min_length: if min_len == usize::MAX { 0 } else { min_len },
        max_length: max_len,
        avg_length: if total > 0 { total_len as f64 / total as f64 } else { 0.0 },
        charset_size: charset.len(),
        contains_upper: has_upper,
        contains_lower: has_lower,
        contains_digits: has_digit,
        contains_special: has_special,
        length_distribution: lengths,
        top_passwords: password_counts,
    };

    println!("{}", serde_json::to_string_pretty(&stats).unwrap());
}

fn combine_wordlists(files: &[String]) {
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    let mut seen = std::collections::HashSet::new();

    for filepath in files {
        let file = match std::fs::File::open(filepath) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Cannot open {}: {}", filepath, e);
                continue;
            }
        };
        let reader = io::BufReader::new(file);
        for line in reader.lines() {
            if let Ok(word) = line {
                let trimmed = word.trim().to_string();
                if !trimmed.is_empty() && seen.insert(trimmed.clone()) {
                    let _ = writeln!(writer, "{}", trimmed);
                }
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("RecurSec Wordlist Generator");
        eprintln!();
        eprintln!("Usage:");
        eprintln!("  wordgen charset -c <chars> -min <n> -max <n>");
        eprintln!("  wordgen mutate -i <wordlist>");
        eprintln!("  wordgen pattern -p <pattern>");
        eprintln!("  wordgen stats -i <wordlist>");
        eprintln!("  wordgen combine <file1> <file2> ...");
        eprintln!();
        eprintln!("Pattern chars: ?l=lower ?u=upper ?d=digit ?s=special ?a=any");
        std::process::exit(1);
    }

    let mode = &args[1];

    match mode.as_str() {
        "charset" => {
            let mut charset = "abcdefghijklmnopqrstuvwxyz0123456789";
            let mut min_len = 1usize;
            let mut max_len = 4usize;

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "-c" => { i += 1; if i < args.len() { charset = &args[i]; } }
                    "-min" => { i += 1; if i < args.len() { min_len = args[i].parse().unwrap_or(1); } }
                    "-max" => { i += 1; if i < args.len() { max_len = args[i].parse().unwrap_or(4); } }
                    _ => {}
                }
                i += 1;
            }

            generate_charset(charset, min_len, max_len);
        }
        "mutate" => {
            let mut input = "";
            let mut i = 2;
            while i < args.len() {
                if args[i] == "-i" { i += 1; if i < args.len() { input = &args[i]; } }
                i += 1;
            }
            if input.is_empty() {
                eprintln!("Usage: wordgen mutate -i <wordlist>");
                std::process::exit(1);
            }
            mutate_wordlist(input);
        }
        "pattern" => {
            let mut pattern = "";
            let mut i = 2;
            while i < args.len() {
                if args[i] == "-p" { i += 1; if i < args.len() { pattern = &args[i]; } }
                i += 1;
            }
            if pattern.is_empty() {
                eprintln!("Usage: wordgen pattern -p <pattern>");
                std::process::exit(1);
            }
            generate_pattern(pattern);
        }
        "stats" => {
            let mut input = "";
            let mut i = 2;
            while i < args.len() {
                if args[i] == "-i" { i += 1; if i < args.len() { input = &args[i]; } }
                i += 1;
            }
            if input.is_empty() {
                eprintln!("Usage: wordgen stats -i <wordlist>");
                std::process::exit(1);
            }
            analyze_wordlist(input);
        }
        "combine" => {
            let files: Vec<String> = args[2..].to_vec();
            if files.is_empty() {
                eprintln!("Usage: wordgen combine <file1> <file2> ...");
                std::process::exit(1);
            }
            combine_wordlists(&files);
        }
        _ => {
            eprintln!("Unknown mode: {}", mode);
            std::process::exit(1);
        }
    }
}
