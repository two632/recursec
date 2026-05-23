#!/usr/bin/env bash
# RecurSec Quick Recon Script — Fast initial reconnaissance.
#
# Usage: ./recon.sh <target> [output_dir]
#
# Runs: DNS enumeration, port scanning, web tech fingerprinting,
#       subdomain discovery, and certificate transparency search.
# All output is saved to structured JSON files.

set -euo pipefail

TARGET="${1:-}"
OUTPUT_DIR="${2:-./recon_output}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target> [output_dir]"
    echo "  target: IP, hostname, or domain"
    exit 1
fi

echo "╔══════════════════════════════════════╗"
echo "║    RecurSec Quick Recon              ║"
echo "║    Target: $TARGET"
echo "║    Time:   $(date)"
echo "╚══════════════════════════════════════╝"
echo ""

mkdir -p "$OUTPUT_DIR"

# ── DNS Resolution ─────────────────────────────────────────
echo "[*] Phase 1: DNS Resolution"
if command -v dig &>/dev/null; then
    echo "  Running dig..."
    dig +short A "$TARGET" > "$OUTPUT_DIR/dns_a.txt" 2>/dev/null || true
    dig +short AAAA "$TARGET" > "$OUTPUT_DIR/dns_aaaa.txt" 2>/dev/null || true
    dig +short MX "$TARGET" > "$OUTPUT_DIR/dns_mx.txt" 2>/dev/null || true
    dig +short NS "$TARGET" > "$OUTPUT_DIR/dns_ns.txt" 2>/dev/null || true
    dig +short TXT "$TARGET" > "$OUTPUT_DIR/dns_txt.txt" 2>/dev/null || true
    dig +short SOA "$TARGET" > "$OUTPUT_DIR/dns_soa.txt" 2>/dev/null || true
    dig +short CNAME "$TARGET" > "$OUTPUT_DIR/dns_cname.txt" 2>/dev/null || true
    echo "  DNS records saved"
fi

# ── Port Scanning ──────────────────────────────────────────
echo "[*] Phase 2: Port Scanning"

# Try our C probe first, then nmap, then netcat
if [[ -f "$(dirname "$0")/../build/bin/c-probe" ]]; then
    echo "  Running RecurSec C probe..."
    "$(dirname "$0")/../build/bin/c-probe" "$TARGET" 1 1024 2000 json > "$OUTPUT_DIR/ports_quick.json" 2>/dev/null || true
    echo "  Quick port scan complete"
fi

if command -v nmap &>/dev/null; then
    echo "  Running nmap top 1000 ports..."
    nmap -sT -T4 --top-ports 1000 -oN "$OUTPUT_DIR/nmap_quick.txt" \
         -oX "$OUTPUT_DIR/nmap_quick.xml" "$TARGET" 2>/dev/null || true
    echo "  nmap scan complete"
fi

if command -v masscan &>/dev/null; then
    echo "  Running masscan (top ports)..."
    masscan "$TARGET" -p1-1024,3306,3389,5432,5900,8080,8443,9090 \
            --rate=1000 -oJ "$OUTPUT_DIR/masscan.json" 2>/dev/null || true
    echo "  masscan complete"
fi

# ── Web Fingerprinting ─────────────────────────────────────
echo "[*] Phase 3: Web Fingerprinting"

# Check for HTTP/HTTPS
for proto in http https; do
    for port in 80 443 8080 8443; do
        URL="${proto}://${TARGET}:${port}"
        if curl -sI --connect-timeout 5 --max-time 10 "$URL" > /dev/null 2>&1; then
            echo "  Found web service at $URL"
            curl -sI --connect-timeout 5 --max-time 10 "$URL" > "$OUTPUT_DIR/headers_${proto}_${port}.txt" 2>/dev/null || true

            # Extract server info
            SERVER=$(grep -i "^Server:" "$OUTPUT_DIR/headers_${proto}_${port}.txt" 2>/dev/null | head -1)
            if [[ -n "$SERVER" ]]; then
                echo "    $SERVER"
            fi
        fi
    done
done

if command -v whatweb &>/dev/null; then
    echo "  Running whatweb..."
    whatweb -q --log-json "$OUTPUT_DIR/whatweb.json" "$TARGET" 2>/dev/null || true
fi

if command -v httpx &>/dev/null; then
    echo "  Running httpx..."
    echo "$TARGET" | httpx -silent -json -o "$OUTPUT_DIR/httpx.json" \
        -status-code -content-length -title -tech-detect 2>/dev/null || true
fi

# ── Subdomain Discovery ───────────────────────────────────
echo "[*] Phase 4: Subdomain Discovery"

if command -v subfinder &>/dev/null; then
    echo "  Running subfinder..."
    subfinder -d "$TARGET" -silent -o "$OUTPUT_DIR/subdomains_subfinder.txt" 2>/dev/null || true
    SUBFINDER_COUNT=$(wc -l < "$OUTPUT_DIR/subdomains_subfinder.txt" 2>/dev/null || echo "0")
    echo "  subfinder found $SUBFINDER_COUNT subdomains"
fi

# Certificate Transparency
echo "  Searching certificate transparency logs..."
curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" 2>/dev/null \
    | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    subs = set()
    for entry in data:
        for name in entry.get('name_value', '').split('\n'):
            name = name.strip().lower()
            if name and not name.startswith('*'):
                subs.add(name)
    for s in sorted(subs):
        print(s)
except:
    pass
" > "$OUTPUT_DIR/subdomains_crtsh.txt" 2>/dev/null || true
CRTSH_COUNT=$(wc -l < "$OUTPUT_DIR/subdomains_crtsh.txt" 2>/dev/null || echo "0")
echo "  crt.sh found $CRTSH_COUNT subdomains"

# Merge all subdomains
cat "$OUTPUT_DIR"/subdomains_*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/subdomains_all.txt" 2>/dev/null || true
TOTAL_SUBS=$(wc -l < "$OUTPUT_DIR/subdomains_all.txt" 2>/dev/null || echo "0")
echo "  Total unique subdomains: $TOTAL_SUBS"

# ── WHOIS ──────────────────────────────────────────────────
echo "[*] Phase 5: WHOIS Lookup"
if command -v whois &>/dev/null; then
    whois "$TARGET" > "$OUTPUT_DIR/whois.txt" 2>/dev/null || true
    echo "  WHOIS data saved"
fi

# ── Summary ────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════╗"
echo "║    Recon Complete                    ║"
echo "║    Output: $OUTPUT_DIR"
echo "║    Files:"
ls -1 "$OUTPUT_DIR" 2>/dev/null | while read -r f; do
    SIZE=$(stat -f%z "$OUTPUT_DIR/$f" 2>/dev/null || stat -c%s "$OUTPUT_DIR/$f" 2>/dev/null || echo "?")
    echo "║      $f ($SIZE bytes)"
done
echo "╚══════════════════════════════════════╝"
