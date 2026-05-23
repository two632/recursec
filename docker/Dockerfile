# RecurSec Docker Image — based on Kali Linux with all security tools pre-installed
FROM kalilinux/kali-rolling:latest

LABEL maintainer="RecurSec"
LABEL description="RecurSec — Recursive Multi-Agent Security Framework"

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

# System updates
RUN apt-get update && apt-get upgrade -y

# ── Core system tools ──────────────────────────────────
RUN apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv python3-dev \
    git curl wget jq xmlstarlet \
    build-essential gcc g++ make cmake \
    libssl-dev libffi-dev \
    net-tools iputils-ping dnsutils \
    && rm -rf /var/lib/apt/lists/*

# ── Kali meta-packages (installs 100+ security tools) ──
RUN apt-get update && apt-get install -y --no-install-recommends \
    kali-tools-top10 \
    nmap masscan \
    nikto \
    sqlmap \
    hydra medusa ncrack \
    john hashcat \
    metasploit-framework \
    exploitdb \
    wireshark-common tshark tcpdump \
    netcat-openbsd socat \
    gobuster dirb \
    enum4linux nbtscan \
    dnsrecon dnsenum \
    whatweb wafw00f \
    sslscan \
    aircrack-ng \
    responder \
    proxychains4 \
    binwalk foremost \
    radare2 \
    yara \
    forensics-extra \
    wordlists \
    seclists \
    && rm -rf /var/lib/apt/lists/*

# ── Go tools (ProjectDiscovery, etc.) ──────────────────
RUN apt-get update && apt-get install -y golang && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/OJ/gobuster/v3@latest && \
    go install github.com/hahwul/dalfox/v2@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/hakluke/hakrawler@latest && \
    go install github.com/jpillora/chisel@latest && \
    cp /root/go/bin/* /usr/local/bin/ && \
    rm -rf /var/lib/apt/lists/*

ENV PATH="/root/go/bin:/usr/local/bin:${PATH}"

# ── Python tools ───────────────────────────────────────
RUN pip3 install --break-system-packages \
    semgrep bandit safety \
    shodan censys \
    sherlock-project \
    boofuzz schemathesis \
    prowler scoutsuite \
    volatility3 \
    impacket \
    dirsearch \
    arjun \
    wfuzz \
    xsstrike \
    pwntools \
    ropper \
    hashid \
    holehe \
    spiderfoot

# ── Ruby tools ─────────────────────────────────────────
RUN apt-get update && apt-get install -y ruby ruby-dev && \
    gem install wpscan evil-winrm brakeman one_gadget && \
    rm -rf /var/lib/apt/lists/*

# ── Node.js tools ─────────────────────────────────────
RUN apt-get update && apt-get install -y nodejs npm && \
    npm install -g retire snyk @ast-grep/cli && \
    rm -rf /var/lib/apt/lists/*

# ── RecurSec installation ─────────────────────────────
WORKDIR /opt/recursec
COPY . /opt/recursec/
RUN pip3 install --break-system-packages -e .

# Workspace for scan outputs
RUN mkdir -p /workspace /data

VOLUME ["/workspace", "/data", "/opt/recursec/configs"]

EXPOSE 8080

ENTRYPOINT ["recursec"]
CMD ["run", "--config", "/opt/recursec/configs/recursec.yaml", "--daemon"]
