"""Binary analysis engine — ELF/PE/Mach-O inspection and security assessment.

Capabilities:
- File type detection (ELF, PE, Mach-O, scripts, archives)
- Security feature detection (ASLR, NX, stack canaries, RELRO, PIE)
- String extraction for intelligence (URLs, IPs, paths, credentials)
- Entropy analysis (packed/encrypted section detection)
- Import/export table inspection
- Section analysis
- Suspicious pattern detection
"""

from __future__ import annotations

import math
import re
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class BinaryInfo:
    """Basic binary file information."""
    filepath: str = ""
    size: int = 0
    file_type: str = "unknown"
    architecture: str = ""
    endianness: str = ""
    is_stripped: bool = False
    has_debug: bool = False
    entropy: float = 0.0
    is_likely_packed: bool = False


@dataclass
class SecurityFeatures:
    """Security mitigation features present in a binary."""
    nx: bool = False           # No-eXecute (DEP)
    pie: bool = False          # Position Independent Executable (ASLR)
    stack_canary: bool = False # Stack smashing protection
    relro: str = "none"        # RELRO: none, partial, full
    fortify: bool = False      # FORTIFY_SOURCE
    rpath: bool = False        # Has RPATH/RUNPATH (potential hijack)
    runpath: bool = False

    def get_issues(self) -> list[dict[str, str]]:
        issues = []
        if not self.nx:
            issues.append({"severity": "high", "issue": "NX (No-Execute) bit not set — executable stack"})
        if not self.pie:
            issues.append({"severity": "medium", "issue": "Not PIE — ASLR not fully effective"})
        if not self.stack_canary:
            issues.append({"severity": "high", "issue": "No stack canary — vulnerable to buffer overflows"})
        if self.relro == "none":
            issues.append({"severity": "medium", "issue": "No RELRO — GOT overwrite possible"})
        elif self.relro == "partial":
            issues.append({"severity": "low", "issue": "Partial RELRO — consider full RELRO"})
        if self.rpath or self.runpath:
            issues.append({"severity": "medium", "issue": "RPATH/RUNPATH set — potential library hijack"})
        return issues

    def to_dict(self) -> dict[str, Any]:
        return {
            "nx": self.nx, "pie": self.pie, "stack_canary": self.stack_canary,
            "relro": self.relro, "fortify": self.fortify,
            "rpath": self.rpath, "runpath": self.runpath,
            "issues": self.get_issues(),
        }


@dataclass
class SectionInfo:
    """Information about a binary section."""
    name: str = ""
    size: int = 0
    entropy: float = 0.0
    is_executable: bool = False
    is_writable: bool = False
    is_suspicious: bool = False


@dataclass
class StringFinding:
    """An interesting string found in a binary."""
    value: str
    offset: int
    category: str  # url, ip, path, credential, email, command, crypto_key


@dataclass
class BinaryAnalysisResult:
    """Complete binary analysis result."""
    info: BinaryInfo = field(default_factory=BinaryInfo)
    security: SecurityFeatures = field(default_factory=SecurityFeatures)
    sections: list[SectionInfo] = field(default_factory=list)
    strings: list[StringFinding] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    suspicious_imports: list[str] = field(default_factory=list)
    issues: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "info": {
                "filepath": self.info.filepath,
                "size": self.info.size,
                "file_type": self.info.file_type,
                "architecture": self.info.architecture,
                "entropy": round(self.info.entropy, 2),
                "likely_packed": self.info.is_likely_packed,
            },
            "security": self.security.to_dict(),
            "sections": [{"name": s.name, "size": s.size, "entropy": round(s.entropy, 2)} for s in self.sections],
            "interesting_strings": len(self.strings),
            "suspicious_imports": self.suspicious_imports,
            "total_issues": len(self.issues) + len(self.security.get_issues()),
        }


# ELF magic and constants
ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
MACHO_MAGIC = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}

# Suspicious import functions (potential for exploitation)
SUSPICIOUS_IMPORTS_LIST = {
    "system", "exec", "execve", "popen", "dlopen", "dlsym",
    "mprotect", "mmap", "ptrace", "fork", "socket", "connect",
    "bind", "listen", "accept", "send", "recv",
    "gets", "strcpy", "strcat", "sprintf", "scanf",
    "chmod", "chown", "setuid", "setgid",
    "CryptEncrypt", "CryptDecrypt", "VirtualAlloc", "VirtualProtect",
    "CreateRemoteThread", "WriteProcessMemory", "ReadProcessMemory",
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "WinExec", "ShellExecuteA", "ShellExecuteW",
    "InternetOpenA", "InternetConnectA", "HttpOpenRequestA",
    "URLDownloadToFileA", "WSAStartup",
}

# String extraction patterns
STRING_PATTERNS = {
    "url": re.compile(r"https?://[\w./\-?=&#%+]+"),
    "ip": re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "path_unix": re.compile(r"/(?:etc|usr|var|tmp|home|root|bin|opt)/[\w./\-]+"),
    "path_windows": re.compile(r"[A-Z]:\\[\w\\.\- ]+"),
    "registry": re.compile(r"HKEY_[\w\\]+"),
    "command": re.compile(r"(?:cmd\.exe|powershell|bash|sh|python)\s"),
    "crypto_key": re.compile(r"(?:-----BEGIN (?:RSA |EC |DSA )?(?:PRIVATE|PUBLIC) KEY-----)"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "base64_blob": re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
}


class BinaryAnalyzer:
    """Analyzes binary files for security properties."""

    def analyze(self, filepath: str) -> BinaryAnalysisResult:
        """Perform comprehensive binary analysis."""
        result = BinaryAnalysisResult()
        path = Path(filepath)

        if not path.exists():
            result.issues.append({"severity": "error", "issue": f"File not found: {filepath}"})
            return result

        try:
            data = path.read_bytes()
        except OSError as e:
            result.issues.append({"severity": "error", "issue": f"Cannot read file: {e}"})
            return result

        result.info.filepath = filepath
        result.info.size = len(data)
        result.info.entropy = self._calculate_entropy(data)
        result.info.is_likely_packed = result.info.entropy > 7.0

        if result.info.is_likely_packed:
            result.issues.append({
                "severity": "medium",
                "issue": f"High entropy ({result.info.entropy:.2f}) — possibly packed/encrypted",
            })

        # Detect file type
        result.info.file_type = self._detect_type(data)

        # Parse based on type
        if result.info.file_type == "ELF":
            self._analyze_elf(data, result)
        elif result.info.file_type == "PE":
            self._analyze_pe_basic(data, result)

        # Extract interesting strings
        result.strings = self._extract_strings(data)

        # Compile all issues
        result.issues.extend(result.security.get_issues())

        return result

    def _detect_type(self, data: bytes) -> str:
        """Detect binary file type from magic bytes."""
        if len(data) < 4:
            return "unknown"
        if data[:4] == ELF_MAGIC:
            return "ELF"
        if data[:2] == PE_MAGIC:
            return "PE"
        if data[:4] in MACHO_MAGIC:
            return "Mach-O"
        if data[:2] == b"#!":
            return "script"
        if data[:4] == b"PK\x03\x04":
            return "archive_zip"
        if data[:3] == b"\x1f\x8b\x08":
            return "archive_gzip"
        return "unknown"

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counter.values():
            prob = count / length
            if prob > 0:
                entropy -= prob * math.log2(prob)
        return entropy

    def _analyze_elf(self, data: bytes, result: BinaryAnalysisResult) -> None:
        """Analyze ELF binary."""
        if len(data) < 64:
            return

        # Architecture
        ei_class = data[4]
        result.info.architecture = "x86_64" if ei_class == 2 else "x86" if ei_class == 1 else "unknown"

        # Endianness
        ei_data = data[5]
        result.info.endianness = "little" if ei_data == 1 else "big" if ei_data == 2 else "unknown"

        endian = "<" if result.info.endianness == "little" else ">"

        # ELF type (ET_EXEC=2, ET_DYN=3 for PIE)
        if len(data) >= 18:
            e_type = struct.unpack(f"{endian}H", data[16:18])[0]
            if e_type == 3:  # ET_DYN — likely PIE
                result.security.pie = True

        # Scan for security features in raw bytes
        text = data.decode("latin-1", errors="replace")

        if "__stack_chk_fail" in text or "__stack_chk_guard" in text:
            result.security.stack_canary = True

        if "__fortify_fail" in text or "FORTIFY" in text:
            result.security.fortify = True

        if "RPATH" in text:
            result.security.rpath = True

        if "RUNPATH" in text:
            result.security.runpath = True

        # Check for RELRO markers
        if "GNU_RELRO" in text or b".got.plt" not in data:
            result.security.relro = "full"
        elif b".got.plt" in data:
            result.security.relro = "partial"

        # NX detection from program headers
        if b"GNU_STACK" in data:
            result.security.nx = True

        # Extract import-like strings
        self._extract_imports(text, result)

    def _analyze_pe_basic(self, data: bytes, result: BinaryAnalysisResult) -> None:
        """Basic PE analysis."""
        if len(data) < 64:
            return

        # Find PE header
        pe_offset = struct.unpack("<I", data[60:64])[0] if len(data) >= 64 else 0
        if pe_offset + 6 > len(data):
            return

        # Machine type
        if pe_offset + 6 <= len(data):
            machine = struct.unpack("<H", data[pe_offset + 4:pe_offset + 6])[0]
            if machine == 0x8664:
                result.info.architecture = "x86_64"
            elif machine == 0x14c:
                result.info.architecture = "x86"
            elif machine == 0xAA64:
                result.info.architecture = "ARM64"

        # Check for ASLR/DEP from DllCharacteristics
        if pe_offset + 0x5E <= len(data):
            chars = struct.unpack("<H", data[pe_offset + 0x5E:pe_offset + 0x60])[0]
            result.security.pie = bool(chars & 0x0040)  # DYNAMIC_BASE (ASLR)
            result.security.nx = bool(chars & 0x0100)   # NX_COMPAT (DEP)

        # Extract import-like strings
        text = data.decode("latin-1", errors="replace")
        self._extract_imports(text, result)

    def _extract_imports(self, text: str, result: BinaryAnalysisResult) -> None:
        """Extract import function names and flag suspicious ones."""
        # Simple extraction of likely function names
        for func in SUSPICIOUS_IMPORTS_LIST:
            if func in text:
                result.suspicious_imports.append(func)
                if func not in result.imports:
                    result.imports.append(func)

    def _extract_strings(self, data: bytes, min_length: int = 6) -> list[StringFinding]:
        """Extract interesting strings from binary data."""
        findings: list[StringFinding] = []

        # Extract printable ASCII strings
        ascii_pattern = re.compile(rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}")
        seen: set[str] = set()

        for match in ascii_pattern.finditer(data):
            string = match.group().decode("ascii", errors="replace")
            if string in seen:
                continue
            seen.add(string)

            for category, pattern in STRING_PATTERNS.items():
                if pattern.search(string):
                    findings.append(StringFinding(
                        value=string[:200],
                        offset=match.start(),
                        category=category,
                    ))
                    break

        return findings[:500]  # Cap findings
