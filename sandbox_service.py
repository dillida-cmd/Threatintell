#!/usr/bin/env python3
"""
Micro Sandbox Service for ShieldTier
Analyzes attachments (.exe, .pdf, scripts) and URLs in isolated environments
Collects IOCs, captures screenshots, and integrates with existing modules
"""

import os
import sys
import json
import shutil
import hashlib
import tempfile
import subprocess
import sqlite3
import threading
import re
import uuid
import base64
import signal
import math
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse

# PE analysis
try:
    import pefile
    PE_ANALYSIS_AVAILABLE = True
except ImportError:
    PE_ANALYSIS_AVAILABLE = False

# Configuration
SANDBOX_DIR = os.path.join(os.path.dirname(__file__), 'sandbox')
SESSIONS_DIR = os.path.join(SANDBOX_DIR, 'sessions')
SAMPLES_DIR = os.path.join(SANDBOX_DIR, 'samples')
RESULTS_DIR = os.path.join(SANDBOX_DIR, 'results')
SCREENSHOTS_DIR = os.path.join(SANDBOX_DIR, 'screenshots')
DATABASE_FILE = os.path.join(os.path.dirname(__file__), 'analysis_results.db')

# Limits
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
MAX_TIMEOUT = 300  # 5 minutes
DEFAULT_TIMEOUT = 30  # 30 seconds
MAX_CONCURRENT_SESSIONS = 3
MEMORY_LIMIT_MB = 512
DISK_LIMIT_MB = 100

# Realistic browser User-Agent to avoid bot detection
REALISTIC_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'

# File type detection
MAGIC_SIGNATURES = {
    b'MZ': 'executable',  # PE/DOS
    b'\x7fELF': 'executable',  # ELF
    b'%PDF': 'pdf',
    b'PK\x03\x04': 'archive',  # ZIP/Office
    b'\xd0\xcf\x11\xe0': 'office_legacy',  # OLE2 (old Office)
    b'#!/': 'script',
    b'#!': 'script',
}

SCRIPT_EXTENSIONS = {'.sh', '.py', '.js', '.pl', '.rb', '.php', '.ps1', '.bat', '.cmd', '.vbs', '.wsf'}
WINDOWS_SCRIPT_EXTENSIONS = {'.bat', '.cmd', '.ps1', '.vbs', '.wsf'}
EXECUTABLE_EXTENSIONS = {'.exe', '.dll', '.msi', '.com', '.scr', '.pif'}
DOCUMENT_EXTENSIONS = {'.docm', '.xlsm', '.pptm', '.doc', '.xls', '.ppt', '.docx', '.xlsx', '.pptx'}
PDF_EXTENSIONS = {'.pdf'}

# IOC extraction patterns
IP_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
URL_PATTERN = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
HASH_MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
HASH_SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
HASH_SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

# Valid TLDs for domain filtering (common ones)
VALID_TLDS = {
    'com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'io', 'co', 'us', 'uk', 'de', 'fr', 'es',
    'it', 'nl', 'be', 'ch', 'at', 'au', 'ca', 'br', 'mx', 'jp', 'cn', 'kr', 'in', 'ru', 'pl',
    'se', 'no', 'dk', 'fi', 'ie', 'nz', 'za', 'sg', 'hk', 'tw', 'my', 'th', 'vn', 'id', 'ph',
    'eu', 'asia', 'info', 'biz', 'name', 'pro', 'xyz', 'online', 'site', 'tech', 'app', 'dev',
    'cloud', 'store', 'shop', 'blog', 'news', 'live', 'today', 'media', 'group', 'world',
    'space', 'top', 'link', 'click', 'club', 'work', 'life', 'email', 'one', 'ai', 'me', 'tv'
}

# File extensions that look like TLDs but aren't domains
FALSE_POSITIVE_EXTENSIONS = {
    'css', 'js', 'php', 'html', 'htm', 'asp', 'aspx', 'jsp', 'py', 'rb', 'pl', 'sh',
    'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'webp', 'bmp', 'tiff',
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'csv', 'xml', 'json',
    'zip', 'rar', 'tar', 'gz', 'exe', 'dll', 'msi', 'bin', 'iso',
    'mp3', 'mp4', 'avi', 'mov', 'wmv', 'flv', 'wav', 'ogg', 'woff', 'woff2', 'ttf', 'eot',
    'min', 'map', 'scss', 'sass', 'less'
}

# Known safe/benign domains to exclude from IOCs
SAFE_DOMAINS = {
    # CDNs and hosting
    'googleapis.com', 'fonts.googleapis.com', 'ajax.googleapis.com', 'maps.googleapis.com',
    'googletagmanager.com', 'www.googletagmanager.com', 'google-analytics.com',
    'cloudflare.com', 'cdnjs.cloudflare.com', 'cdn.cloudflare.com',
    'jsdelivr.net', 'cdn.jsdelivr.net', 'unpkg.com', 'cdnjs.com',
    'bootstrapcdn.com', 'maxcdn.bootstrapcdn.com',
    'fontawesome.com', 'kit.fontawesome.com', 'use.fontawesome.com',
    'jquery.com', 'code.jquery.com',
    # Standards and specs
    'w3.org', 'www.w3.org', 'schema.org', 'ogp.me', 'gmpg.org',
    # WordPress
    'wordpress.org', 'api.wordpress.org', 'api.w.org', 's.w.org',
    'wp.org', 'api.wp.org', 'gravatar.com', 's.gravatar.com',
    # Social/Common
    'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com', 'youtube.com',
    'github.com', 'githubusercontent.com', 'raw.githubusercontent.com',
    # Analytics
    'google.com', 'www.google.com', 'gstatic.com', 'www.gstatic.com',
}

# Patterns that indicate CSS classes or JS code, not domains
CSS_JS_PATTERNS = [
    r'^wp-block-',  # WordPress blocks
    r'^style\.',    # CSS
    r'^script\.',
    r'^window\.',   # JS globals
    r'^document\.',
    r'^datalayer\.',
    r'^image\.',
    r'^img\.',
    r'^body\.',
    r'^h[1-6]\.',   # h1.has, h2.has etc
    r'\.align',     # .alignleft, .alignright
    r'\.has[A-Z]',  # .hasImage
    r'\.wp[a-z]',   # .wpg
    r'\.is[A-Z]',   # .isDefault
    r'-\d+x\d+\.',  # image dimensions like -150x150.png
    r'^cropped-',   # WordPress cropped images
    r'\.min$',      # minified files
    r'^[a-z]+callbacks\.',  # JS callbacks
]

# Session tracking
_active_sessions = {}
_session_lock = threading.Lock()


# =============================================================================
# Directory Setup
# =============================================================================

def ensure_directories():
    """Create sandbox directory structure"""
    for directory in [SANDBOX_DIR, SESSIONS_DIR, SAMPLES_DIR, RESULTS_DIR, SCREENSHOTS_DIR]:
        os.makedirs(directory, exist_ok=True)


# Initialize directories on import
ensure_directories()


# =============================================================================
# Capability Detection
# =============================================================================

class SandboxConfig:
    """Detects available sandboxing capabilities"""

    def __init__(self):
        self._capabilities = None
        self._lock = threading.Lock()

    def detect_capabilities(self) -> Dict[str, Any]:
        """Detect available sandboxing tools and backends"""
        with self._lock:
            if self._capabilities is not None:
                return self._capabilities

            self._capabilities = {
                'docker': self._check_docker(),
                'bubblewrap': self._check_bubblewrap(),
                'wine': self._check_wine(),
                'strace': self._check_strace(),
                'timeout_cmd': self._check_timeout(),
                'chromium': self._check_chromium(),
                'libreoffice': self._check_libreoffice(),
                'python': self._check_python(),
                'node': self._check_node(),
            }

            # Determine supported file types
            self._capabilities['supported_types'] = self._get_supported_types()

            return self._capabilities

    def _check_docker(self) -> Dict:
        """Check if Docker is available"""
        result = {'available': False, 'version': None}
        try:
            proc = subprocess.run(['docker', '--version'], capture_output=True, timeout=5)
            if proc.returncode == 0:
                result['available'] = True
                result['version'] = proc.stdout.decode().strip()
                # Check if we can actually run containers
                proc2 = subprocess.run(['docker', 'info'], capture_output=True, timeout=10)
                result['functional'] = proc2.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return result

    def _check_bubblewrap(self) -> Dict:
        """Check if bubblewrap (bwrap) is available"""
        result = {'available': False, 'version': None}
        try:
            proc = subprocess.run(['bwrap', '--version'], capture_output=True, timeout=5)
            if proc.returncode == 0:
                result['available'] = True
                result['version'] = proc.stdout.decode().strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return result

    def _check_wine(self) -> Dict:
        """Check if Wine is available for Windows binary analysis"""
        result = {'available': False, 'version': None}
        try:
            proc = subprocess.run(['wine', '--version'], capture_output=True, timeout=5)
            if proc.returncode == 0:
                result['available'] = True
                result['version'] = proc.stdout.decode().strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return result

    def _check_strace(self) -> Dict:
        """Check if strace is available for syscall tracing"""
        result = {'available': False, 'version': None}
        try:
            proc = subprocess.run(['strace', '-V'], capture_output=True, timeout=5)
            if proc.returncode == 0:
                result['available'] = True
                result['version'] = proc.stdout.decode().split('\n')[0].strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return result

    def _check_timeout(self) -> Dict:
        """Check if timeout command is available"""
        result = {'available': False}
        try:
            proc = subprocess.run(['timeout', '--version'], capture_output=True, timeout=5)
            result['available'] = proc.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return result

    def _check_chromium(self) -> Dict:
        """Check if Chromium is available for URL analysis"""
        result = {'available': False, 'path': None}
        # Prioritize google-chrome over snap chromium which has permission issues
        for cmd in ['google-chrome-stable', 'google-chrome', 'chromium', 'chromium-browser']:
            path = shutil.which(cmd)
            if path:
                result['available'] = True
                result['path'] = path
                break
        return result

    def _check_libreoffice(self) -> Dict:
        """Check if LibreOffice is available for document analysis"""
        result = {'available': False, 'path': None}
        for cmd in ['libreoffice', 'soffice']:
            path = shutil.which(cmd)
            if path:
                result['available'] = True
                result['path'] = path
                break
        return result

    def _check_python(self) -> Dict:
        """Check if Python is available for script analysis"""
        result = {'available': False, 'version': None}
        try:
            proc = subprocess.run(['python3', '--version'], capture_output=True, timeout=5)
            if proc.returncode == 0:
                result['available'] = True
                result['version'] = proc.stdout.decode().strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return result

    def _check_node(self) -> Dict:
        """Check if Node.js is available for JS analysis"""
        result = {'available': False, 'version': None}
        try:
            proc = subprocess.run(['node', '--version'], capture_output=True, timeout=5)
            if proc.returncode == 0:
                result['available'] = True
                result['version'] = proc.stdout.decode().strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return result

    def _get_supported_types(self) -> Dict[str, bool]:
        """Determine which file types can be analyzed"""
        caps = self._capabilities
        bwrap = caps.get('bubblewrap', {}).get('available', False)
        docker = caps.get('docker', {}).get('available', False)

        wine_available = caps.get('wine', {}).get('available', False)
        return {
            'scripts': bwrap or docker,
            'windows_scripts': (bwrap or docker),  # Partial support via interpreters
            'executables': (bwrap or docker) and wine_available,
            'documents': docker and caps.get('libreoffice', {}).get('available', False),
            'pdfs': bwrap or docker,
            'urls': caps.get('chromium', {}).get('available', False),
        }

    def get_preferred_backend(self) -> str:
        """Get the preferred sandboxing backend"""
        caps = self.detect_capabilities()
        if caps.get('bubblewrap', {}).get('available'):
            return 'bubblewrap'
        elif caps.get('docker', {}).get('functional'):
            return 'docker'
        return 'none'


# Global config instance
_config = SandboxConfig()


# =============================================================================
# IOC Collector
# =============================================================================

class IOCCollector:
    """Extracts and collects IOCs from various sources"""

    def __init__(self):
        self.ips = set()
        self.urls = set()
        self.domains = set()
        self.emails = set()
        self.hashes = {'md5': set(), 'sha1': set(), 'sha256': set()}
        self.file_paths = set()
        self.registry_keys = set()
        self.mutex_names = set()
        self.dns_queries = set()

    def extract_from_text(self, text: str):
        """Extract IOCs from text content"""
        if not text:
            return

        # Extract IPs
        for match in IP_PATTERN.findall(text):
            # Filter out common false positives
            if not match.startswith('0.') and not match.startswith('127.'):
                self.ips.add(match)

        # Extract URLs
        for match in URL_PATTERN.findall(text):
            self.urls.add(match)

        # Extract domains with improved filtering
        for match in DOMAIN_PATTERN.findall(text):
            domain = match.lower()

            # Skip if too short
            if len(domain) < 4 or '.' not in domain:
                continue

            # Get the TLD (last part after dot)
            parts = domain.split('.')
            tld = parts[-1]

            # Skip if TLD is actually a file extension
            if tld in FALSE_POSITIVE_EXTENSIONS:
                continue

            # Skip if TLD is not a valid domain TLD
            if tld not in VALID_TLDS:
                continue

            # Skip known safe domains
            if domain in SAFE_DOMAINS or any(domain.endswith('.' + safe) for safe in SAFE_DOMAINS):
                continue

            # Skip if matches CSS/JS patterns
            is_css_js = False
            for pattern in CSS_JS_PATTERNS:
                if re.search(pattern, domain, re.IGNORECASE):
                    is_css_js = True
                    break
            if is_css_js:
                continue

            # Skip if it looks like a file path (has multiple segments with file-like names)
            if any(part.endswith(('.css', '.js', '.png', '.jpg', '.php', '.html')) for part in parts[:-1]):
                continue

            self.domains.add(domain)

        # Extract emails
        for match in EMAIL_PATTERN.findall(text):
            self.emails.add(match.lower())

        # Extract hashes
        for match in HASH_MD5_PATTERN.findall(text):
            self.hashes['md5'].add(match.lower())
        for match in HASH_SHA1_PATTERN.findall(text):
            self.hashes['sha1'].add(match.lower())
        for match in HASH_SHA256_PATTERN.findall(text):
            self.hashes['sha256'].add(match.lower())

    def extract_from_strace(self, strace_output: str):
        """Extract IOCs from strace output"""
        if not strace_output:
            return

        # Extract file paths from open/openat/stat calls
        file_patterns = [
            r'open(?:at)?\([^,]*,\s*"([^"]+)"',
            r'stat\("([^"]+)"',
            r'execve\("([^"]+)"',
            r'access\("([^"]+)"',
        ]

        for pattern in file_patterns:
            for match in re.findall(pattern, strace_output):
                if not match.startswith('/proc/') and not match.startswith('/sys/'):
                    self.file_paths.add(match)

        # Extract network connections
        connect_pattern = r'connect\([^,]+,\s*\{[^}]*sin_addr=inet_addr\("([^"]+)"\)[^}]*sin_port=htons\((\d+)\)'
        for match in re.findall(connect_pattern, strace_output):
            ip, port = match
            self.ips.add(ip)
            self.urls.add(f"tcp://{ip}:{port}")

        # Extract DNS queries (from /etc/resolv.conf reads or getaddrinfo calls)
        dns_pattern = r'getaddrinfo\("([^"]+)"'
        for match in re.findall(dns_pattern, strace_output):
            self.dns_queries.add(match)
            self.domains.add(match)

        # Also scan for any text-based IOCs
        self.extract_from_text(strace_output)

    def extract_from_network_log(self, network_data: str):
        """Extract IOCs from network capture logs"""
        if not network_data:
            return

        self.extract_from_text(network_data)

    def to_dict(self) -> Dict:
        """Convert collected IOCs to dictionary"""
        return {
            'ips': list(self.ips),
            'urls': list(self.urls),
            'domains': list(self.domains),
            'emails': list(self.emails),
            'hashes': {
                'md5': list(self.hashes['md5']),
                'sha1': list(self.hashes['sha1']),
                'sha256': list(self.hashes['sha256']),
            },
            'filePaths': list(self.file_paths),
            'dnsQueries': list(self.dns_queries),
            'summary': {
                'totalIPs': len(self.ips),
                'totalURLs': len(self.urls),
                'totalDomains': len(self.domains),
                'totalHashes': sum(len(h) for h in self.hashes.values()),
            }
        }


# =============================================================================
# Threat Map - MITRE ATT&CK Mapping
# =============================================================================

class ThreatMap:
    """Categorize and visualize malware behaviors with MITRE ATT&CK mappings"""

    categories = {
        'network': {'icon': '🌐', 'title': 'Network Activity'},
        'filesystem': {'icon': '📁', 'title': 'File System'},
        'registry': {'icon': '🔑', 'title': 'Registry'},
        'process': {'icon': '⚙️', 'title': 'Process Activity'},
        'persistence': {'icon': '🔄', 'title': 'Persistence'},
        'evasion': {'icon': '🛡️', 'title': 'Defense Evasion'},
        'discovery': {'icon': '🔍', 'title': 'Discovery'},
        'credential': {'icon': '🔐', 'title': 'Credential Access'}
    }

    # MITRE ATT&CK technique mappings for suspicious behaviors
    technique_mappings = {
        # Process Injection - T1055
        'VirtualAlloc': {'technique': 'T1055', 'name': 'Process Injection', 'category': 'evasion', 'severity': 'high'},
        'VirtualAllocEx': {'technique': 'T1055', 'name': 'Process Injection', 'category': 'evasion', 'severity': 'high'},
        'VirtualProtect': {'technique': 'T1055', 'name': 'Process Injection', 'category': 'evasion', 'severity': 'high'},
        'VirtualProtectEx': {'technique': 'T1055', 'name': 'Process Injection', 'category': 'evasion', 'severity': 'high'},
        'WriteProcessMemory': {'technique': 'T1055', 'name': 'Process Injection', 'category': 'process', 'severity': 'critical'},
        'CreateRemoteThread': {'technique': 'T1055', 'name': 'Process Injection', 'category': 'process', 'severity': 'critical'},
        'NtUnmapViewOfSection': {'technique': 'T1055.012', 'name': 'Process Hollowing', 'category': 'evasion', 'severity': 'critical'},

        # Boot/Logon Autostart - T1547
        'RegSetValueEx': {'technique': 'T1547', 'name': 'Boot/Logon Autostart', 'category': 'persistence', 'severity': 'high'},
        'RegSetValueExA': {'technique': 'T1547', 'name': 'Boot/Logon Autostart', 'category': 'persistence', 'severity': 'high'},
        'RegSetValueExW': {'technique': 'T1547', 'name': 'Boot/Logon Autostart', 'category': 'persistence', 'severity': 'high'},
        'RegCreateKeyEx': {'technique': 'T1547', 'name': 'Boot/Logon Autostart', 'category': 'registry', 'severity': 'medium'},

        # Application Layer Protocol - T1071
        'InternetConnect': {'technique': 'T1071', 'name': 'Application Layer Protocol', 'category': 'network', 'severity': 'medium'},
        'InternetConnectA': {'technique': 'T1071', 'name': 'Application Layer Protocol', 'category': 'network', 'severity': 'medium'},
        'InternetConnectW': {'technique': 'T1071', 'name': 'Application Layer Protocol', 'category': 'network', 'severity': 'medium'},
        'HttpOpenRequest': {'technique': 'T1071', 'name': 'Application Layer Protocol', 'category': 'network', 'severity': 'medium'},
        'HttpSendRequest': {'technique': 'T1071', 'name': 'Application Layer Protocol', 'category': 'network', 'severity': 'medium'},
        'URLDownloadToFile': {'technique': 'T1071', 'name': 'Application Layer Protocol', 'category': 'network', 'severity': 'high'},

        # Dynamic Resolution - T1027 (Obfuscated Files)
        'GetProcAddress': {'technique': 'T1027', 'name': 'Obfuscated Files/Dynamic Resolution', 'category': 'evasion', 'severity': 'low'},
        'LoadLibraryA': {'technique': 'T1027', 'name': 'Obfuscated Files/Dynamic Resolution', 'category': 'evasion', 'severity': 'low'},
        'LoadLibraryW': {'technique': 'T1027', 'name': 'Obfuscated Files/Dynamic Resolution', 'category': 'evasion', 'severity': 'low'},
        'LoadLibraryExA': {'technique': 'T1027', 'name': 'Obfuscated Files/Dynamic Resolution', 'category': 'evasion', 'severity': 'low'},
        'LoadLibraryExW': {'technique': 'T1027', 'name': 'Obfuscated Files/Dynamic Resolution', 'category': 'evasion', 'severity': 'low'},

        # Anti-Debugging - T1622
        'IsDebuggerPresent': {'technique': 'T1622', 'name': 'Debugger Evasion', 'category': 'evasion', 'severity': 'medium'},
        'CheckRemoteDebuggerPresent': {'technique': 'T1622', 'name': 'Debugger Evasion', 'category': 'evasion', 'severity': 'medium'},
        'NtQueryInformationProcess': {'technique': 'T1622', 'name': 'Debugger Evasion', 'category': 'evasion', 'severity': 'medium'},

        # File Manipulation - T1070
        'DeleteFileA': {'technique': 'T1070.004', 'name': 'File Deletion', 'category': 'evasion', 'severity': 'low'},
        'DeleteFileW': {'technique': 'T1070.004', 'name': 'File Deletion', 'category': 'evasion', 'severity': 'low'},

        # Process Creation - T1059
        'CreateProcess': {'technique': 'T1059', 'name': 'Command Execution', 'category': 'process', 'severity': 'medium'},
        'CreateProcessA': {'technique': 'T1059', 'name': 'Command Execution', 'category': 'process', 'severity': 'medium'},
        'CreateProcessW': {'technique': 'T1059', 'name': 'Command Execution', 'category': 'process', 'severity': 'medium'},
        'ShellExecute': {'technique': 'T1059', 'name': 'Command Execution', 'category': 'process', 'severity': 'medium'},
        'ShellExecuteA': {'technique': 'T1059', 'name': 'Command Execution', 'category': 'process', 'severity': 'medium'},
        'ShellExecuteW': {'technique': 'T1059', 'name': 'Command Execution', 'category': 'process', 'severity': 'medium'},
        'WinExec': {'technique': 'T1059', 'name': 'Command Execution', 'category': 'process', 'severity': 'medium'},

        # System Discovery - T1082
        'GetSystemInfo': {'technique': 'T1082', 'name': 'System Information Discovery', 'category': 'discovery', 'severity': 'low'},
        'GetVersionEx': {'technique': 'T1082', 'name': 'System Information Discovery', 'category': 'discovery', 'severity': 'low'},
        'GetComputerName': {'technique': 'T1082', 'name': 'System Information Discovery', 'category': 'discovery', 'severity': 'low'},

        # Credential Access - T1003
        'LsaRetrievePrivateData': {'technique': 'T1003', 'name': 'OS Credential Dumping', 'category': 'credential', 'severity': 'critical'},
        'CredEnumerate': {'technique': 'T1555', 'name': 'Credentials from Password Stores', 'category': 'credential', 'severity': 'high'},

        # Screen Capture - T1113
        'BitBlt': {'technique': 'T1113', 'name': 'Screen Capture', 'category': 'discovery', 'severity': 'medium'},
        'GetDC': {'technique': 'T1113', 'name': 'Screen Capture', 'category': 'discovery', 'severity': 'low'},

        # Clipboard - T1115
        'GetClipboardData': {'technique': 'T1115', 'name': 'Clipboard Data', 'category': 'discovery', 'severity': 'medium'},
        'SetClipboardData': {'technique': 'T1115', 'name': 'Clipboard Data', 'category': 'discovery', 'severity': 'low'},

        # Keylogging - T1056.001
        'SetWindowsHookEx': {'technique': 'T1056.001', 'name': 'Keylogging', 'category': 'credential', 'severity': 'high'},
        'GetAsyncKeyState': {'technique': 'T1056.001', 'name': 'Keylogging', 'category': 'credential', 'severity': 'medium'},
        'GetKeyState': {'technique': 'T1056.001', 'name': 'Keylogging', 'category': 'credential', 'severity': 'low'},
    }

    def __init__(self):
        self.behaviors = {cat: [] for cat in self.categories}

    def add_behavior(self, category: str, behavior: str, api: str = None,
                     technique: str = None, severity: str = 'medium', details: str = None):
        """Add a behavior to the threat map"""
        if category not in self.behaviors:
            category = 'process'  # Default category

        entry = {
            'behavior': behavior,
            'severity': severity
        }
        if api:
            entry['api'] = api
        if technique:
            entry['technique'] = technique
        if details:
            entry['details'] = details

        # Avoid duplicates
        if entry not in self.behaviors[category]:
            self.behaviors[category].append(entry)

    def analyze_imports(self, imports: List[Dict]) -> List[Dict]:
        """Analyze PE imports and map to MITRE techniques"""
        risk_reasons = []

        for dll_entry in imports:
            dll_name = dll_entry.get('dll', '').lower()
            for func in dll_entry.get('functions', []):
                func_name = func.get('name', '')
                if func_name in self.technique_mappings:
                    mapping = self.technique_mappings[func_name]
                    self.add_behavior(
                        category=mapping['category'],
                        behavior=f"{mapping['name']} via {func_name}",
                        api=func_name,
                        technique=mapping['technique'],
                        severity=mapping['severity']
                    )
                    risk_reasons.append({
                        'category': 'Suspicious Import',
                        'description': f'{func_name} can be used for {mapping["name"]}',
                        'severity': mapping['severity'],
                        'technique': f"{mapping['technique']} - {mapping['name']}",
                        'source': f'{dll_name}!{func_name}'
                    })

        return risk_reasons

    def analyze_sections(self, sections: List[Dict]) -> List[Dict]:
        """Analyze PE sections for suspicious characteristics"""
        risk_reasons = []

        for section in sections:
            name = section.get('name', '')
            entropy = section.get('entropy', 0)
            chars = section.get('characteristics', [])

            # Check for executable and writable sections (RWX)
            if 'EXECUTE' in chars and 'WRITE' in chars:
                self.add_behavior(
                    category='evasion',
                    behavior='Executable section with write permission',
                    technique='T1027',
                    severity='medium',
                    details=f'Section: {name}'
                )
                risk_reasons.append({
                    'category': 'Suspicious Section',
                    'description': f'Section {name} has both EXECUTE and WRITE permissions (RWX)',
                    'severity': 'medium',
                    'technique': 'T1027 - Obfuscated Files or Information'
                })

            # Check for high entropy (packed/encrypted)
            if entropy > 7.0:
                self.add_behavior(
                    category='evasion',
                    behavior='High entropy section (possibly packed/encrypted)',
                    technique='T1027',
                    severity='high',
                    details=f'Section: {name}, Entropy: {entropy:.2f}'
                )
                risk_reasons.append({
                    'category': 'Packed/Encrypted',
                    'description': f'Section {name} has high entropy ({entropy:.2f}) indicating packing or encryption',
                    'severity': 'high',
                    'technique': 'T1027 - Obfuscated Files or Information'
                })

            # Check for unusual section names
            if section.get('unusual'):
                self.add_behavior(
                    category='evasion',
                    behavior=f'Unusual section name: {name}',
                    technique='T1027',
                    severity='low'
                )

        return risk_reasons

    def to_dict(self) -> Dict:
        """Convert threat map to dictionary for JSON output"""
        return {cat: behaviors for cat, behaviors in self.behaviors.items() if behaviors}

    @classmethod
    def get_severity_score(cls, severity: str) -> int:
        """Get numeric score for severity level"""
        scores = {'critical': 25, 'high': 15, 'medium': 10, 'low': 5}
        return scores.get(severity, 5)


# =============================================================================
# MITRE ATT&CK Technique Mappings
# =============================================================================

MITRE_TECHNIQUES = {
    # Execution
    'CreateProcess': {'id': 'T1106', 'name': 'Native API', 'tactic': 'Execution'},
    'ShellExecute': {'id': 'T1059', 'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'},
    'WinExec': {'id': 'T1106', 'name': 'Native API', 'tactic': 'Execution'},
    'LoadLibrary': {'id': 'T1129', 'name': 'Shared Modules', 'tactic': 'Execution'},
    'GetProcAddress': {'id': 'T1106', 'name': 'Native API', 'tactic': 'Execution'},

    # Defense Evasion / Process Injection
    'VirtualAlloc': {'id': 'T1055', 'name': 'Process Injection', 'tactic': 'Defense Evasion'},
    'VirtualProtect': {'id': 'T1055', 'name': 'Process Injection', 'tactic': 'Defense Evasion'},
    'WriteProcessMemory': {'id': 'T1055.001', 'name': 'DLL Injection', 'tactic': 'Defense Evasion'},
    'CreateRemoteThread': {'id': 'T1055.001', 'name': 'DLL Injection', 'tactic': 'Privilege Escalation'},
    'NtUnmapViewOfSection': {'id': 'T1055.012', 'name': 'Process Hollowing', 'tactic': 'Defense Evasion'},

    # Command and Control
    'WSAStartup': {'id': 'T1071', 'name': 'Application Layer Protocol', 'tactic': 'Command and Control'},
    'socket': {'id': 'T1095', 'name': 'Non-Application Layer Protocol', 'tactic': 'Command and Control'},
    'connect': {'id': 'T1095', 'name': 'Non-Application Layer Protocol', 'tactic': 'Command and Control'},
    'send': {'id': 'T1095', 'name': 'Non-Application Layer Protocol', 'tactic': 'Command and Control'},
    'recv': {'id': 'T1095', 'name': 'Non-Application Layer Protocol', 'tactic': 'Command and Control'},
    'InternetOpen': {'id': 'T1071.001', 'name': 'Web Protocols', 'tactic': 'Command and Control'},
    'InternetConnect': {'id': 'T1071.001', 'name': 'Web Protocols', 'tactic': 'Command and Control'},
    'HttpOpenRequest': {'id': 'T1071.001', 'name': 'Web Protocols', 'tactic': 'Command and Control'},
    'gethostbyname': {'id': 'T1071', 'name': 'Application Layer Protocol', 'tactic': 'Command and Control'},
    'getaddrinfo': {'id': 'T1071', 'name': 'Application Layer Protocol', 'tactic': 'Command and Control'},

    # Persistence
    'RegSetValue': {'id': 'T1547.001', 'name': 'Registry Run Keys', 'tactic': 'Persistence'},
    'RegCreateKey': {'id': 'T1547.001', 'name': 'Registry Run Keys', 'tactic': 'Persistence'},
    'CreateService': {'id': 'T1543.003', 'name': 'Windows Service', 'tactic': 'Persistence'},

    # Discovery
    'GetTickCount': {'id': 'T1497', 'name': 'Virtualization/Sandbox Evasion', 'tactic': 'Defense Evasion'},
    'GetSystemTime': {'id': 'T1124', 'name': 'System Time Discovery', 'tactic': 'Discovery'},
    'GetComputerName': {'id': 'T1082', 'name': 'System Information Discovery', 'tactic': 'Discovery'},
    'GetUserName': {'id': 'T1033', 'name': 'System Owner/User Discovery', 'tactic': 'Discovery'},
    'GetVersion': {'id': 'T1082', 'name': 'System Information Discovery', 'tactic': 'Discovery'},

    # File Operations
    'CreateFile': {'id': 'T1083', 'name': 'File and Directory Discovery', 'tactic': 'Discovery'},
    'ReadFile': {'id': 'T1005', 'name': 'Data from Local System', 'tactic': 'Collection'},
    'WriteFile': {'id': 'T1565.001', 'name': 'Stored Data Manipulation', 'tactic': 'Impact'},
    'DeleteFile': {'id': 'T1070.004', 'name': 'File Deletion', 'tactic': 'Defense Evasion'},

    # Crypto
    'CryptAcquireContext': {'id': 'T1027', 'name': 'Obfuscated Files or Information', 'tactic': 'Defense Evasion'},
    'CryptEncrypt': {'id': 'T1486', 'name': 'Data Encrypted for Impact', 'tactic': 'Impact'},
    'CryptDecrypt': {'id': 'T1140', 'name': 'Deobfuscate/Decode Files', 'tactic': 'Defense Evasion'},
}

# Suspicious API patterns that indicate malicious behavior
SUSPICIOUS_API_PATTERNS = {
    'process_injection': ['VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory', 'CreateRemoteThread', 'NtUnmapViewOfSection'],
    'code_execution': ['CreateProcess', 'ShellExecute', 'WinExec', 'system'],
    'network_communication': ['WSAStartup', 'socket', 'connect', 'send', 'recv', 'InternetOpen', 'InternetConnect'],
    'persistence': ['RegSetValue', 'RegCreateKey', 'CreateService', 'SetFileAttributes'],
    'anti_analysis': ['GetTickCount', 'QueryPerformanceCounter', 'IsDebuggerPresent', 'CheckRemoteDebuggerPresent'],
    'credential_access': ['CredRead', 'LsaRetrievePrivateData', 'CryptUnprotectData'],
    'discovery': ['GetComputerName', 'GetUserName', 'GetSystemInfo', 'GetVersion', 'EnumProcesses'],
}


# =============================================================================
# Enhanced Wine Debug Output Parser with API Tracing
# =============================================================================

def parse_wine_debug_output(output: str) -> Dict:
    """Parse Wine debug output to extract behavioral data

    Wine trace format examples:
    - trace:reg:NtOpenKeyEx ((nil),L"\\Registry\\Machine\\...")
    - trace:file:nt_to_unix_file_name L"\\??\\C:\\Windows\\..."
    - trace:loaddll:Loaded L"C:\\Windows\\System32\\ntdll.dll"
    - trace:relay:Call KERNEL32.VirtualAlloc(...)
    """
    result = {
        'filesystem': {
            'filesOpened': [],
            'filesCreated': [],
        },
        'registry': {
            'keysOpened': [],
            'keysModified': [],
        },
        'dlls': [],
        'apiCalls': [],
        'mitreTechniques': [],
        'networkActivity': {
            'dnsQueries': [],
            'connections': [],
        },
    }

    if not output:
        return result

    seen_files = set()
    seen_registry = set()
    seen_dlls = set()
    seen_apis = set()
    seen_techniques = set()

    for line in output.split('\n'):
        # Parse DLL loads: trace:loaddll:Loaded L"..." or Module loaded
        if 'loaddll:' in line or 'Loaded' in line:
            dll_match = re.search(r'L"([^"]+\.(dll|exe))"', line, re.IGNORECASE)
            if dll_match:
                dll_path = dll_match.group(1)
                if dll_path not in seen_dlls:
                    seen_dlls.add(dll_path)
                    result['dlls'].append(dll_path)

        # Parse file operations: trace:file:nt_to_unix_file_name L"..."
        if 'trace:file:' in line:
            # Match Windows paths in L"..." format
            file_match = re.search(r'L"([^"]+)"', line)
            if file_match:
                file_path = file_match.group(1)
                # Convert Wine path format and filter
                if '\\' in file_path and file_path not in seen_files:
                    # Skip system noise paths
                    if not any(skip in file_path.lower() for skip in ['dosdevices', '??\\', 'sandbox']):
                        seen_files.add(file_path)
                        # Clean up path
                        clean_path = file_path.replace('\\??\\', '').replace('\\\\', '\\')
                        if clean_path.lower().endswith('.dll'):
                            if clean_path not in seen_dlls:
                                seen_dlls.add(clean_path)
                                result['dlls'].append(clean_path)
                        else:
                            result['filesystem']['filesOpened'].append(clean_path)

        # Parse registry operations: trace:reg:NtOpenKeyEx/NtCreateKey L"\\Registry\\..."
        if 'trace:reg:' in line:
            reg_match = re.search(r'L"\\\\Registry\\\\([^"]+)"', line)
            if reg_match:
                reg_path = reg_match.group(1)
                # Convert to HKEY format
                if reg_path.startswith('Machine\\'):
                    reg_key = 'HKEY_LOCAL_MACHINE\\' + reg_path[8:]
                elif reg_path.startswith('User\\'):
                    # Extract user key path after SID
                    parts = reg_path.split('\\', 2)
                    if len(parts) > 2:
                        reg_key = 'HKEY_CURRENT_USER\\' + parts[2]
                    else:
                        reg_key = 'HKEY_USERS\\' + reg_path[5:]
                else:
                    reg_key = 'HKEY_' + reg_path

                if reg_key not in seen_registry:
                    seen_registry.add(reg_key)
                    if 'NtSetValue' in line or 'NtCreateKey' in line:
                        result['registry']['keysModified'].append(reg_key)
                    else:
                        result['registry']['keysOpened'].append(reg_key)

        # Parse API calls from relay output: trace:relay:Call MODULE.APIName(...)
        if 'relay:' in line and 'Call' in line:
            # Match API call pattern: Call MODULE.APIName
            api_match = re.search(r'Call\s+(\w+)\.(\w+)', line)
            if api_match:
                module = api_match.group(1)
                api_name = api_match.group(2)
                api_key = f"{module}.{api_name}"

                # Only track interesting APIs (not too noisy)
                if api_name in MITRE_TECHNIQUES and api_key not in seen_apis:
                    seen_apis.add(api_key)

                    # Get MITRE mapping
                    technique = MITRE_TECHNIQUES.get(api_name)
                    if technique:
                        result['apiCalls'].append({
                            'module': module,
                            'api': api_name,
                            'technique': technique['id'],
                            'techniqueName': technique['name'],
                            'tactic': technique['tactic'],
                        })

                        # Track unique techniques
                        tech_key = technique['id']
                        if tech_key not in seen_techniques:
                            seen_techniques.add(tech_key)
                            result['mitreTechniques'].append({
                                'id': technique['id'],
                                'name': technique['name'],
                                'tactic': technique['tactic'],
                            })

        # Parse DNS queries from gethostbyname/getaddrinfo calls
        if 'gethostbyname' in line or 'getaddrinfo' in line:
            # Try to extract hostname from arguments
            host_match = re.search(r'"([a-zA-Z0-9](?:[a-zA-Z0-9\-\.]+[a-zA-Z0-9])?)"', line)
            if host_match:
                hostname = host_match.group(1)
                if hostname and '.' in hostname and hostname not in result['networkActivity']['dnsQueries']:
                    result['networkActivity']['dnsQueries'].append(hostname)

        # Parse socket connect calls for IP addresses
        if 'connect(' in line or 'WSAConnect' in line:
            # Try to extract IP:port from arguments
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:\s]+(\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                port = ip_match.group(2)
                conn = {'ip': ip, 'port': int(port)}
                if conn not in result['networkActivity']['connections']:
                    result['networkActivity']['connections'].append(conn)

    return result


def parse_tcpdump_output(pcap_file: str) -> Dict:
    """Parse tcpdump pcap file to extract network activity"""
    result = {
        'dnsQueries': [],
        'httpRequests': [],
        'connections': [],
        'protocols': set(),
    }

    if not os.path.exists(pcap_file):
        return result

    # Use tcpdump to read pcap in text format
    tcpdump_path = shutil.which('tcpdump')
    if not tcpdump_path:
        return result

    try:
        # Extract DNS queries
        proc = subprocess.run(
            [tcpdump_path, '-r', pcap_file, '-n', 'udp port 53', '-v'],
            capture_output=True, timeout=30
        )
        dns_output = proc.stdout.decode('utf-8', errors='replace')
        for line in dns_output.split('\n'):
            # Match DNS query patterns
            if ' A? ' in line or ' AAAA? ' in line:
                query_match = re.search(r'\s(A\??|AAAA\??)\s+([a-zA-Z0-9\.\-]+)', line)
                if query_match:
                    domain = query_match.group(2).rstrip('.')
                    if domain and domain not in result['dnsQueries']:
                        result['dnsQueries'].append(domain)

        # Extract TCP connections
        proc = subprocess.run(
            [tcpdump_path, '-r', pcap_file, '-n', 'tcp', '-q'],
            capture_output=True, timeout=30
        )
        tcp_output = proc.stdout.decode('utf-8', errors='replace')
        seen_conns = set()
        for line in tcp_output.split('\n'):
            # Match connection patterns: IP > IP.port:
            conn_match = re.search(r'(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)', line)
            if conn_match:
                src_ip, src_port, dst_ip, dst_port = conn_match.groups()
                # Filter out local/internal connections
                if not dst_ip.startswith(('127.', '10.', '192.168.', '172.')):
                    conn_key = f"{dst_ip}:{dst_port}"
                    if conn_key not in seen_conns:
                        seen_conns.add(conn_key)
                        result['connections'].append({
                            'ip': dst_ip,
                            'port': int(dst_port),
                            'protocol': 'tcp'
                        })

        # Detect HTTP traffic
        proc = subprocess.run(
            [tcpdump_path, '-r', pcap_file, '-A', 'tcp port 80 or tcp port 443'],
            capture_output=True, timeout=30
        )
        http_output = proc.stdout.decode('utf-8', errors='replace')
        for line in http_output.split('\n'):
            # Match HTTP request patterns
            if line.startswith(('GET ', 'POST ', 'PUT ', 'HEAD ')):
                parts = line.split(' ')
                if len(parts) >= 2:
                    method = parts[0]
                    path = parts[1]
                    result['httpRequests'].append({
                        'method': method,
                        'path': path
                    })
            # Match Host headers
            if line.lower().startswith('host:'):
                host = line.split(':', 1)[1].strip()
                if host and host not in result['dnsQueries']:
                    result['dnsQueries'].append(host)

        result['protocols'] = list(result['protocols'])

    except Exception as e:
        pass

    return result


def start_network_capture(output_file: str, interface: str = 'any', timeout: int = 30) -> Optional[subprocess.Popen]:
    """Start tcpdump to capture network traffic during sandbox execution"""
    tcpdump_path = shutil.which('tcpdump')
    if not tcpdump_path:
        return None

    try:
        # Start tcpdump in background
        proc = subprocess.Popen(
            [
                tcpdump_path,
                '-i', interface,
                '-w', output_file,
                '-c', '1000',  # Max 1000 packets
                'not port 22',  # Exclude SSH
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return proc
    except Exception:
        return None


def stop_network_capture(proc: Optional[subprocess.Popen]) -> None:
    """Stop tcpdump capture process"""
    if proc:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


# =============================================================================
# Bubblewrap Backend
# =============================================================================

class BubblewrapBackend:
    """Sandbox execution using bubblewrap (bwrap)"""

    def __init__(self, session_dir: str, timeout: int = DEFAULT_TIMEOUT):
        self.session_dir = session_dir
        self.timeout = min(timeout, MAX_TIMEOUT)
        self.work_dir = os.path.join(session_dir, 'work')
        self.output_dir = os.path.join(session_dir, 'output')
        self.screenshots_dir = os.path.join(session_dir, 'screenshots')
        os.makedirs(self.work_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.screenshots_dir, exist_ok=True)

    def _capture_screenshots(self, display_id: str = None, count: int = 3, interval: float = 2.0) -> List[str]:
        """
        Capture screenshots during execution.
        Returns list of base64-encoded PNG images.
        """
        screenshots = []

        # Check if import (ImageMagick) is available
        import_path = shutil.which('import')
        if not import_path:
            return screenshots

        for i in range(count):
            time.sleep(interval)
            screenshot_path = os.path.join(self.screenshots_dir, f'screenshot_{i}.png')

            try:
                # Capture using ImageMagick's import
                cmd = ['import', '-window', 'root', screenshot_path]
                if display_id:
                    cmd = ['env', f'DISPLAY={display_id}'] + cmd

                proc = subprocess.run(cmd, capture_output=True, timeout=5)

                if proc.returncode == 0 and os.path.exists(screenshot_path):
                    # Read and encode screenshot
                    with open(screenshot_path, 'rb') as f:
                        screenshots.append(base64.b64encode(f.read()).decode('utf-8'))
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass

        return screenshots

    def _capture_screenshots_async(self, display_id: str = None, count: int = 3,
                                    interval: float = 2.0, results_list: List = None):
        """Async wrapper for screenshot capture to run in background thread"""
        if results_list is None:
            results_list = []
        captured = self._capture_screenshots(display_id, count, interval)
        results_list.extend(captured)

    def _build_bwrap_args(self, command: List[str], allow_network: bool = False) -> List[str]:
        """Build bubblewrap command arguments"""
        args = ['bwrap']

        # Filesystem isolation - bind necessary directories if they exist
        # Modern Linux distros use symlinks: /bin -> usr/bin, /lib -> usr/lib
        # Bind /usr first, then create symlinks for compatibility
        bind_dirs = [
            ('/usr', '/usr'),
        ]

        # Symlinks for modern filesystem layout (Kali, Ubuntu 22.04+, etc.)
        symlink_dirs = []
        if os.path.islink('/bin'):
            symlink_dirs.append(('usr/bin', '/bin'))
        if os.path.islink('/sbin'):
            symlink_dirs.append(('usr/sbin', '/sbin'))
        if os.path.islink('/lib'):
            symlink_dirs.append(('usr/lib', '/lib'))
        if os.path.islink('/lib64'):
            symlink_dirs.append(('usr/lib64', '/lib64'))

        # Fallback: bind directly if not symlinks (older systems)
        if not os.path.islink('/bin'):
            bind_dirs.append(('/bin', '/bin'))
        if not os.path.islink('/sbin'):
            bind_dirs.append(('/sbin', '/sbin'))
        if not os.path.islink('/lib'):
            bind_dirs.append(('/lib', '/lib'))

        # Add optional directories that may exist
        optional_dirs = [
            '/etc/alternatives',
            '/etc/ld.so.cache',
            '/etc/ld.so.conf',
            '/etc/ld.so.conf.d',
        ]

        # Only add lib64/lib32 if they're real directories, not symlinks
        if os.path.exists('/lib64') and not os.path.islink('/lib64'):
            optional_dirs.append('/lib64')
        if os.path.exists('/lib32') and not os.path.islink('/lib32'):
            optional_dirs.append('/lib32')

        for src, dest in bind_dirs:
            if os.path.exists(src):
                args.extend(['--ro-bind', src, dest])

        # Add symlinks for modern filesystem layout (Kali, Ubuntu 22.04+)
        for target, link_path in symlink_dirs:
            args.extend(['--symlink', target, link_path])

        for dir_path in optional_dirs:
            if os.path.exists(dir_path):
                args.extend(['--ro-bind', dir_path, dir_path])

        # Temporary filesystem
        args.extend([
            '--tmpfs', '/tmp',
            '--tmpfs', '/var/tmp',
            '--tmpfs', '/run',
        ])

        # Working directory
        args.extend([
            '--bind', self.work_dir, '/sandbox',
            '--bind', self.output_dir, '/output',
        ])

        # Isolation options
        args.extend([
            '--unshare-user', '--unshare-pid', '--unshare-net', '--unshare-ipc', '--unshare-uts', '--unshare-cgroup',
            '--die-with-parent',
            '--new-session',
            '--cap-drop', 'ALL',
            '--chdir', '/sandbox',
        ])

        # Additional hardening - block access to sensitive kernel interfaces
        args.extend([
            '--proc', '/proc',           # Mount minimal /proc
            '--dev', '/dev',             # Mount minimal /dev
            '--tmpfs', '/sys',           # Block /sys access
            '--hostname', 'sandbox',     # Isolated hostname
            '--unsetenv', 'HOME',        # Clear sensitive env vars
            '--unsetenv', 'USER',
            '--unsetenv', 'LOGNAME',
            '--setenv', 'PATH', '/usr/bin:/bin',  # Minimal PATH
        ])

        # Seccomp - block dangerous syscalls (if seccomp file exists)
        # Seccomp disabled - bwrap seccomp requires file descriptor, not path
        # TODO: Implement proper seccomp with subprocess fd passing
        # seccomp_filter = os.path.join(os.path.dirname(__file__), 'sandbox_seccomp.json')
        # if os.path.exists(seccomp_filter):
        #     args.extend(['--seccomp', '3', '3<' + seccomp_filter])

        if not allow_network:
            args.extend(['--unshare-net'])

        # Add the actual command
        args.extend(command)

        return args

    def execute_script(self, script_path: str, interpreter: str = None,
                      strace_enabled: bool = True) -> Dict:
        """Execute a script in sandbox with optional strace"""
        result = {
            'success': False,
            'stdout': '',
            'stderr': '',
            'strace_output': '',
            'exit_code': -1,
            'execution_time': 0,
            'error': None,
        }

        # Copy script to work directory
        script_name = os.path.basename(script_path)
        sandbox_script = os.path.join(self.work_dir, script_name)
        shutil.copy2(script_path, sandbox_script)
        os.chmod(sandbox_script, 0o755)

        # Determine interpreter
        if not interpreter:
            ext = os.path.splitext(script_name)[1].lower()
            interpreter_map = {
                '.sh': '/bin/bash',
                '.py': '/usr/bin/python3',
                '.js': '/usr/bin/node',
                '.pl': '/usr/bin/perl',
                '.rb': '/usr/bin/ruby',
            }
            interpreter = interpreter_map.get(ext, '/bin/bash')

        # Build command
        if strace_enabled and _config.detect_capabilities().get('strace', {}).get('available'):
            strace_output_file = os.path.join(self.output_dir, 'strace.log')
            command = [
                'strace', '-f', '-o', '/output/strace.log',
                '-e', 'trace=file,process,network',
                interpreter, f'/sandbox/{script_name}'
            ]
        else:
            command = [interpreter, f'/sandbox/{script_name}']

        # Execute with timeout
        bwrap_args = self._build_bwrap_args(command)

        start_time = datetime.now()
        try:
            # Use timeout and prlimit wrappers for resource control
            # Memory limit: 512MB, CPU time: timeout seconds, File size: 100MB
            prlimit_args = [
                'prlimit',
                f'--as={MEMORY_LIMIT_MB * 1024 * 1024}',  # Virtual memory limit
                f'--fsize={DISK_LIMIT_MB * 1024 * 1024}',  # Max file size
                # Note: --nproc removed - it blocks namespace creation
                f'--nofile=256',  # Max open files
                '--core=0',  # No core dumps
            ]
            timeout_args = ['timeout', '--signal=KILL', str(self.timeout)] + prlimit_args + bwrap_args

            proc = subprocess.run(
                timeout_args,
                capture_output=True,
                timeout=self.timeout + 5,  # Extra buffer for cleanup
                cwd=self.session_dir,
            )

            result['stdout'] = proc.stdout.decode('utf-8', errors='replace')[:200000]
            result['stderr'] = proc.stderr.decode('utf-8', errors='replace')[:200000]
            result['exit_code'] = proc.returncode
            result['success'] = proc.returncode == 0

        except subprocess.TimeoutExpired:
            result['error'] = 'Execution timed out'
            result['exit_code'] = -9
        except Exception as e:
            result['error'] = str(e)

        result['execution_time'] = (datetime.now() - start_time).total_seconds()

        # Read strace output if available
        strace_file = os.path.join(self.output_dir, 'strace.log')
        if os.path.exists(strace_file):
            try:
                with open(strace_file, 'r', errors='replace') as f:
                    result['strace_output'] = f.read()[:100000]
            except Exception:
                pass

        return result

    def execute_command(self, command: List[str], allow_network: bool = False,
                       strace_enabled: bool = True) -> Dict:
        """Execute arbitrary command in sandbox"""
        result = {
            'success': False,
            'stdout': '',
            'stderr': '',
            'strace_output': '',
            'exit_code': -1,
            'execution_time': 0,
            'error': None,
        }

        # Build command with optional strace
        if strace_enabled and _config.detect_capabilities().get('strace', {}).get('available'):
            full_command = [
                'strace', '-f', '-o', '/output/strace.log',
                '-e', 'trace=file,process,network',
            ] + command
        else:
            full_command = command

        bwrap_args = self._build_bwrap_args(full_command, allow_network=allow_network)

        start_time = datetime.now()
        try:
            # Use timeout and prlimit wrappers for resource control
            prlimit_args = [
                'prlimit',
                f'--as={MEMORY_LIMIT_MB * 1024 * 1024}',  # Virtual memory limit
                f'--fsize={DISK_LIMIT_MB * 1024 * 1024}',  # Max file size
                # Note: --nproc removed - it blocks namespace creation
                f'--nofile=256',  # Max open files
                '--core=0',  # No core dumps
            ]
            timeout_args = ['timeout', '--signal=KILL', str(self.timeout)] + prlimit_args + bwrap_args

            proc = subprocess.run(
                timeout_args,
                capture_output=True,
                timeout=self.timeout + 5,
                cwd=self.session_dir,
            )

            result['stdout'] = proc.stdout.decode('utf-8', errors='replace')[:200000]
            result['stderr'] = proc.stderr.decode('utf-8', errors='replace')[:200000]
            result['exit_code'] = proc.returncode
            result['success'] = proc.returncode == 0

        except subprocess.TimeoutExpired:
            result['error'] = 'Execution timed out'
            result['exit_code'] = -9
        except Exception as e:
            result['error'] = str(e)

        result['execution_time'] = (datetime.now() - start_time).total_seconds()

        # Read strace output
        strace_file = os.path.join(self.output_dir, 'strace.log')
        if os.path.exists(strace_file):
            try:
                with open(strace_file, 'r', errors='replace') as f:
                    result['strace_output'] = f.read()[:100000]
            except Exception:
                pass

        return result

    def execute_executable(self, exe_path: str, strace_enabled: bool = True,
                           capture_screenshots: bool = True) -> Dict:
        """Execute a Windows executable using Wine in sandbox"""
        result = {
            'success': False,
            'stdout': '',
            'stderr': '',
            'strace_output': '',
            'exit_code': -1,
            'execution_time': 0,
            'error': None,
            'screenshots': [],
        }

        # Check if Wine is available
        caps = _config.detect_capabilities()
        if not caps.get('wine', {}).get('available'):
            result['error'] = 'Wine is not available for executable analysis'
            return result

        # Copy executable to work directory
        exe_name = os.path.basename(exe_path)
        sandbox_exe = os.path.join(self.work_dir, exe_name)
        shutil.copy2(exe_path, sandbox_exe)

        # Find Wine binary (use wine64 directly to avoid shell wrapper)
        wine_binary = '/usr/lib/wine/wine64'
        if not os.path.exists(wine_binary):
            wine_binary = '/usr/lib/wine/wine'
        if not os.path.exists(wine_binary):
            wine_binary = '/usr/bin/wine'

        # Build Wine command
        wine_command = [wine_binary, f'/sandbox/{exe_name}']

        # Create writable Wine prefix in work directory
        # Copy from template prefix if available to avoid Wine initialization delay
        wine_prefix = os.path.join(self.work_dir, '.wine')

        # Look for Wine prefix template in order of preference
        template_prefix = None
        for template_path in [
            '/opt/shieldtier/wine_prefix',  # Production template
            os.path.expanduser('~/.wine'),   # User's Wine prefix
            '/home/shieldtier/.wine',        # Service user's Wine prefix
        ]:
            if os.path.exists(template_path) and os.path.isdir(template_path):
                template_prefix = template_path
                break

        if template_prefix and os.path.exists(os.path.join(template_prefix, 'system.reg')):
            # Copy essential Wine prefix files for faster startup
            # IMPORTANT: use symlinks=True to preserve symlinks and avoid copying
            # entire mounted drives (like CD-ROM or ISO mounts)
            try:
                # Copy the wine prefix (this is faster than Wine initialization)
                shutil.copytree(template_prefix, wine_prefix, dirs_exist_ok=True, symlinks=True)
            except Exception as e:
                # Fallback to empty prefix if copy fails
                os.makedirs(wine_prefix, exist_ok=True)
        else:
            os.makedirs(wine_prefix, exist_ok=True)

        # Build bwrap args - order matters!
        args = [
            'bwrap',
            '--unshare-user', '--unshare-pid', '--unshare-net', '--unshare-ipc', '--unshare-uts', '--unshare-cgroup',
            '--die-with-parent',
            '--new-session',
        ]

        # Filesystem isolation - bind necessary directories
        # Modern Linux distros use symlinks: /bin -> usr/bin, /lib -> usr/lib
        bind_dirs = [
            ('/usr', '/usr'),
        ]

        # Symlinks for modern filesystem layout (Kali, Ubuntu 22.04+, etc.)
        symlink_dirs = []
        if os.path.islink('/bin'):
            symlink_dirs.append(('usr/bin', '/bin'))
        if os.path.islink('/sbin'):
            symlink_dirs.append(('usr/sbin', '/sbin'))
        if os.path.islink('/lib'):
            symlink_dirs.append(('usr/lib', '/lib'))
        if os.path.islink('/lib64'):
            symlink_dirs.append(('usr/lib64', '/lib64'))

        # Fallback: bind directly if not symlinks (older systems)
        if not os.path.islink('/bin'):
            bind_dirs.append(('/bin', '/bin'))
        if not os.path.islink('/sbin'):
            bind_dirs.append(('/sbin', '/sbin'))
        if not os.path.islink('/lib'):
            bind_dirs.append(('/lib', '/lib'))

        optional_dirs = [
            '/etc/alternatives',
            '/etc/ld.so.cache',
            '/etc/ld.so.conf',
            '/etc/ld.so.conf.d',
            '/etc/fonts',  # For Wine fontconfig
        ]

        # Only add lib64/lib32 if they're real directories, not symlinks
        if os.path.exists('/lib64') and not os.path.islink('/lib64'):
            optional_dirs.append('/lib64')
        if os.path.exists('/lib32') and not os.path.islink('/lib32'):
            optional_dirs.append('/lib32')

        for src, dest in bind_dirs:
            if os.path.exists(src):
                args.extend(['--ro-bind', src, dest])

        # Add symlinks for modern filesystem layout
        for target, link_path in symlink_dirs:
            args.extend(['--symlink', target, link_path])

        for dir_path in optional_dirs:
            if os.path.exists(dir_path):
                args.extend(['--ro-bind', dir_path, dir_path])

        # Wine requires its own directories
        wine_dirs = [
            '/opt/wine-stable',
            '/opt/wine',
        ]
        for wine_dir in wine_dirs:
            if os.path.exists(wine_dir):
                args.extend(['--ro-bind', wine_dir, wine_dir])

        # Working directory and Wine prefix
        args.extend([
            '--bind', self.work_dir, '/sandbox',
            '--bind', self.output_dir, '/output',
            '--bind', wine_prefix, '/sandbox/.wine',
        ])

        # Temporary filesystem and special mounts
        args.extend([
            '--tmpfs', '/tmp',
            '--tmpfs', '/var/tmp',
            '--tmpfs', '/run',
            '--tmpfs', '/sys',
            '--proc', '/proc',
            '--dev', '/dev',
        ])

        # Environment and final options
        # Enable Wine debug channels to capture behavioral data
        # +loaddll: DLL loading, +file: file access, +reg: registry access
        # +relay: API call tracing (for detailed API monitoring)
        # +seh: exception handling, +module: module events
        wine_debug = '+loaddll'  # Minimal debug to capture DLL loads without flooding output
        args.extend([
            '--cap-drop', 'ALL',
            '--hostname', 'sandbox',
            '--chdir', '/sandbox',
            '--setenv', 'WINEPREFIX', '/sandbox/.wine',
            '--setenv', 'WINEDEBUG', wine_debug,
            '--setenv', 'DISPLAY', '',
            '--setenv', 'PATH', '/usr/bin:/bin:/usr/lib/wine',
        ])

        # Add strace if enabled
        if strace_enabled and caps.get('strace', {}).get('available'):
            command = [
                'strace', '-f', '-o', '/output/strace.log',
                '-e', 'trace=file,process,network',
            ] + wine_command
        else:
            command = wine_command

        args.extend(command)

        start_time = datetime.now()

        # Start network capture if tcpdump is available
        pcap_file = os.path.join(self.output_dir, 'capture.pcap')
        network_capture_proc = start_network_capture(pcap_file, timeout=self.timeout)

        # Start screenshot capture in background thread if enabled
        screenshot_results = []
        screenshot_thread = None
        if capture_screenshots:
            # Calculate screenshot intervals based on timeout
            num_screenshots = min(3, max(1, self.timeout // 10))
            interval = max(2.0, self.timeout / (num_screenshots + 1))

            screenshot_thread = threading.Thread(
                target=self._capture_screenshots_async,
                args=(None, num_screenshots, interval, screenshot_results),
                daemon=True
            )
            screenshot_thread.start()

        try:
            # Use timeout only, apply prlimit inside if needed
            timeout_args = ['timeout', '--signal=KILL', str(self.timeout)] + args

            proc = subprocess.run(
                timeout_args,
                capture_output=True,
                timeout=self.timeout + 5,
                cwd=self.session_dir,
            )

            result['stdout'] = proc.stdout.decode('utf-8', errors='replace')[:200000]
            result['stderr'] = proc.stderr.decode('utf-8', errors='replace')[:200000]
            result['exit_code'] = proc.returncode
            # Wine returns various exit codes, consider it successful if it ran
            result['success'] = proc.returncode != -9

        except subprocess.TimeoutExpired:
            result['error'] = 'Execution timed out'
            result['exit_code'] = -9
        except Exception as e:
            result['error'] = str(e)

        result['execution_time'] = (datetime.now() - start_time).total_seconds()

        # Stop network capture
        stop_network_capture(network_capture_proc)

        # Wait for screenshot thread to complete (with timeout)
        if screenshot_thread and screenshot_thread.is_alive():
            screenshot_thread.join(timeout=5)

        # Add captured screenshots to result
        result['screenshots'] = screenshot_results

        # Read strace output
        strace_file = os.path.join(self.output_dir, 'strace.log')
        if os.path.exists(strace_file):
            try:
                with open(strace_file, 'r', errors='replace') as f:
                    result['strace_output'] = f.read()[:100000]
            except Exception:
                pass

        # Parse Wine debug output for behavioral data (including API calls)
        wine_output = result.get('stderr', '') + result.get('stdout', '')
        behavioral_data = parse_wine_debug_output(wine_output)
        result['filesystemChanges'] = behavioral_data.get('filesystem', {})
        result['registryChanges'] = behavioral_data.get('registry', {})
        result['dllLoads'] = behavioral_data.get('dlls', [])
        result['apiCalls'] = behavioral_data.get('apiCalls', [])
        result['mitreTechniques'] = behavioral_data.get('mitreTechniques', [])

        # Parse network capture from tcpdump
        network_from_wine = behavioral_data.get('networkActivity', {})
        network_from_pcap = parse_tcpdump_output(pcap_file)

        # Merge network activity from Wine debug and tcpdump
        result['networkActivity'] = {
            'dnsQueries': list(set(
                network_from_wine.get('dnsQueries', []) +
                network_from_pcap.get('dnsQueries', [])
            )),
            'connections': network_from_wine.get('connections', []) + network_from_pcap.get('connections', []),
            'httpRequests': network_from_pcap.get('httpRequests', []),
        }

        return result


# =============================================================================
# Docker Backend (for when Docker is available)
# =============================================================================

class DockerBackend:
    """Sandbox execution using Docker"""

    def __init__(self, session_dir: str, timeout: int = DEFAULT_TIMEOUT):
        self.session_dir = session_dir
        self.timeout = min(timeout, MAX_TIMEOUT)
        self.work_dir = os.path.join(session_dir, 'work')
        self.output_dir = os.path.join(session_dir, 'output')
        os.makedirs(self.work_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)
        self.container_name = f"sandbox_{uuid.uuid4().hex[:8]}"

    def execute_script(self, script_path: str, interpreter: str = None,
                      image: str = 'python:3.11-slim') -> Dict:
        """Execute script in Docker container"""
        result = {
            'success': False,
            'stdout': '',
            'stderr': '',
            'exit_code': -1,
            'execution_time': 0,
            'error': None,
        }

        # Copy script to work directory
        script_name = os.path.basename(script_path)
        sandbox_script = os.path.join(self.work_dir, script_name)
        shutil.copy2(script_path, sandbox_script)

        # Determine interpreter
        if not interpreter:
            ext = os.path.splitext(script_name)[1].lower()
            interpreter_map = {
                '.sh': '/bin/bash',
                '.py': 'python3',
                '.js': 'node',
            }
            interpreter = interpreter_map.get(ext, '/bin/bash')

        # Docker command
        docker_args = [
            'docker', 'run',
            '--rm',
            '--name', self.container_name,
            '--network', 'none',  # No network
            '--memory', f'{MEMORY_LIMIT_MB}m',
            '--cpus', '0.5',
            '--read-only',
            '--tmpfs', '/tmp:size=100m',
            '-v', f'{self.work_dir}:/sandbox:ro',
            '-v', f'{self.output_dir}:/output',
            '-w', '/sandbox',
            image,
            interpreter, f'/sandbox/{script_name}'
        ]

        start_time = datetime.now()
        try:
            proc = subprocess.run(
                docker_args,
                capture_output=True,
                timeout=self.timeout + 10,
            )

            result['stdout'] = proc.stdout.decode('utf-8', errors='replace')[:200000]
            result['stderr'] = proc.stderr.decode('utf-8', errors='replace')[:200000]
            result['exit_code'] = proc.returncode
            result['success'] = proc.returncode == 0

        except subprocess.TimeoutExpired:
            # Kill container
            subprocess.run(['docker', 'kill', self.container_name], capture_output=True)
            result['error'] = 'Execution timed out'
            result['exit_code'] = -9
        except Exception as e:
            result['error'] = str(e)

        result['execution_time'] = (datetime.now() - start_time).total_seconds()
        return result

    def execute_executable(self, exe_path: str, strace_enabled: bool = False, image: str = 'scottyhardy/docker-wine:latest') -> Dict:
        """Execute a Windows executable using Wine in Docker"""
        result = {
            'success': False,
            'stdout': '',
            'stderr': '',
            'exit_code': -1,
            'execution_time': 0,
            'error': None,
        }

        # Copy executable to work directory
        exe_name = os.path.basename(exe_path)
        sandbox_exe = os.path.join(self.work_dir, exe_name)
        shutil.copy2(exe_path, sandbox_exe)

        # Docker command with Wine image
        # Enable Wine debug channels to capture behavioral data
        # +loaddll: DLL loading, +file: file access, +reg: registry, +relay: API calls
        wine_debug = '+loaddll'  # Minimal debug to capture DLL loads without flooding output
        docker_args = [
            'docker', 'run',
            '--rm',
            '--name', self.container_name,
            '--network', 'none',
            '--memory', f'{MEMORY_LIMIT_MB}m',
            '--cpus', '0.5',
            '-e', f'WINEDEBUG={wine_debug}',
            '-e', 'DISPLAY=',
            '-v', f'{self.work_dir}:/sandbox:ro',
            '-v', f'{self.output_dir}:/output',
            '-w', '/sandbox',
            image,
            'wine', f'/sandbox/{exe_name}'
        ]

        start_time = datetime.now()
        try:
            proc = subprocess.run(
                docker_args,
                capture_output=True,
                timeout=self.timeout + 10,
            )

            result['stdout'] = proc.stdout.decode('utf-8', errors='replace')[:200000]
            result['stderr'] = proc.stderr.decode('utf-8', errors='replace')[:200000]
            result['exit_code'] = proc.returncode
            # Wine returns various exit codes, consider it successful if it ran
            result['success'] = proc.returncode != -9

        except subprocess.TimeoutExpired:
            subprocess.run(['docker', 'kill', self.container_name], capture_output=True)
            result['error'] = 'Execution timed out'
            result['exit_code'] = -9
        except Exception as e:
            result['error'] = str(e)

        result['execution_time'] = (datetime.now() - start_time).total_seconds()

        # Parse Wine debug output for behavioral data (including API calls)
        wine_output = result.get('stderr', '') + result.get('stdout', '')
        behavioral_data = parse_wine_debug_output(wine_output)
        result['filesystemChanges'] = behavioral_data.get('filesystem', {})
        result['registryChanges'] = behavioral_data.get('registry', {})
        result['dllLoads'] = behavioral_data.get('dlls', [])
        result['apiCalls'] = behavioral_data.get('apiCalls', [])
        result['mitreTechniques'] = behavioral_data.get('mitreTechniques', [])
        result['networkActivity'] = behavioral_data.get('networkActivity', {})

        return result

    def cleanup(self):
        """Clean up Docker container"""
        try:
            subprocess.run(
                ['docker', 'rm', '-f', self.container_name],
                capture_output=True,
                timeout=10
            )
        except Exception:
            pass


# =============================================================================
# Sandbox Session
# =============================================================================

class SandboxSession:
    """Manages a sandbox analysis session"""

    def __init__(self, session_id: str = None, timeout: int = DEFAULT_TIMEOUT):
        self.session_id = session_id or uuid.uuid4().hex
        self.session_dir = os.path.join(SESSIONS_DIR, self.session_id)
        self.timeout = min(timeout, MAX_TIMEOUT)
        self.created_at = datetime.now()
        self.status = 'initializing'
        self.results = {}
        self.ioc_collector = IOCCollector()

        # Create session directory
        os.makedirs(self.session_dir, exist_ok=True)

        # Select backend
        caps = _config.detect_capabilities()
        if caps.get('bubblewrap', {}).get('available'):
            self.backend = BubblewrapBackend(self.session_dir, timeout)
            self.backend_type = 'bubblewrap'
        elif caps.get('docker', {}).get('functional'):
            self.backend = DockerBackend(self.session_dir, timeout)
            self.backend_type = 'docker'
        else:
            self.backend = None
            self.backend_type = 'none'
            self.status = 'error'
            self.results['error'] = 'No sandbox backend available'

    def analyze_file(self, file_path: str, file_type: str = None) -> Dict:
        """Analyze a file in the sandbox"""
        self.status = 'analyzing'

        result = {
            'sessionId': self.session_id,
            'fileAnalysis': {},
            'execution': {},
            'iocs': {},
            'riskScore': 0,
            'riskLevel': 'Low',
            'status': 'completed',
        }

        if not self.backend:
            result['status'] = 'error'
            result['error'] = 'No sandbox backend available'
            return result

        try:
            # Detect file type if not specified
            if not file_type:
                file_type = self._detect_file_type(file_path)

            result['fileAnalysis'] = {
                'detectedType': file_type,
                'fileName': os.path.basename(file_path),
                'fileSize': os.path.getsize(file_path),
                'hashes': self._calculate_hashes(file_path),
            }

            # Execute based on file type
            if file_type in ('script', 'bash_script', 'python_script', 'javascript'):
                exec_result = self.backend.execute_script(file_path)
                result['execution'] = exec_result

                # Extract IOCs from execution output
                self.ioc_collector.extract_from_text(exec_result.get('stdout', ''))
                self.ioc_collector.extract_from_text(exec_result.get('stderr', ''))
                if exec_result.get('strace_output'):
                    self.ioc_collector.extract_from_strace(exec_result['strace_output'])

            elif file_type == 'pdf':
                result['execution'] = self._analyze_pdf(file_path)

            elif file_type == 'executable':
                # Static PE analysis (always performed)
                pe_analysis = self._analyze_pe(file_path)
                result['peAnalysis'] = pe_analysis

                # Update file analysis with PE-specific info if available
                if pe_analysis.get('isPE'):
                    result['fileAnalysis']['fileType'] = pe_analysis.get('basicProperties', {}).get('fileType', 'executable')
                    result['fileAnalysis']['magic'] = pe_analysis.get('basicProperties', {}).get('magic', '')
                    result['fileAnalysis']['imphash'] = pe_analysis.get('basicProperties', {}).get('imphash', '')

                # Check if dynamic execution is supported
                caps = _config.detect_capabilities()
                supported = caps.get('supported_types', {}).get('executables', False)

                if not supported:
                    result['execution'] = {
                        'success': False,
                        'error': 'Dynamic analysis requires Wine (and Docker for full support). Static PE analysis completed.',
                        'staticOnly': True
                    }
                else:
                    # Disable strace for executables (Wine+strace is very slow)
                    exec_result = self.backend.execute_executable(file_path, strace_enabled=False)
                    result['execution'] = exec_result

                    # Extract IOCs from execution output
                    self.ioc_collector.extract_from_text(exec_result.get('stdout', ''))
                    self.ioc_collector.extract_from_text(exec_result.get('stderr', ''))
                    if exec_result.get('strace_output'):
                        self.ioc_collector.extract_from_strace(exec_result['strace_output'])

            else:
                result['execution'] = {
                    'success': False,
                    'error': f'Unsupported file type: {file_type}'
                }

            # Collect IOCs
            result['iocs'] = self.ioc_collector.to_dict()

            # Calculate risk score
            result['riskScore'], result['riskLevel'] = self._calculate_risk_score(result)

            # Generate human-readable summary
            result['summary'] = self._generate_summary(result)

        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)

        self.status = 'completed'
        self.results = result
        return result

    def _generate_summary(self, result: Dict) -> Dict:
        """Generate a human-readable summary of the analysis"""
        file_info = result.get('fileAnalysis', {})
        execution = result.get('execution', {})
        iocs = result.get('iocs', {})
        pe_analysis = result.get('peAnalysis', {})
        risk_score = result.get('riskScore', 0)
        risk_level = result.get('riskLevel', 'Unknown')

        # File type descriptions
        type_descriptions = {
            'executable': 'Windows Executable (PE)',
            'script': 'Script file',
            'bash_script': 'Bash/Shell script',
            'python_script': 'Python script',
            'javascript': 'JavaScript file',
            'pdf': 'PDF document',
            'document': 'Office document',
            'unknown': 'Unknown file type'
        }

        file_type = file_info.get('detectedType', 'unknown')
        file_type_desc = type_descriptions.get(file_type, file_type)

        # Use PE analysis type if available
        if pe_analysis.get('isPE'):
            file_type_desc = pe_analysis.get('basicProperties', {}).get('fileType', file_type_desc)

        # Build findings list
        findings = []
        behaviors = []

        # Add PE analysis findings
        if pe_analysis.get('isPE'):
            header = pe_analysis.get('header', {})
            findings.append(f"Target: {header.get('targetMachine', 'Unknown')}")
            findings.append(f"Compiled: {header.get('compilationTimestamp', 'Unknown')}")
            findings.append(f"Sections: {header.get('numberOfSections', 0)}")

            # Add PE detections
            for detection in pe_analysis.get('detections', []):
                behaviors.append(detection)

            # Check for packing
            packed = pe_analysis.get('signatures', {}).get('packed', {})
            if packed.get('detected'):
                behaviors.append(f"Packer detected: {packed.get('name', 'Unknown')}")

            # Check imports count
            total_imports = sum(len(i.get('functions', [])) for i in pe_analysis.get('imports', []))
            if total_imports > 0:
                findings.append(f"Imports: {len(pe_analysis.get('imports', []))} DLLs, {total_imports} functions")

        # Check execution status
        if execution.get('success'):
            exec_time = execution.get('execution_time', 0)
            exit_code = execution.get('exit_code', -1)

            if exit_code == 0:
                findings.append(f"Program executed successfully in {exec_time:.1f} seconds")
            else:
                findings.append(f"Program exited with code {exit_code} after {exec_time:.1f} seconds")

            # Analyze stdout/stderr for behaviors
            stdout = execution.get('stdout', '')
            stderr = execution.get('stderr', '')
            output = stdout + stderr

            # Check for common behaviors
            if 'network' in output.lower() or 'connect' in output.lower():
                behaviors.append("Attempted network connection")
            if 'registry' in output.lower():
                behaviors.append("Registry access detected")
            if 'file not found' in output.lower() or 'cannot be run' in output.lower():
                behaviors.append("File execution failed (missing dependencies)")
            if 'permission denied' in output.lower():
                behaviors.append("Permission issues encountered")
            if 'syswow64' in output.lower() or 'wine32' in output.lower():
                behaviors.append("32-bit subsystem required (wine32 not installed)")

        elif execution.get('error'):
            findings.append(f"Execution failed: {execution.get('error')}")

        # Analyze IOCs
        ioc_summary = iocs.get('summary', {})
        total_ips = ioc_summary.get('totalIPs', 0)
        total_urls = ioc_summary.get('totalURLs', 0)
        total_domains = ioc_summary.get('totalDomains', 0)

        if total_ips > 0:
            findings.append(f"Found {total_ips} IP address(es) in output")
            behaviors.append("Network indicators detected")
        if total_urls > 0:
            findings.append(f"Found {total_urls} URL(s) in output")
            behaviors.append("Web communication indicators")
        if total_domains > 0:
            # Filter out common Windows system files from domain count
            real_domains = [d for d in iocs.get('domains', [])
                          if not d.endswith('.exe') and not d.endswith('.dll')]
            if real_domains:
                findings.append(f"Found {len(real_domains)} domain(s): {', '.join(real_domains[:3])}")

        # Risk assessment text
        risk_assessments = {
            'Critical': "This file exhibits highly suspicious behavior and should be considered dangerous. Do not execute on production systems.",
            'High': "This file shows multiple concerning indicators. Exercise extreme caution and investigate further before allowing.",
            'Medium': "This file has some suspicious characteristics. Review the detailed findings before making a decision.",
            'Low': "This file shows minor suspicious indicators. Likely safe but verify the source.",
            'Clean': "No significant malicious indicators detected. File appears to be safe based on dynamic analysis."
        }

        # Build verdict
        if risk_level == 'Critical':
            verdict = "MALICIOUS - High confidence"
        elif risk_level == 'High':
            verdict = "SUSPICIOUS - Likely malicious"
        elif risk_level == 'Medium':
            verdict = "SUSPICIOUS - Requires investigation"
        elif risk_level == 'Low':
            verdict = "LIKELY SAFE - Minor concerns"
        else:
            verdict = "CLEAN - No threats detected"

        # Format file size
        file_size = file_info.get('fileSize', 0)
        if file_size >= 1024 * 1024:
            size_str = f"{file_size / (1024*1024):.2f} MB"
        elif file_size >= 1024:
            size_str = f"{file_size / 1024:.2f} KB"
        else:
            size_str = f"{file_size} bytes"

        # Build file info with PE details if available
        file_info_summary = {
            'name': file_info.get('fileName', 'Unknown'),
            'type': file_type_desc,
            'size': size_str,
            'md5': file_info.get('hashes', {}).get('md5', 'N/A'),
            'sha1': file_info.get('hashes', {}).get('sha1', 'N/A'),
            'sha256': file_info.get('hashes', {}).get('sha256', 'N/A')
        }

        # Add PE-specific info
        if pe_analysis.get('isPE'):
            pe_props = pe_analysis.get('basicProperties', {})
            pe_header = pe_analysis.get('header', {})
            file_info_summary['imphash'] = pe_props.get('imphash', 'N/A')
            file_info_summary['magic'] = pe_props.get('magic', '')
            file_info_summary['targetMachine'] = pe_header.get('targetMachine', 'Unknown')
            file_info_summary['compilationTimestamp'] = pe_header.get('compilationTimestamp', 'Unknown')
            file_info_summary['entryPoint'] = pe_header.get('entryPoint', 'N/A')
            file_info_summary['subsystem'] = pe_header.get('subsystem', 'Unknown')

        return {
            'verdict': verdict,
            'riskAssessment': risk_assessments.get(risk_level, "Analysis complete."),
            'fileInfo': file_info_summary,
            'findings': findings if findings else ["No significant activity detected during execution"],
            'behaviors': behaviors if behaviors else ["No suspicious behaviors observed"],
            'recommendations': self._get_recommendations(risk_level, file_type, behaviors)
        }

    def _get_recommendations(self, risk_level: str, file_type: str, behaviors: List[str]) -> List[str]:
        """Generate recommendations based on analysis results"""
        recommendations = []

        if risk_level in ('Critical', 'High'):
            recommendations.append("Do NOT execute this file on any production system")
            recommendations.append("Submit to additional malware analysis services (VirusTotal, Any.Run)")
            recommendations.append("Block the associated hashes in your security tools")
            recommendations.append("Check if this file was distributed to other systems")
        elif risk_level == 'Medium':
            recommendations.append("Investigate the source of this file")
            recommendations.append("Run additional scans before allowing execution")
            recommendations.append("Monitor for similar files in your environment")
        elif risk_level == 'Low':
            recommendations.append("Verify the file source is trusted")
            recommendations.append("Consider running in an isolated environment first")
        else:
            recommendations.append("File appears safe for normal use")
            recommendations.append("Always verify software sources before installation")

        # Add type-specific recommendations
        if file_type == 'executable':
            recommendations.append("Check digital signature if available")
        if 'network' in ' '.join(behaviors).lower():
            recommendations.append("Review firewall logs for related connections")

        return recommendations[:5]  # Limit to 5 recommendations

    def _detect_file_type(self, file_path: str) -> str:
        """Detect file type from magic bytes and extension"""
        ext = os.path.splitext(file_path)[1].lower()

        # Check by extension first
        if ext in SCRIPT_EXTENSIONS:
            if ext == '.py':
                return 'python_script'
            elif ext == '.js':
                return 'javascript'
            elif ext in ('.sh', '.bash'):
                return 'bash_script'
            return 'script'
        elif ext in EXECUTABLE_EXTENSIONS:
            return 'executable'
        elif ext in DOCUMENT_EXTENSIONS:
            return 'document'
        elif ext in PDF_EXTENSIONS:
            return 'pdf'

        # Check magic bytes
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)

            for magic, ftype in MAGIC_SIGNATURES.items():
                if header.startswith(magic):
                    return ftype
        except Exception:
            pass

        return 'unknown'

    def _calculate_hashes(self, file_path: str) -> Dict:
        """Calculate file hashes"""
        hashes = {}
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                hashes['md5'] = hashlib.md5(data).hexdigest()
                hashes['sha1'] = hashlib.sha1(data).hexdigest()
                hashes['sha256'] = hashlib.sha256(data).hexdigest()
        except Exception:
            pass
        return hashes

    def _analyze_pe(self, file_path: str) -> Dict:
        """Analyze PE (Windows executable) file - VT-style analysis"""
        if not PE_ANALYSIS_AVAILABLE:
            return {'error': 'PE analysis not available (pefile not installed)'}

        result = {
            'isPE': False,
            'basicProperties': {},
            'header': {},
            'sections': [],
            'imports': [],
            'exports': [],
            'resources': [],
            'signatures': {},
            'detections': []
        }

        try:
            pe = pefile.PE(file_path)
            result['isPE'] = True

            # Read raw file for hash calculations
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # Basic Properties - Multiple hash types
            result['basicProperties'] = {
                'md5': hashlib.md5(file_data).hexdigest(),
                'sha1': hashlib.sha1(file_data).hexdigest(),
                'sha256': hashlib.sha256(file_data).hexdigest(),
                'imphash': pe.get_imphash() if hasattr(pe, 'get_imphash') else None,
                'fileSize': len(file_data),
                'fileSizeFormatted': self._format_file_size(len(file_data)),
            }

            # Machine type mapping
            machine_types = {
                0x14c: 'x86 (i386)',
                0x8664: 'x64 (AMD64)',
                0x1c0: 'ARM',
                0xaa64: 'ARM64',
                0x200: 'IA64',
            }

            # Subsystem mapping
            subsystems = {
                0: 'Unknown',
                1: 'Native',
                2: 'Windows GUI',
                3: 'Windows Console',
                5: 'OS/2 Console',
                7: 'POSIX Console',
                9: 'Windows CE',
                10: 'EFI Application',
                11: 'EFI Boot Service Driver',
                12: 'EFI Runtime Driver',
                13: 'EFI ROM',
                14: 'Xbox',
                16: 'Windows Boot Application',
            }

            # Header information
            machine = pe.FILE_HEADER.Machine
            timestamp = pe.FILE_HEADER.TimeDateStamp
            compilation_time = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC') if timestamp else 'Unknown'

            result['header'] = {
                'targetMachine': machine_types.get(machine, f'Unknown (0x{machine:x})'),
                'machineHex': f'0x{machine:x}',
                'compilationTimestamp': compilation_time,
                'compilationTimestampRaw': timestamp,
                'entryPoint': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'entryPointRaw': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                'imageBase': hex(pe.OPTIONAL_HEADER.ImageBase),
                'subsystem': subsystems.get(pe.OPTIONAL_HEADER.Subsystem, 'Unknown'),
                'subsystemRaw': pe.OPTIONAL_HEADER.Subsystem,
                'numberOfSections': pe.FILE_HEADER.NumberOfSections,
                'characteristics': self._parse_pe_characteristics(pe.FILE_HEADER.Characteristics),
                'dllCharacteristics': self._parse_dll_characteristics(pe.OPTIONAL_HEADER.DllCharacteristics),
            }

            # Determine file type
            is_dll = pe.FILE_HEADER.Characteristics & 0x2000
            is_64bit = machine == 0x8664
            subsystem_name = subsystems.get(pe.OPTIONAL_HEADER.Subsystem, 'Unknown')

            if is_dll:
                file_type = f"Win{'64' if is_64bit else '32'} DLL"
            else:
                file_type = f"Win{'64' if is_64bit else '32'} EXE"

            result['basicProperties']['fileType'] = file_type
            result['basicProperties']['magic'] = f"PE{'64' if is_64bit else '32'}+ executable ({subsystem_name}) {'x86-64' if is_64bit else 'x86'}, for MS Windows"

            # Sections analysis
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
                section_data = section.get_data()
                entropy = self._calculate_entropy(section_data)

                section_info = {
                    'name': section_name,
                    'virtualAddress': hex(section.VirtualAddress),
                    'virtualSize': section.Misc_VirtualSize,
                    'rawSize': section.SizeOfRawData,
                    'entropy': round(entropy, 2),
                    'md5': hashlib.md5(section_data).hexdigest() if section_data else None,
                    'characteristics': self._parse_section_characteristics(section.Characteristics),
                }

                # Flag suspicious sections
                if entropy > 7.0:
                    section_info['suspicious'] = 'High entropy (possibly packed/encrypted)'
                    result['detections'].append(f"High entropy section: {section_name} ({entropy:.2f})")
                if section_name not in ['.text', '.data', '.rdata', '.rsrc', '.reloc', '.pdata', '.bss', '.edata', '.idata', '.tls']:
                    section_info['unusual'] = True
                    if not section_name.startswith('.'):
                        result['detections'].append(f"Unusual section name: {section_name}")

                result['sections'].append(section_info)

            # Imports analysis
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='replace')
                    functions = []
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='replace')
                            functions.append({
                                'name': func_name,
                                'address': hex(imp.address) if imp.address else None,
                                'ordinal': imp.ordinal
                            })
                            # Flag suspicious imports
                            suspicious_funcs = ['VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory',
                                              'CreateRemoteThread', 'NtUnmapViewOfSection', 'IsDebuggerPresent',
                                              'GetProcAddress', 'LoadLibraryA', 'LoadLibraryW']
                            if func_name in suspicious_funcs:
                                result['detections'].append(f"Suspicious import: {dll_name}!{func_name}")
                        else:
                            functions.append({
                                'name': f'Ordinal {imp.ordinal}',
                                'ordinal': imp.ordinal
                            })

                    result['imports'].append({
                        'dll': dll_name,
                        'functions': functions,
                        'functionCount': len(functions)
                    })

            # Exports analysis
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        result['exports'].append({
                            'name': exp.name.decode('utf-8', errors='replace'),
                            'ordinal': exp.ordinal,
                            'address': hex(exp.address) if exp.address else None
                        })

            # Resources analysis (limited)
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                resource_types = {
                    1: 'Cursor', 2: 'Bitmap', 3: 'Icon', 4: 'Menu', 5: 'Dialog',
                    6: 'String', 7: 'FontDir', 8: 'Font', 9: 'Accelerator',
                    10: 'RCData', 11: 'MessageTable', 14: 'IconGroup', 16: 'Version',
                    24: 'Manifest'
                }
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    type_name = resource_types.get(resource_type.id, f'Type_{resource_type.id}')
                    if hasattr(resource_type, 'directory'):
                        count = len(resource_type.directory.entries)
                        result['resources'].append({
                            'type': type_name,
                            'typeId': resource_type.id,
                            'count': count
                        })

            # Check for common packers/protectors
            result['signatures']['packed'] = self._detect_packer(pe, file_data)

            # Extract suspicious strings for reverse shell / malware detection
            result['suspiciousStrings'] = self._extract_suspicious_strings(file_data)

            # Add detections based on suspicious strings
            for finding in result['suspiciousStrings'].get('findings', []):
                result['detections'].append(finding)

            pe.close()

        except pefile.PEFormatError as e:
            result['error'] = f'Invalid PE format: {str(e)}'
        except Exception as e:
            result['error'] = f'PE analysis error: {str(e)}'

        return result

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        entropy = 0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data)
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        return entropy

    def _format_file_size(self, size: int) -> str:
        """Format file size in human-readable format"""
        if size >= 1024 * 1024:
            return f"{size / (1024*1024):.2f} MB ({size:,} bytes)"
        elif size >= 1024:
            return f"{size / 1024:.2f} KB ({size:,} bytes)"
        return f"{size} bytes"

    def _parse_pe_characteristics(self, chars: int) -> List[str]:
        """Parse PE characteristics flags"""
        flags = []
        char_map = {
            0x0001: 'RELOCS_STRIPPED',
            0x0002: 'EXECUTABLE_IMAGE',
            0x0004: 'LINE_NUMS_STRIPPED',
            0x0008: 'LOCAL_SYMS_STRIPPED',
            0x0020: 'LARGE_ADDRESS_AWARE',
            0x0100: '32BIT_MACHINE',
            0x0200: 'DEBUG_STRIPPED',
            0x2000: 'DLL',
        }
        for flag, name in char_map.items():
            if chars & flag:
                flags.append(name)
        return flags

    def _parse_dll_characteristics(self, chars: int) -> List[str]:
        """Parse DLL characteristics flags"""
        flags = []
        char_map = {
            0x0020: 'HIGH_ENTROPY_VA',
            0x0040: 'DYNAMIC_BASE (ASLR)',
            0x0080: 'FORCE_INTEGRITY',
            0x0100: 'NX_COMPAT (DEP)',
            0x0200: 'NO_ISOLATION',
            0x0400: 'NO_SEH',
            0x0800: 'NO_BIND',
            0x1000: 'APPCONTAINER',
            0x2000: 'WDM_DRIVER',
            0x4000: 'GUARD_CF',
            0x8000: 'TERMINAL_SERVER_AWARE',
        }
        for flag, name in char_map.items():
            if chars & flag:
                flags.append(name)
        return flags

    def _parse_section_characteristics(self, chars: int) -> List[str]:
        """Parse section characteristics"""
        flags = []
        char_map = {
            0x00000020: 'CODE',
            0x00000040: 'INITIALIZED_DATA',
            0x00000080: 'UNINITIALIZED_DATA',
            0x02000000: 'DISCARDABLE',
            0x04000000: 'NOT_CACHED',
            0x08000000: 'NOT_PAGED',
            0x10000000: 'SHARED',
            0x20000000: 'EXECUTE',
            0x40000000: 'READ',
            0x80000000: 'WRITE',
        }
        for flag, name in char_map.items():
            if chars & flag:
                flags.append(name)
        return flags

    def _detect_packer(self, pe, file_data: bytes) -> Dict:
        """Detect common packers/protectors"""
        result = {'detected': False, 'name': None, 'indicators': []}

        # Check section names for packer signatures
        packer_sections = {
            'UPX': ['UPX0', 'UPX1', 'UPX2', '.UPX'],
            'ASPack': ['.aspack', '.adata'],
            'PECompact': ['pec1', 'pec2', 'PEC2'],
            'Themida': ['.themida'],
            'VMProtect': ['.vmp0', '.vmp1', '.vmp2'],
            'Enigma': ['.enigma1', '.enigma2'],
        }

        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
            for packer, signatures in packer_sections.items():
                if section_name in signatures:
                    result['detected'] = True
                    result['name'] = packer
                    result['indicators'].append(f'Section name: {section_name}')

        # Check for high entropy (indicates packing)
        total_entropy = 0
        for section in pe.sections:
            section_data = section.get_data()
            if section_data:
                entropy = self._calculate_entropy(section_data)
                if entropy > 7.5:
                    result['indicators'].append(f'High entropy section ({entropy:.2f})')
                total_entropy += entropy

        avg_entropy = total_entropy / len(pe.sections) if pe.sections else 0
        if avg_entropy > 7.0:
            result['indicators'].append(f'High average entropy ({avg_entropy:.2f})')
            if not result['detected']:
                result['detected'] = True
                result['name'] = 'Unknown packer/encryption'

        return result

    def _extract_suspicious_strings(self, file_data: bytes) -> Dict:
        """Extract suspicious strings that indicate malware behavior"""
        result = {
            'networkLibraries': [],
            'suspiciousDlls': [],
            'shellIndicators': [],
            'embeddedIPs': [],
            'embeddedUrls': [],
            'findings': []
        }

        # Extract printable strings (min 4 chars)
        strings = re.findall(b'[\x20-\x7e]{4,}', file_data)
        string_set = set(s.decode('ascii', errors='ignore').lower() for s in strings)

        # Network/Socket libraries (reverse shell indicators)
        network_libs = ['ws2_32', 'wsock32', 'wininet', 'winhttp', 'urlmon', 'mswsock']
        for lib in network_libs:
            if any(lib in s for s in string_set):
                result['networkLibraries'].append(lib)
                result['findings'].append(f'Dynamic network library: {lib} (possible reverse shell)')

        # Suspicious DLLs loaded dynamically
        suspicious_dlls = {
            'ntdll': 'NT API access (evasion/injection)',
            'kernel32': 'Core Windows API',
            'advapi32': 'Registry/Security functions',
            'crypt32': 'Cryptographic operations',
            'shell32': 'Shell execution',
            'user32': 'User interface/keylogging',
        }
        for dll, desc in suspicious_dlls.items():
            # Look for dll string that's not just in import table
            if any(dll in s and '.dll' in s for s in string_set):
                result['suspiciousDlls'].append({'dll': dll, 'description': desc})

        # Shell/Command execution indicators
        shell_indicators = ['cmd.exe', 'powershell', 'cmd /c', '/bin/sh', '/bin/bash',
                          'wscript', 'cscript', 'mshta', 'rundll32', 'regsvr32']
        for indicator in shell_indicators:
            if any(indicator in s for s in string_set):
                result['shellIndicators'].append(indicator)
                result['findings'].append(f'Shell execution indicator: {indicator}')

        # Extract embedded IPs (plaintext)
        ip_pattern = re.compile(rb'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        ips = ip_pattern.findall(file_data)
        for ip in set(ips):
            ip_str = ip.decode()
            # Filter out common non-IOC IPs
            if not ip_str.startswith('0.') and not ip_str.startswith('127.') and ip_str != '255.255.255.255':
                result['embeddedIPs'].append(ip_str)
                result['findings'].append(f'Embedded IP address: {ip_str}')

        # Extract sockaddr_in structures (shellcode C2 config)
        # Format: 02 00 [port BE] [IP bytes] - AF_INET + port + IP
        import struct
        for i in range(len(file_data) - 8):
            # Look for AF_INET (0x0002) followed by port and IP
            if file_data[i:i+2] == b'\x02\x00':
                port_bytes = file_data[i+2:i+4]
                ip_bytes = file_data[i+4:i+8]

                # Port is big-endian (network byte order)
                port = struct.unpack(">H", port_bytes)[0]

                # Check if this looks like a valid C2 config
                if port in range(1, 65536) and port != 0:
                    ip = f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"

                    # Filter: valid IP range, not broadcast/multicast
                    if (1 <= ip_bytes[0] <= 223 and
                        ip_bytes[0] not in [127] and  # not localhost
                        not (ip_bytes[0] == 169 and ip_bytes[1] == 254) and  # not link-local
                        ip_bytes[3] != 0 and ip_bytes[3] != 255):  # not network/broadcast

                        # Common reverse shell ports
                        if port in [4444, 4443, 443, 80, 8080, 8443, 1234, 5555, 6666, 7777, 8888, 9999, 1337, 31337]:
                            c2_str = f"{ip}:{port}"
                            if c2_str not in result['embeddedIPs']:
                                result['embeddedIPs'].append(c2_str)
                                result['findings'].append(f'C2 callback: {c2_str} (sockaddr_in structure)')
                                result['findings'].insert(0, f'REVERSE SHELL C2: {c2_str}')

        # Check for common reverse shell patterns
        if result['networkLibraries'] and (result['shellIndicators'] or
            any('virtualprotect' in s or 'virtualalloc' in s for s in string_set)):
            result['findings'].insert(0, 'LIKELY REVERSE SHELL: Network library + memory manipulation detected')

        # Check for shellcode markers
        shellcode_markers = ['payload', 'shellcode', 'meterpreter', 'beacon', 'cobalt']
        for marker in shellcode_markers:
            if any(marker in s for s in string_set):
                result['findings'].append(f'Shellcode/payload marker: {marker}')

        return result

    def _analyze_pdf(self, file_path: str) -> Dict:
        """Analyze PDF file for suspicious elements"""
        result = {
            'success': True,
            'hasJavaScript': False,
            'hasAutoAction': False,
            'hasEmbeddedFiles': False,
            'externalLinks': [],
            'suspiciousElements': [],
        }

        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                content_str = content.decode('latin-1', errors='replace')

            # Check for JavaScript
            if b'/JavaScript' in content or b'/JS' in content:
                result['hasJavaScript'] = True
                result['suspiciousElements'].append('Contains JavaScript')

            # Check for auto-open actions
            if b'/OpenAction' in content or b'/AA' in content:
                result['hasAutoAction'] = True
                result['suspiciousElements'].append('Has auto-open action')

            # Check for embedded files
            if b'/EmbeddedFile' in content or b'/EmbeddedFiles' in content:
                result['hasEmbeddedFiles'] = True
                result['suspiciousElements'].append('Contains embedded files')

            # Check for external links
            if b'/URI' in content or b'/S /URI' in content:
                result['suspiciousElements'].append('Contains external URIs')

            # Extract URLs
            self.ioc_collector.extract_from_text(content_str)

        except Exception as e:
            result['success'] = False
            result['error'] = str(e)

        return result

    def _calculate_risk_score(self, analysis_result: Dict) -> Tuple[int, str]:
        """Calculate risk score based on analysis results with detailed reasons"""
        score = 0
        risk_reasons = []

        # Get or create threat map
        threat_map = analysis_result.get('_threat_map')
        if not threat_map:
            threat_map = ThreatMap()

        # Execution-based scoring
        execution = analysis_result.get('execution', {})
        if execution.get('error') and not execution.get('staticOnly'):
            score += 10
            risk_reasons.append({
                'category': 'Execution Error',
                'description': 'File failed to execute properly, may indicate anti-analysis techniques',
                'severity': 'low',
                'score_contribution': 10
            })

        # IOC-based scoring
        iocs = analysis_result.get('iocs', {})
        if iocs.get('ips'):
            ip_count = len(iocs['ips'])
            contribution = min(ip_count * 5, 25)
            score += contribution
            if ip_count > 0:
                risk_reasons.append({
                    'category': 'Network IOCs',
                    'description': f'{ip_count} IP address(es) found in execution output',
                    'severity': 'medium' if ip_count > 2 else 'low',
                    'score_contribution': contribution
                })
                threat_map.add_behavior('network', f'{ip_count} IP addresses contacted', severity='medium')

        if iocs.get('urls'):
            url_count = len(iocs['urls'])
            contribution = min(url_count * 3, 15)
            score += contribution
            if url_count > 0:
                risk_reasons.append({
                    'category': 'Network IOCs',
                    'description': f'{url_count} URL(s) found in execution output',
                    'severity': 'medium' if url_count > 3 else 'low',
                    'score_contribution': contribution
                })
                threat_map.add_behavior('network', f'{url_count} URLs accessed', severity='medium')

        if iocs.get('domains'):
            domain_count = len(iocs['domains'])
            contribution = min(domain_count * 2, 10)
            score += contribution

        # PDF-specific scoring
        if execution.get('hasJavaScript'):
            score += 30
            risk_reasons.append({
                'category': 'Malicious Content',
                'description': 'PDF contains JavaScript which can be used for exploitation',
                'severity': 'high',
                'technique': 'T1204 - User Execution',
                'score_contribution': 30
            })
            threat_map.add_behavior('evasion', 'JavaScript in PDF', technique='T1204', severity='high')

        if execution.get('hasAutoAction'):
            score += 25
            risk_reasons.append({
                'category': 'Auto-Execution',
                'description': 'PDF has auto-open actions that execute without user interaction',
                'severity': 'high',
                'technique': 'T1204 - User Execution',
                'score_contribution': 25
            })
            threat_map.add_behavior('evasion', 'Auto-open action in PDF', technique='T1204', severity='high')

        if execution.get('hasEmbeddedFiles'):
            score += 20
            risk_reasons.append({
                'category': 'Embedded Content',
                'description': 'PDF contains embedded files that could be malicious',
                'severity': 'medium',
                'score_contribution': 20
            })
            threat_map.add_behavior('evasion', 'Embedded files in PDF', severity='medium')

        # Strace-based scoring (suspicious syscalls)
        strace = execution.get('strace_output', '')
        if 'connect(' in strace:
            score += 15
            risk_reasons.append({
                'category': 'Network Activity',
                'description': 'Process attempted to establish network connections',
                'severity': 'medium',
                'technique': 'T1071 - Application Layer Protocol',
                'score_contribution': 15
            })
            threat_map.add_behavior('network', 'Network connection attempts', technique='T1071', severity='medium')

        if 'execve(' in strace and strace.count('execve(') > 1:
            exec_count = strace.count('execve(')
            score += 20
            risk_reasons.append({
                'category': 'Process Creation',
                'description': f'Process spawned {exec_count} child processes',
                'severity': 'medium',
                'technique': 'T1059 - Command and Scripting Interpreter',
                'score_contribution': 20
            })
            threat_map.add_behavior('process', f'{exec_count} child processes created', technique='T1059', severity='medium')

        if '/etc/passwd' in strace or '/etc/shadow' in strace:
            score += 40
            risk_reasons.append({
                'category': 'Credential Access',
                'description': 'Process attempted to access system credential files',
                'severity': 'critical',
                'technique': 'T1003 - OS Credential Dumping',
                'score_contribution': 40
            })
            threat_map.add_behavior('credential', 'Access to credential files', technique='T1003', severity='critical')

        # PE Analysis scoring
        pe_analysis = analysis_result.get('peAnalysis', {})
        if pe_analysis.get('isPE'):
            # Analyze imports with ThreatMap
            pe_risk_reasons = threat_map.analyze_imports(pe_analysis.get('imports', []))
            for reason in pe_risk_reasons:
                score += ThreatMap.get_severity_score(reason.get('severity', 'low'))
            risk_reasons.extend(pe_risk_reasons)

            # Analyze sections
            section_reasons = threat_map.analyze_sections(pe_analysis.get('sections', []))
            for reason in section_reasons:
                score += ThreatMap.get_severity_score(reason.get('severity', 'low'))
            risk_reasons.extend(section_reasons)

            # Check for packer detection
            packed = pe_analysis.get('signatures', {}).get('packed', {})
            if packed.get('detected'):
                packer_name = packed.get('name', 'Unknown')
                score += 20
                risk_reasons.append({
                    'category': 'Packing/Obfuscation',
                    'description': f'File is packed/protected with {packer_name}',
                    'severity': 'high',
                    'technique': 'T1027 - Obfuscated Files or Information',
                    'score_contribution': 20
                })
                threat_map.add_behavior('evasion', f'Packed with {packer_name}', technique='T1027', severity='high')

            # Check detections list
            for detection in pe_analysis.get('detections', []):
                if 'Suspicious import' in detection:
                    score += 5
                elif 'High entropy' in detection:
                    score += 10
                elif 'Unusual section' in detection:
                    score += 5
                elif 'reverse shell' in detection.lower():
                    score += 30
                elif 'network library' in detection.lower():
                    score += 15
                elif 'Embedded IP' in detection:
                    score += 10
                elif 'Shell execution' in detection:
                    score += 15

            # Process suspicious strings for threat map
            suspicious_strings = pe_analysis.get('suspiciousStrings', {})

            # Network libraries indicate potential reverse shell
            for lib in suspicious_strings.get('networkLibraries', []):
                threat_map.add_behavior('network', f'Dynamic load: {lib}', technique='T1071', severity='high')
                risk_reasons.append({
                    'category': 'Network Capability',
                    'description': f'Dynamically loads {lib} (Winsock) - common in reverse shells',
                    'severity': 'high',
                    'technique': 'T1071 - Application Layer Protocol'
                })
                score += 15

            # Shell indicators
            for shell in suspicious_strings.get('shellIndicators', []):
                threat_map.add_behavior('process', f'Shell access: {shell}', technique='T1059', severity='high')
                risk_reasons.append({
                    'category': 'Command Execution',
                    'description': f'References {shell} - may spawn shell processes',
                    'severity': 'high',
                    'technique': 'T1059 - Command and Scripting Interpreter'
                })
                score += 10

            # Embedded IPs
            for ip in suspicious_strings.get('embeddedIPs', []):
                threat_map.add_behavior('network', f'Hardcoded IP: {ip}', technique='T1095', severity='critical')
                risk_reasons.append({
                    'category': 'C2 Indicator',
                    'description': f'Embedded IP address: {ip} - potential C2 server',
                    'severity': 'critical',
                    'technique': 'T1095 - Non-Application Layer Protocol'
                })
                score += 20

            # Check for reverse shell pattern
            if suspicious_strings.get('networkLibraries') and (
                suspicious_strings.get('shellIndicators') or
                any('VirtualProtect' in f.get('name', '') for imp in pe_analysis.get('imports', []) for f in imp.get('functions', []))
            ):
                threat_map.add_behavior('network', 'REVERSE SHELL PATTERN DETECTED', technique='T1059.001', severity='critical')
                risk_reasons.insert(0, {
                    'category': 'Reverse Shell',
                    'description': 'File exhibits reverse shell characteristics: network library + memory manipulation or shell access',
                    'severity': 'critical',
                    'technique': 'T1059.001 - PowerShell / Command Shell'
                })
                score += 25

        # Cap score at 100
        score = min(score, 100)

        # Determine risk level
        if score >= 70:
            level = 'Critical'
        elif score >= 50:
            level = 'High'
        elif score >= 30:
            level = 'Medium'
        elif score >= 10:
            level = 'Low'
        else:
            level = 'Clean'

        # Store risk reasons and threat map in result
        analysis_result['riskReasons'] = risk_reasons
        analysis_result['threatMap'] = threat_map.to_dict()

        return score, level

    def cleanup(self):
        """Clean up session files"""
        try:
            if os.path.exists(self.session_dir):
                shutil.rmtree(self.session_dir)
        except Exception:
            pass

        if isinstance(self.backend, DockerBackend):
            self.backend.cleanup()


# =============================================================================
# URL Analysis
# =============================================================================

class URLAnalyzer:
    """Analyzes URLs in isolated browser environment"""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = min(timeout, MAX_TIMEOUT)
        self.session_id = uuid.uuid4().hex
        self.session_dir = os.path.join(SESSIONS_DIR, f"url_{self.session_id}")
        os.makedirs(self.session_dir, exist_ok=True)
        self.ioc_collector = IOCCollector()

    def analyze_http(self, url: str) -> Dict:
        """Lightweight HTTP analysis - follows redirects without JS"""
        result = {
            'sessionId': self.session_id,
            'url': url,
            'mode': 'http',
            'redirectChain': [],
            'finalUrl': None,
            'statusCode': None,
            'headers': {},
            'contentType': None,
            'iocs': {},
            'riskScore': 0,
            'riskLevel': 'Low',
            'status': 'completed',
        }

        try:
            import urllib.request
            import urllib.error
            import ssl

            # Create SSL context that doesn't verify (for analysis purposes)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # Custom redirect handler to track chain
            class RedirectTracker(urllib.request.HTTPRedirectHandler):
                def __init__(self):
                    super().__init__()
                    self.redirects = []

                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    self.redirects.append({
                        'url': req.full_url,
                        'statusCode': code,
                        'redirectTo': newurl
                    })
                    return super().redirect_request(req, fp, code, msg, headers, newurl)

            tracker = RedirectTracker()
            opener = urllib.request.build_opener(
                tracker,
                urllib.request.HTTPSHandler(context=ctx)
            )

            req = urllib.request.Request(url, headers={
                'User-Agent': REALISTIC_UA
            })

            with opener.open(req, timeout=self.timeout) as response:
                result['finalUrl'] = response.url
                result['statusCode'] = response.status
                result['headers'] = dict(response.headers)
                result['contentType'] = response.headers.get('Content-Type', '')
                result['redirectChain'] = tracker.redirects

                # Read some content for IOC extraction
                content = response.read(50000).decode('utf-8', errors='replace')
                self.ioc_collector.extract_from_text(content)

        except urllib.error.HTTPError as e:
            result['statusCode'] = e.code
            result['error'] = str(e)
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)

        result['iocs'] = self.ioc_collector.to_dict()
        result['riskScore'], result['riskLevel'] = self._calculate_url_risk(result)

        return result

    def analyze_browser(self, url: str, capture_screenshot: bool = True) -> Dict:
        """Full browser analysis with JS execution and step-by-step screenshots"""
        result = {
            'sessionId': self.session_id,
            'url': url,
            'mode': 'browser',
            'finalUrl': None,
            'pageTitle': None,
            'screenshot': None,
            'screenshots': [],  # Screenshots for each redirect step
            'screenshotPath': None,
            'redirectChain': [],
            'networkRequests': [],
            'formFields': [],
            'downloads': [],
            'iocs': {},
            'riskScore': 0,
            'riskLevel': 'Low',
            'status': 'completed',
        }

        caps = _config.detect_capabilities()
        if not caps.get('chromium', {}).get('available'):
            result['status'] = 'error'
            result['error'] = 'Chromium not available for browser analysis'
            return result

        chromium_path = caps['chromium']['path']
        print(f"[URL Analysis] Browser mode: chromium={chromium_path}, url={url}", flush=True)

        # First, get the redirect chain using HTTP analysis
        http_result = self.analyze_http(url)
        result['redirectChain'] = http_result.get('redirectChain', [])

        # Build list of URLs to screenshot (original + all redirects + final)
        urls_to_capture = [url]
        for redirect in result['redirectChain']:
            if redirect.get('redirectTo'):
                urls_to_capture.append(redirect['redirectTo'])

        # Add final URL if different
        if http_result.get('finalUrl') and http_result['finalUrl'] not in urls_to_capture:
            urls_to_capture.append(http_result['finalUrl'])

        result['finalUrl'] = http_result.get('finalUrl', url)

        # Capture screenshot for each URL in the chain
        screenshots = []
        profile_dir = None

        try:
            profile_dir = tempfile.mkdtemp(prefix='sandbox_chrome_')

            print(f"[URL Analysis] URLs to capture: {urls_to_capture}, session_dir={self.session_dir}, profile_dir={profile_dir}", flush=True)

            for i, capture_url in enumerate(urls_to_capture[:10]):  # Limit to 10 URLs
                screenshot_path = os.path.join(self.session_dir, f'screenshot_{i}.png')

                # Build Chrome command
                chrome_args = [
                    chromium_path,
                    '--headless=new',
                    '--disable-gpu',
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-web-security',
                    '--disable-features=IsolateOrigins,site-per-process',
                    f'--user-agent={REALISTIC_UA}',
                    '--disable-blink-features=AutomationControlled',
                    '--window-size=1920,1080',
                    '--hide-scrollbars',
                    f'--user-data-dir={profile_dir}',
                    f'--screenshot={screenshot_path}',
                    '--run-all-compositor-stages-before-draw',
                    capture_url
                ]

                try:
                    proc = subprocess.run(
                        chrome_args,
                        capture_output=True,
                        timeout=30,  # 30 sec per URL
                    )

                    # Debug: log Chromium exit code and errors
                    chrome_stderr = proc.stderr.decode('utf-8', errors='replace') if proc.stderr else ''
                    if proc.returncode != 0:
                        print(f"[URL Analysis] Chromium exit code {proc.returncode} for {capture_url}", flush=True)
                        print(f"[URL Analysis] Chromium stderr: {chrome_stderr[:500]}", flush=True)
                    if not os.path.exists(screenshot_path):
                        print(f"[URL Analysis] Screenshot file not created for {capture_url}", flush=True)
                    elif os.path.getsize(screenshot_path) == 0:
                        print(f"[URL Analysis] Screenshot file is empty for {capture_url}", flush=True)

                    # Check screenshot
                    if os.path.exists(screenshot_path) and os.path.getsize(screenshot_path) > 0:
                        with open(screenshot_path, 'rb') as f:
                            screenshot_b64 = base64.b64encode(f.read()).decode('utf-8')
                            screenshots.append(screenshot_b64)

                            # Update redirect chain with screenshot info
                            if i > 0 and i - 1 < len(result['redirectChain']):
                                result['redirectChain'][i - 1]['screenshot'] = screenshot_b64

                    # Extract IOCs from output
                    stdout = proc.stdout.decode('utf-8', errors='replace')
                    stderr = proc.stderr.decode('utf-8', errors='replace')
                    self.ioc_collector.extract_from_text(stdout + stderr)

                except subprocess.TimeoutExpired:
                    print(f"[URL Analysis] Screenshot timeout for {capture_url}", flush=True)
                except Exception as e:
                    print(f"[URL Analysis] Screenshot error for {capture_url}: {e}", flush=True)

            # Final screenshot is the last one captured
            if screenshots:
                result['screenshot'] = screenshots[-1]
                result['screenshots'] = screenshots

        except Exception as e:
            print(f"[URL Analysis] Outer exception: {e}", flush=True)
            result['status'] = 'error'
            result['error'] = str(e)
        finally:
            # Cleanup
            try:
                if profile_dir and os.path.exists(profile_dir):
                    shutil.rmtree(profile_dir)
            except Exception:
                pass

        result['iocs'] = self.ioc_collector.to_dict()
        result['riskScore'], result['riskLevel'] = self._calculate_url_risk(result)

        return result

    def _calculate_url_risk(self, result: Dict) -> Tuple[int, str]:
        """Calculate risk score for URL analysis"""
        score = 0

        # Redirect chain scoring
        redirects = result.get('redirectChain', [])
        if len(redirects) > 3:
            score += 20
        elif len(redirects) > 1:
            score += 10

        # IOC scoring
        iocs = result.get('iocs', {})
        if iocs.get('ips'):
            score += min(len(iocs['ips']) * 5, 25)
        if iocs.get('urls'):
            score += min(len(iocs['urls']) * 2, 20)

        # Content type scoring
        content_type = result.get('contentType') or ''
        if 'application/octet-stream' in content_type:
            score += 30
        if 'application/x-msdownload' in content_type:
            score += 40

        # Error scoring
        if result.get('error'):
            score += 10

        # Form detection (potential credential harvesting)
        if result.get('formFields'):
            score += 25

        score = min(score, 100)

        if score >= 70:
            level = 'Critical'
        elif score >= 50:
            level = 'High'
        elif score >= 30:
            level = 'Medium'
        elif score >= 10:
            level = 'Low'
        else:
            level = 'Clean'

        return score, level

    def cleanup(self):
        """Clean up session files"""
        try:
            if os.path.exists(self.session_dir):
                shutil.rmtree(self.session_dir)
        except Exception:
            pass


# =============================================================================
# Main Sandbox Service
# =============================================================================

class SandboxService:
    """Main interface for sandbox analysis"""

    def __init__(self):
        self._db_lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        """Initialize sandbox tables in database"""
        with self._db_lock:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sandbox_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    entry_ref TEXT,
                    sample_hash TEXT,
                    sample_type TEXT,
                    backend_used TEXT,
                    process_tree TEXT,
                    filesystem_changes TEXT,
                    network_connections TEXT,
                    extracted_iocs TEXT,
                    risk_score INTEGER DEFAULT 0,
                    risk_level TEXT DEFAULT 'Low',
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_sandbox_sessions_hash
                ON sandbox_sessions(sample_hash)
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_sandbox_sessions_status
                ON sandbox_sessions(status)
            ''')

            conn.commit()
            conn.close()

    def get_status(self) -> Dict:
        """Get sandbox service status and capabilities"""
        caps = _config.detect_capabilities()

        return {
            'service': 'sandbox',
            'status': 'available' if caps.get('supported_types', {}).get('scripts') else 'limited',
            'backends': {
                'docker': caps.get('docker', {}).get('functional', False),
                'bubblewrap': caps.get('bubblewrap', {}).get('available', False),
            },
            'capabilities': caps.get('supported_types', {}),
            'tools': {
                'strace': caps.get('strace', {}).get('available', False),
                'wine': caps.get('wine', {}).get('available', False),
                'chromium': caps.get('chromium', {}).get('available', False),
                'libreoffice': caps.get('libreoffice', {}).get('available', False),
            },
            'limits': {
                'maxFileSize': MAX_FILE_SIZE,
                'maxTimeout': MAX_TIMEOUT,
                'defaultTimeout': DEFAULT_TIMEOUT,
                'maxConcurrentSessions': MAX_CONCURRENT_SESSIONS,
            },
            'directories': {
                'sandbox': SANDBOX_DIR,
                'sessions': SESSIONS_DIR,
                'samples': SAMPLES_DIR,
                'results': RESULTS_DIR,
            }
        }

    def analyze_file(self, file_data: bytes, filename: str, secret_key: str = None,
                    timeout: int = DEFAULT_TIMEOUT, entry_ref: str = None) -> Dict:
        """Analyze a file in sandbox environment"""

        # Check file size
        if len(file_data) > MAX_FILE_SIZE:
            return {
                'success': False,
                'error': f'File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB'
            }

        # Check concurrent sessions
        with _session_lock:
            if len(_active_sessions) >= MAX_CONCURRENT_SESSIONS:
                return {
                    'success': False,
                    'error': 'Maximum concurrent sessions reached. Try again later.'
                }

        # Create session
        session = SandboxSession(timeout=timeout)

        with _session_lock:
            _active_sessions[session.session_id] = session

        try:
            # Save file to samples directory
            sample_path = os.path.join(SAMPLES_DIR, f"{session.session_id}_{filename}")
            with open(sample_path, 'wb') as f:
                f.write(file_data)

            # Analyze
            result = session.analyze_file(sample_path)
            result['success'] = result.get('status') != 'error'
            result['filename'] = filename
            result['entryRef'] = entry_ref

            # Build behavior summary for frontend stats
            threat_map = result.get('threatMap', {})
            risk_reasons = result.get('riskReasons', [])
            iocs = result.get('iocs', {})
            pe_analysis = result.get('peAnalysis', {})
            suspicious_strings = pe_analysis.get('suspiciousStrings', {})

            result['behaviorSummary'] = {
                'processCount': len(threat_map.get('process', [])),
                'fileOperations': len(pe_analysis.get('sections', [])),
                'networkConnections': len(threat_map.get('network', [])) + len(suspicious_strings.get('embeddedIPs', [])),
                'suspiciousActivities': len(risk_reasons),
                'registryOperations': len(threat_map.get('registry', [])),
                'evasionTechniques': len(threat_map.get('evasion', [])),
                'credentialAccess': len(threat_map.get('credential', [])),
                'iocCount': iocs.get('summary', {}).get('totalIPs', 0) + iocs.get('summary', {}).get('totalURLs', 0)
            }

            # Store session results
            self._store_session(session, result)

            # Investigate IOCs if threat_intel is available
            result['iocInvestigation'] = self._investigate_iocs(result.get('iocs', {}))

            return result

        finally:
            # Cleanup
            with _session_lock:
                _active_sessions.pop(session.session_id, None)

            session.cleanup()

            # Remove sample file
            try:
                if os.path.exists(sample_path):
                    os.remove(sample_path)
            except Exception:
                pass

    def analyze_url(self, url: str, mode: str = 'http', secret_key: str = None,
                   timeout: int = DEFAULT_TIMEOUT, entry_ref: str = None) -> Dict:
        """Analyze a URL"""

        # Validate URL
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return {
                    'success': False,
                    'error': 'Invalid URL format'
                }
        except Exception:
            return {
                'success': False,
                'error': 'Failed to parse URL'
            }

        analyzer = URLAnalyzer(timeout=timeout)

        try:
            if mode == 'browser':
                result = analyzer.analyze_browser(url)
            else:
                result = analyzer.analyze_http(url)

            result['success'] = result.get('status') != 'error'
            result['entryRef'] = entry_ref

            # Investigate IOCs
            result['iocInvestigation'] = self._investigate_iocs(result.get('iocs', {}))

            return result

        finally:
            analyzer.cleanup()

    def _investigate_iocs(self, iocs: Dict) -> Dict:
        """Investigate extracted IOCs using threat intelligence"""
        try:
            import threat_intel

            ips = iocs.get('ips', [])[:5]
            urls = iocs.get('urls', [])[:5]
            hashes_all = []
            for hash_list in iocs.get('hashes', {}).values():
                hashes_all.extend(hash_list[:2])

            if not ips and not urls and not hashes_all:
                return {'summary': {'totalIOCs': 0, 'maliciousIOCs': 0}}

            return threat_intel.investigate_all_iocs(
                ips=ips,
                urls=urls,
                hashes=hashes_all[:5],
                max_per_type=5
            )

        except ImportError:
            return {'error': 'Threat intelligence module not available'}
        except Exception as e:
            return {'error': str(e)}

    def _store_session(self, session: SandboxSession, result: Dict):
        """Store session results in database"""
        with self._db_lock:
            try:
                conn = sqlite3.connect(DATABASE_FILE)
                cursor = conn.cursor()

                file_analysis = result.get('fileAnalysis', {})

                cursor.execute('''
                    INSERT INTO sandbox_sessions
                    (session_id, entry_ref, sample_hash, sample_type, backend_used,
                     extracted_iocs, risk_score, risk_level, status, completed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    session.session_id,
                    result.get('entryRef'),
                    file_analysis.get('hashes', {}).get('sha256'),
                    file_analysis.get('detectedType'),
                    session.backend_type,
                    json.dumps(result.get('iocs', {})),
                    result.get('riskScore', 0),
                    result.get('riskLevel', 'Low'),
                    result.get('status', 'completed'),
                    datetime.now().isoformat()
                ))

                conn.commit()
                conn.close()

            except Exception as e:
                print(f"[Sandbox] Database error: {e}")

    def get_session_count(self) -> int:
        """Get count of active sessions"""
        with _session_lock:
            return len(_active_sessions)


# Global service instance
_service = None


def get_service() -> SandboxService:
    """Get or create sandbox service instance"""
    global _service
    if _service is None:
        _service = SandboxService()
    return _service


# =============================================================================
# CLI Interface
# =============================================================================

if __name__ == '__main__':
    import sys

    print("=== Sandbox Service Status ===\n")

    service = get_service()
    status = service.get_status()

    print(f"Status: {status['status']}")
    print(f"\nBackends:")
    for backend, available in status['backends'].items():
        state = "✓" if available else "✗"
        print(f"  {state} {backend}")

    print(f"\nCapabilities:")
    for cap, supported in status['capabilities'].items():
        state = "✓" if supported else "✗"
        print(f"  {state} {cap}")

    print(f"\nTools:")
    for tool, available in status['tools'].items():
        state = "✓" if available else "✗"
        print(f"  {state} {tool}")

    print(f"\nLimits:")
    for limit, value in status['limits'].items():
        print(f"  {limit}: {value}")

    if len(sys.argv) > 2:
        cmd = sys.argv[1]
        target = sys.argv[2]

        if cmd == 'file':
            print(f"\n=== Analyzing file: {target} ===\n")
            with open(target, 'rb') as f:
                data = f.read()
            result = service.analyze_file(data, os.path.basename(target))
            print(json.dumps(result, indent=2, default=str))

        elif cmd == 'url':
            mode = sys.argv[3] if len(sys.argv) > 3 else 'http'
            print(f"\n=== Analyzing URL ({mode} mode): {target} ===\n")
            result = service.analyze_url(target, mode=mode)
            # Remove screenshot base64 for cleaner output
            if 'screenshot' in result:
                result['screenshot'] = f"<base64 data, {len(result['screenshot'])} chars>"
            print(json.dumps(result, indent=2, default=str))

    else:
        print("\nUsage:")
        print("  python sandbox_service.py file <path>     - Analyze a file")
        print("  python sandbox_service.py url <url> [mode] - Analyze URL (mode: http|browser)")
