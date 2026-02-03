#!/usr/bin/env python3
"""
Micro Sandbox Service for Manny Threat Intel
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
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse

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
        for cmd in ['chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable']:
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

        return {
            'scripts': bwrap or docker,
            'windows_scripts': (bwrap or docker),  # Partial support via interpreters
            'executables': docker and caps.get('wine', {}).get('available', False),
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

        # Extract domains
        for match in DOMAIN_PATTERN.findall(text):
            # Filter out common false positives
            if len(match) > 4 and '.' in match:
                self.domains.add(match.lower())

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
# Bubblewrap Backend
# =============================================================================

class BubblewrapBackend:
    """Sandbox execution using bubblewrap (bwrap)"""

    def __init__(self, session_dir: str, timeout: int = DEFAULT_TIMEOUT):
        self.session_dir = session_dir
        self.timeout = min(timeout, MAX_TIMEOUT)
        self.work_dir = os.path.join(session_dir, 'work')
        self.output_dir = os.path.join(session_dir, 'output')
        os.makedirs(self.work_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)

    def _build_bwrap_args(self, command: List[str], allow_network: bool = False) -> List[str]:
        """Build bubblewrap command arguments"""
        args = ['bwrap']

        # Filesystem isolation - bind necessary directories if they exist
        bind_dirs = [
            ('/usr', '/usr'),
            ('/lib', '/lib'),
            ('/bin', '/bin'),
            ('/sbin', '/sbin'),
        ]

        # Add optional directories that may exist
        optional_dirs = [
            '/lib64',
            '/lib32',
            '/etc/alternatives',
            '/etc/ld.so.cache',
            '/etc/ld.so.conf',
            '/etc/ld.so.conf.d',
        ]

        for src, dest in bind_dirs:
            if os.path.exists(src):
                args.extend(['--ro-bind', src, dest])

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
            '--unshare-all',
            '--die-with-parent',
            '--new-session',
            '--cap-drop', 'ALL',
            '--chdir', '/sandbox',
        ])

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
            # Use timeout wrapper
            timeout_args = ['timeout', '--signal=KILL', str(self.timeout)] + bwrap_args

            proc = subprocess.run(
                timeout_args,
                capture_output=True,
                timeout=self.timeout + 5,  # Extra buffer for cleanup
                cwd=self.session_dir,
            )

            result['stdout'] = proc.stdout.decode('utf-8', errors='replace')[:50000]
            result['stderr'] = proc.stderr.decode('utf-8', errors='replace')[:50000]
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
            timeout_args = ['timeout', '--signal=KILL', str(self.timeout)] + bwrap_args

            proc = subprocess.run(
                timeout_args,
                capture_output=True,
                timeout=self.timeout + 5,
                cwd=self.session_dir,
            )

            result['stdout'] = proc.stdout.decode('utf-8', errors='replace')[:50000]
            result['stderr'] = proc.stderr.decode('utf-8', errors='replace')[:50000]
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

            result['stdout'] = proc.stdout.decode('utf-8', errors='replace')[:50000]
            result['stderr'] = proc.stderr.decode('utf-8', errors='replace')[:50000]
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

            else:
                result['execution'] = {
                    'success': False,
                    'error': f'Unsupported file type: {file_type}'
                }

            # Collect IOCs
            result['iocs'] = self.ioc_collector.to_dict()

            # Calculate risk score
            result['riskScore'], result['riskLevel'] = self._calculate_risk_score(result)

        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)

        self.status = 'completed'
        self.results = result
        return result

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
        """Calculate risk score based on analysis results"""
        score = 0

        # Execution-based scoring
        execution = analysis_result.get('execution', {})
        if execution.get('error'):
            score += 10

        # IOC-based scoring
        iocs = analysis_result.get('iocs', {})
        if iocs.get('ips'):
            score += len(iocs['ips']) * 5
        if iocs.get('urls'):
            score += len(iocs['urls']) * 3
        if iocs.get('domains'):
            score += len(iocs['domains']) * 2

        # PDF-specific scoring
        if execution.get('hasJavaScript'):
            score += 30
        if execution.get('hasAutoAction'):
            score += 25
        if execution.get('hasEmbeddedFiles'):
            score += 20

        # Strace-based scoring (suspicious syscalls)
        strace = execution.get('strace_output', '')
        if 'connect(' in strace:
            score += 15
        if 'execve(' in strace and strace.count('execve(') > 1:
            score += 20
        if '/etc/passwd' in strace or '/etc/shadow' in strace:
            score += 40

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
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
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
        """Full browser analysis with JS execution"""
        result = {
            'sessionId': self.session_id,
            'url': url,
            'mode': 'browser',
            'finalUrl': None,
            'pageTitle': None,
            'screenshot': None,
            'screenshotPath': None,
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

        try:
            # Create temporary directory for Chrome profile
            profile_dir = tempfile.mkdtemp(prefix='sandbox_chrome_')
            screenshot_path = os.path.join(self.session_dir, 'screenshot.png')

            # Build Chrome command
            chrome_args = [
                chromium_path,
                '--headless',
                '--disable-gpu',
                '--no-sandbox',
                '--disable-dev-shm-usage',
                '--disable-web-security',
                '--disable-features=IsolateOrigins,site-per-process',
                '--window-size=1920,1080',
                '--hide-scrollbars',
                f'--user-data-dir={profile_dir}',
                f'--screenshot={screenshot_path}',
                '--virtual-time-budget=5000',  # 5 second JS execution budget
                url
            ]

            proc = subprocess.run(
                chrome_args,
                capture_output=True,
                timeout=self.timeout,
            )

            # Check screenshot
            if os.path.exists(screenshot_path) and os.path.getsize(screenshot_path) > 0:
                result['screenshotPath'] = screenshot_path
                if capture_screenshot:
                    with open(screenshot_path, 'rb') as f:
                        result['screenshot'] = base64.b64encode(f.read()).decode('utf-8')

            # Extract any output
            stdout = proc.stdout.decode('utf-8', errors='replace')
            stderr = proc.stderr.decode('utf-8', errors='replace')
            self.ioc_collector.extract_from_text(stdout + stderr)

        except subprocess.TimeoutExpired:
            result['error'] = 'Browser analysis timed out'
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
        finally:
            # Cleanup
            try:
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
        content_type = result.get('contentType', '')
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
