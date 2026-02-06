#!/usr/bin/env python3
"""IP Lookup Website Server with Sandbox Analysis Features and Secure Storage"""

from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
import urllib.request
import urllib.error
import os
import io
import re
import email
import socket
import hashlib
import base64
import sqlite3
import threading
from email import policy
from email.parser import BytesParser
from datetime import datetime, timedelta
from urllib.parse import urlparse, unquote, urlunparse, quote

# Import threat intelligence module
try:
    import threat_intel
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    THREAT_INTEL_AVAILABLE = False
    print("[Warning] threat_intel module not available")

# Import screenshot service
try:
    import screenshot_service
    SCREENSHOT_AVAILABLE = True
except ImportError:
    SCREENSHOT_AVAILABLE = False
    print("[Warning] screenshot_service module not available")

# Import PDF export service
try:
    import pdf_export
    PDF_EXPORT_AVAILABLE = True
except ImportError:
    PDF_EXPORT_AVAILABLE = False
    print("[Warning] pdf_export module not available")

# Import sandbox service
try:
    import sandbox_service
    SANDBOX_AVAILABLE = True
except ImportError:
    SANDBOX_AVAILABLE = False
    print("[Warning] sandbox_service module not available")

# Import AI risk validator
try:
    import ai_validator
    AI_VALIDATOR_AVAILABLE = True
except ImportError:
    AI_VALIDATOR_AVAILABLE = False
    print("[Warning] ai_validator module not available")

# Import AI flow analyzer
try:
    import ai_flow_analyzer
    AI_FLOW_AVAILABLE = True
except ImportError:
    AI_FLOW_AVAILABLE = False
    print("[Warning] ai_flow_analyzer module not available")

PORT = 3000
MAX_FILE_SIZE = 15 * 1024 * 1024  # 15MB
DATABASE_FILE = os.path.join(os.path.dirname(__file__), 'analysis_results.db')
MASTER_KEY_FILE = os.path.join(os.path.dirname(__file__), '.msb_master_key')
KEY_SALT_FILE = os.path.join(os.path.dirname(__file__), '.msb_key_salt')
EXPIRATION_DAYS = 30
MIN_SECRET_KEY_LENGTH = 8
PBKDF2_ITERATIONS = 100000

# Load API key from config file or environment
def get_abuseipdb_key():
    """Get AbuseIPDB API key from config file or environment"""
    if THREAT_INTEL_AVAILABLE:
        key = threat_intel.get_api_key('abuseipdb')
        if key:
            return key
    return os.environ.get('ABUSEIPDB_API_KEY', '')

ABUSEIPDB_API_KEY = get_abuseipdb_key()

# Abuse categories from AbuseIPDB
ABUSE_CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted"
}

# Suspicious file extensions for phishing detection
SUSPICIOUS_EXTENSIONS = {'.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.msi', '.dll', '.com', '.pif', '.hta', '.wsf'}

# Urgency keywords for phishing detection
URGENCY_KEYWORDS = [
    'urgent', 'immediate', 'action required', 'verify your account', 'suspended',
    'confirm your identity', 'unusual activity', 'unauthorized', 'expire', 'locked',
    'security alert', 'click here immediately', 'within 24 hours', 'limited time'
]

# Lookalike domain patterns
LOOKALIKE_PATTERNS = [
    (r'paypa[l1]', 'paypal'),
    (r'amaz[o0]n', 'amazon'),
    (r'g[o0]{2}gle', 'google'),
    (r'micros[o0]ft', 'microsoft'),
    (r'app[l1]e', 'apple'),
    (r'faceb[o0]{2}k', 'facebook'),
    (r'netf[l1]ix', 'netflix'),
    (r'[l1]inkedin', 'linkedin'),
]

# High-risk file extensions for download detection
HIGH_RISK_EXTENSIONS = {'.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.msi', '.hta', '.wsf', '.com', '.pif'}

# In-memory cache for external lookups
_lookup_cache = {}
_cache_lock = threading.Lock()
CACHE_TTL = 300  # 5 minutes

# QR Code data patterns for analysis
QR_URL_PATTERN = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
QR_EMAIL_PATTERN = re.compile(r'mailto:([^\s?]+)', re.IGNORECASE)
QR_PHONE_PATTERN = re.compile(r'tel:([+\d\-\s]+)', re.IGNORECASE)
QR_WIFI_PATTERN = re.compile(r'WIFI:([^;]*;)+', re.IGNORECASE)
QR_VCARD_PATTERN = re.compile(r'BEGIN:VCARD', re.IGNORECASE)


# ============================================================================
# URL Normalization
# ============================================================================

def normalize_url_for_api(url: str) -> str:
    """
    Normalize URL handling percent-encoding properly.
    Handles double-encoded URLs and ensures proper encoding for API calls.
    """
    if not url:
        return url

    try:
        # Decode any double-encoding first (up to 3 levels)
        decoded = url
        for _ in range(3):
            new_decoded = unquote(decoded)
            if new_decoded == decoded:
                break
            decoded = new_decoded

        # Parse the decoded URL
        parsed = urlparse(decoded)

        # If no scheme, assume https
        scheme = parsed.scheme or 'https'
        netloc = parsed.netloc

        # Handle cases where URL was provided without scheme
        if not netloc and parsed.path:
            # Try to extract domain from path
            path_parts = parsed.path.split('/', 1)
            if '.' in path_parts[0]:
                netloc = path_parts[0]
                path = '/' + path_parts[1] if len(path_parts) > 1 else '/'
            else:
                path = parsed.path
        else:
            path = parsed.path or '/'

        # Re-encode path and query properly
        # Safe characters in path: unreserved + sub-delims + ':@/'
        safe_path = quote(path, safe='/:@!$&\'()*+,;=-._~')

        # Safe characters in query: unreserved + sub-delims + ':@/?'
        safe_query = quote(parsed.query, safe='=&:@/?!$\'()*+,;-._~') if parsed.query else ''

        # Reconstruct the URL
        normalized = urlunparse((
            scheme,
            netloc,
            safe_path,
            parsed.params,
            safe_query,
            parsed.fragment
        ))

        return normalized

    except Exception:
        # If normalization fails, return original URL
        return url


# ============================================================================
# Encryption Classes
# ============================================================================

class MasterKeyManager:
    """Manages the master key for database-level encryption"""

    def __init__(self):
        from cryptography.fernet import Fernet
        self.key = self._load_or_create_key()
        self.fernet = Fernet(self.key)

    def _load_or_create_key(self):
        """Load existing key or create new one"""
        from cryptography.fernet import Fernet
        if os.path.exists(MASTER_KEY_FILE):
            with open(MASTER_KEY_FILE, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            # Create with restrictive permissions
            fd = os.open(MASTER_KEY_FILE, os.O_WRONLY | os.O_CREAT, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(key)
            return key

    def encrypt(self, data):
        """Encrypt data with master key"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return self.fernet.encrypt(data)

    def decrypt(self, data):
        """Decrypt data with master key"""
        return self.fernet.decrypt(data)


class SecretKeyManager:
    """Manages user-provided secret key encryption"""

    def __init__(self):
        self.salt = self._load_or_create_salt()

    def _load_or_create_salt(self):
        """Load existing salt or create new one"""
        if os.path.exists(KEY_SALT_FILE):
            with open(KEY_SALT_FILE, 'rb') as f:
                return f.read()
        else:
            salt = os.urandom(32)
            fd = os.open(KEY_SALT_FILE, os.O_WRONLY | os.O_CREAT, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(salt)
            return salt

    def derive_key(self, secret_key):
        """Derive encryption key from user's secret key using PBKDF2"""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.fernet import Fernet

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=PBKDF2_ITERATIONS,
        )
        key = base64.urlsafe_b64encode(kdf.derive(secret_key.encode('utf-8')))
        return key

    def hash_secret_key(self, secret_key):
        """Hash the secret key for storage (for validation only)"""
        return hashlib.sha256((secret_key + self.salt.hex()).encode()).hexdigest()

    def encrypt(self, data, secret_key):
        """Encrypt data with user's secret key"""
        from cryptography.fernet import Fernet
        derived_key = self.derive_key(secret_key)
        fernet = Fernet(derived_key)
        if isinstance(data, str):
            data = data.encode('utf-8')
        return fernet.encrypt(data)

    def decrypt(self, data, secret_key):
        """Decrypt data with user's secret key"""
        from cryptography.fernet import Fernet
        derived_key = self.derive_key(secret_key)
        fernet = Fernet(derived_key)
        return fernet.decrypt(data)


class EncryptionService:
    """Two-layer encryption service combining master key and user secret key"""

    def __init__(self):
        self.master = MasterKeyManager()
        self.secret = SecretKeyManager()

    def encrypt_results(self, results, secret_key):
        """Encrypt results with both layers"""
        # First encrypt with user's secret key
        json_data = json.dumps(results)
        user_encrypted = self.secret.encrypt(json_data, secret_key)
        # Then encrypt with master key
        return self.master.encrypt(user_encrypted)

    def decrypt_results(self, encrypted_data, secret_key):
        """Decrypt results with both layers"""
        # First decrypt with master key
        user_encrypted = self.master.decrypt(encrypted_data)
        # Then decrypt with user's secret key
        decrypted = self.secret.decrypt(user_encrypted, secret_key)
        return json.loads(decrypted.decode('utf-8'))

    def encrypt_filename(self, filename):
        """Encrypt filename with master key only"""
        return self.master.encrypt(filename)

    def decrypt_filename(self, encrypted_filename):
        """Decrypt filename with master key"""
        return self.master.decrypt(encrypted_filename).decode('utf-8')

    def hash_secret_key(self, secret_key):
        """Hash secret key for validation storage"""
        return self.secret.hash_secret_key(secret_key)


# ============================================================================
# Key Generator for Entry References
# ============================================================================

class KeyGenerator:
    """Generates sequential MSB entry references"""

    def __init__(self, db_path):
        self.db_path = db_path
        self._lock = threading.Lock()

    def get_next_ref(self):
        """Generate next MSB reference (MSB0001, MSB0002, etc.)"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            try:
                # Get current value
                cursor.execute('SELECT current_value FROM entry_sequence WHERE id = 1')
                row = cursor.fetchone()
                if row:
                    current = row[0]
                else:
                    current = 0
                    cursor.execute('INSERT INTO entry_sequence (id, current_value) VALUES (1, 0)')

                # Increment
                next_value = current + 1
                cursor.execute('UPDATE entry_sequence SET current_value = ? WHERE id = 1', (next_value,))
                conn.commit()

                return f'MSB{next_value:04d}'
            finally:
                conn.close()


# ============================================================================
# Result Storage
# ============================================================================

class ResultStorage:
    """Stores and retrieves encrypted analysis results"""

    def __init__(self):
        self.db_path = DATABASE_FILE
        self.encryption = EncryptionService()
        self.key_gen = KeyGenerator(self.db_path)
        self._init_db()

    def _init_db(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Main results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_ref TEXT UNIQUE NOT NULL,
                secret_key_hash TEXT NOT NULL,
                original_filename_encrypted BLOB NOT NULL,
                file_type TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                results_encrypted BLOB NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                access_count INTEGER DEFAULT 0,
                last_accessed_at TIMESTAMP
            )
        ''')

        # Entry sequence table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS entry_sequence (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                current_value INTEGER NOT NULL DEFAULT 0
            )
        ''')

        # Access log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_ref TEXT NOT NULL,
                action TEXT NOT NULL,
                client_ip TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.commit()
        conn.close()

    def store(self, filename, file_type, file_data, results, secret_key, client_ip=None):
        """Store analysis results"""
        entry_ref = self.key_gen.get_next_ref()

        # Calculate file hash
        file_hash = hashlib.sha256(file_data).hexdigest()
        file_size = len(file_data)

        # Encrypt data
        encrypted_filename = self.encryption.encrypt_filename(filename)
        encrypted_results = self.encryption.encrypt_results(results, secret_key)
        secret_key_hash = self.encryption.hash_secret_key(secret_key)

        # Calculate expiration
        expires_at = datetime.now() + timedelta(days=EXPIRATION_DAYS)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                INSERT INTO analysis_results
                (entry_ref, secret_key_hash, original_filename_encrypted, file_type,
                 file_hash, file_size, results_encrypted, risk_score, risk_level, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                entry_ref,
                secret_key_hash,
                encrypted_filename,
                file_type,
                file_hash,
                file_size,
                encrypted_results,
                results.get('riskScore', 0),
                results.get('riskLevel', 'Low'),
                expires_at.isoformat()
            ))

            # Log creation
            cursor.execute('''
                INSERT INTO access_log (entry_ref, action, client_ip)
                VALUES (?, 'created', ?)
            ''', (entry_ref, client_ip))

            conn.commit()
            return entry_ref, expires_at.isoformat()

        finally:
            conn.close()

    def retrieve(self, entry_ref, secret_key, client_ip=None):
        """Retrieve and decrypt analysis results"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                SELECT secret_key_hash, original_filename_encrypted, file_type,
                       file_hash, file_size, results_encrypted, risk_score, risk_level,
                       created_at, expires_at, access_count
                FROM analysis_results
                WHERE entry_ref = ?
            ''', (entry_ref,))

            row = cursor.fetchone()
            if not row:
                return None, 'Entry not found'

            (secret_key_hash, encrypted_filename, file_type, file_hash, file_size,
             encrypted_results, risk_score, risk_level, created_at, expires_at, access_count) = row

            # Check expiration
            if expires_at:
                exp_date = datetime.fromisoformat(expires_at)
                if datetime.now() > exp_date:
                    return None, 'Entry has expired'

            # Validate secret key
            provided_hash = self.encryption.hash_secret_key(secret_key)
            if provided_hash != secret_key_hash:
                return None, 'Invalid secret key'

            # Decrypt results
            try:
                results = self.encryption.decrypt_results(encrypted_results, secret_key)
                filename = self.encryption.decrypt_filename(encrypted_filename)
            except Exception:
                return None, 'Decryption failed - invalid secret key'

            # Update access count
            cursor.execute('''
                UPDATE analysis_results
                SET access_count = access_count + 1, last_accessed_at = CURRENT_TIMESTAMP
                WHERE entry_ref = ?
            ''', (entry_ref,))

            # Log retrieval
            cursor.execute('''
                INSERT INTO access_log (entry_ref, action, client_ip)
                VALUES (?, 'retrieved', ?)
            ''', (entry_ref, client_ip))

            conn.commit()

            return {
                'entryRef': entry_ref,
                'originalFilename': filename,
                'fileType': file_type,
                'fileHash': file_hash,
                'fileSize': file_size,
                'riskScore': risk_score,
                'riskLevel': risk_level,
                'createdAt': created_at,
                'expiresAt': expires_at,
                'accessCount': access_count + 1,
                'results': results
            }, None

        finally:
            conn.close()

    def delete(self, entry_ref, secret_key, client_ip=None):
        """Delete stored results"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # First verify ownership
            cursor.execute('''
                SELECT secret_key_hash FROM analysis_results WHERE entry_ref = ?
            ''', (entry_ref,))

            row = cursor.fetchone()
            if not row:
                return False, 'Entry not found'

            # Validate secret key
            provided_hash = self.encryption.hash_secret_key(secret_key)
            if provided_hash != row[0]:
                return False, 'Invalid secret key'

            # Delete
            cursor.execute('DELETE FROM analysis_results WHERE entry_ref = ?', (entry_ref,))

            # Log deletion
            cursor.execute('''
                INSERT INTO access_log (entry_ref, action, client_ip)
                VALUES (?, 'deleted', ?)
            ''', (entry_ref, client_ip))

            conn.commit()
            return True, None

        finally:
            conn.close()

    def get_stats(self):
        """Get storage statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('SELECT COUNT(*) FROM analysis_results')
            total_count = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM analysis_results WHERE expires_at < ?',
                          (datetime.now().isoformat(),))
            expired_count = cursor.fetchone()[0]

            cursor.execute('''
                SELECT file_type, COUNT(*) FROM analysis_results
                GROUP BY file_type
            ''')
            by_type = dict(cursor.fetchall())

            cursor.execute('''
                SELECT risk_level, COUNT(*) FROM analysis_results
                GROUP BY risk_level
            ''')
            by_risk = dict(cursor.fetchall())

            return {
                'totalEntries': total_count,
                'expiredEntries': expired_count,
                'byType': by_type,
                'byRiskLevel': by_risk
            }

        finally:
            conn.close()

    def cleanup_expired(self, client_ip=None):
        """Remove expired entries"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Get expired entries
            cursor.execute('''
                SELECT entry_ref FROM analysis_results WHERE expires_at < ?
            ''', (datetime.now().isoformat(),))

            expired = cursor.fetchall()

            # Delete and log
            for (entry_ref,) in expired:
                cursor.execute('DELETE FROM analysis_results WHERE entry_ref = ?', (entry_ref,))
                cursor.execute('''
                    INSERT INTO access_log (entry_ref, action, client_ip)
                    VALUES (?, 'expired', ?)
                ''', (entry_ref, client_ip))

            conn.commit()
            return len(expired)

        finally:
            conn.close()


# Initialize storage globally
_storage = None

def get_storage():
    global _storage
    if _storage is None:
        _storage = ResultStorage()
    return _storage


# ============================================================================
# External Lookup Functions (Enrichment)
# ============================================================================

def get_cached(key):
    """Get cached value if not expired"""
    with _cache_lock:
        if key in _lookup_cache:
            value, timestamp = _lookup_cache[key]
            if datetime.now().timestamp() - timestamp < CACHE_TTL:
                return value
            else:
                del _lookup_cache[key]
    return None


def set_cached(key, value):
    """Set cached value"""
    with _cache_lock:
        _lookup_cache[key] = (value, datetime.now().timestamp())


def dns_lookup(domain):
    """Resolve domain to IP addresses"""
    cache_key = f'dns:{domain}'
    cached = get_cached(cache_key)
    if cached:
        return cached

    result = {
        'domain': domain,
        'ips': [],
        'error': None
    }

    try:
        ips = socket.gethostbyname_ex(domain)[2]
        result['ips'] = ips
    except socket.gaierror as e:
        result['error'] = str(e)
    except Exception as e:
        result['error'] = str(e)

    set_cached(cache_key, result)
    return result


def whois_lookup(domain):
    """Get WHOIS information for domain"""
    cache_key = f'whois:{domain}'
    cached = get_cached(cache_key)
    if cached:
        return cached

    result = {
        'domain': domain,
        'registrar': None,
        'creation_date': None,
        'expiration_date': None,
        'registrant_country': None,
        'domain_age_days': None,
        'error': None
    }

    try:
        import whois
        w = whois.whois(domain)

        result['registrar'] = w.registrar if hasattr(w, 'registrar') else None

        # Handle creation date (can be list or single value)
        creation = w.creation_date if hasattr(w, 'creation_date') else None
        if isinstance(creation, list):
            creation = creation[0] if creation else None
        if creation:
            result['creation_date'] = creation.isoformat() if hasattr(creation, 'isoformat') else str(creation)
            try:
                age = (datetime.now() - creation).days
                result['domain_age_days'] = age
            except Exception:
                pass

        # Handle expiration date
        expiry = w.expiration_date if hasattr(w, 'expiration_date') else None
        if isinstance(expiry, list):
            expiry = expiry[0] if expiry else None
        if expiry:
            result['expiration_date'] = expiry.isoformat() if hasattr(expiry, 'isoformat') else str(expiry)

        # Registrant country
        if hasattr(w, 'country'):
            result['registrant_country'] = w.country
        elif hasattr(w, 'registrant_country'):
            result['registrant_country'] = w.registrant_country

    except Exception as e:
        result['error'] = str(e)

    set_cached(cache_key, result)
    return result


def ip_lookup(ip):
    """Get geolocation and ISP info for IP"""
    cache_key = f'ip:{ip}'
    cached = get_cached(cache_key)
    if cached:
        return cached

    result = {
        'ip': ip,
        'country': None,
        'city': None,
        'isp': None,
        'org': None,
        'asn': None,
        'is_proxy': None,
        'is_hosting': None,
        'error': None
    }

    try:
        api_url = f'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,isp,org,as,mobile,proxy,hosting,query'
        req = urllib.request.Request(api_url, headers={'User-Agent': 'IPLookup/1.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())

        if data.get('status') == 'success':
            result['country'] = data.get('country')
            result['country_code'] = data.get('countryCode')
            result['city'] = data.get('city')
            result['isp'] = data.get('isp')
            result['org'] = data.get('org')
            result['asn'] = data.get('as')
            result['is_proxy'] = data.get('proxy')
            result['is_hosting'] = data.get('hosting')
        else:
            result['error'] = data.get('message', 'Lookup failed')

    except Exception as e:
        result['error'] = str(e)

    set_cached(cache_key, result)
    return result


def check_abuse_ipdb(ip):
    """Check IP against AbuseIPDB for threat intelligence"""
    # Try using threat_intel module first
    if THREAT_INTEL_AVAILABLE:
        result = threat_intel.check_abuseipdb(ip)
        if 'error' not in result:
            return result
        # Fall through to original method if error

    # Original implementation as fallback
    api_key = get_abuseipdb_key()
    if not api_key:
        return None

    cache_key = f'abuse:{ip}'
    cached = get_cached(cache_key)
    if cached:
        return cached

    try:
        url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose=true'
        req = urllib.request.Request(url, headers={
            'Key': api_key,
            'Accept': 'application/json'
        })
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            result = data.get('data')
            set_cached(cache_key, result)
            return result
    except Exception as e:
        print(f"AbuseIPDB error: {e}")
        return None


def investigate_iocs(ips=None, urls=None, hashes=None, max_per_type=5):
    """
    Investigate IOCs using threat intelligence APIs.
    Returns investigation results for all IOC types.
    """
    if not THREAT_INTEL_AVAILABLE:
        return {
            'error': 'Threat intelligence module not available',
            'ips': [],
            'urls': [],
            'hashes': []
        }

    try:
        return threat_intel.investigate_all_iocs(
            ips=ips or [],
            urls=urls or [],
            hashes=hashes or [],
            max_per_type=max_per_type
        )
    except Exception as e:
        print(f"IOC investigation error: {e}")
        return {
            'error': str(e),
            'ips': [],
            'urls': [],
            'hashes': []
        }


def get_threat_intel_status():
    """Get status of configured threat intelligence services"""
    if not THREAT_INTEL_AVAILABLE:
        return {
            'available': False,
            'services': {}
        }

    try:
        return {
            'available': True,
            'services': threat_intel.get_configured_services()
        }
    except Exception as e:
        return {
            'available': False,
            'error': str(e),
            'services': {}
        }


def enrich_url(url):
    """Enrich URL with DNS, IP lookup, and threat intel"""
    result = {
        'url': url,
        'domain': None,
        'dns': None,
        'ip_info': [],
        'threat_info': []
    }

    try:
        parsed = urlparse(url)
        domain = parsed.netloc

        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]

        if not domain:
            return result

        result['domain'] = domain

        # DNS lookup
        dns_result = dns_lookup(domain)
        result['dns'] = dns_result

        # IP lookups for resolved IPs
        if dns_result.get('ips'):
            for ip in dns_result['ips'][:3]:  # Limit to 3 IPs
                ip_info = ip_lookup(ip)
                result['ip_info'].append(ip_info)

                # Threat intel
                threat = check_abuse_ipdb(ip)
                if threat:
                    result['threat_info'].append({
                        'ip': ip,
                        'abuse_score': threat.get('abuseConfidenceScore', 0),
                        'total_reports': threat.get('totalReports', 0),
                        'is_tor': threat.get('isTor', False)
                    })

    except Exception as e:
        result['error'] = str(e)

    return result


def enrich_domain(domain):
    """Enrich domain with WHOIS, DNS, and IP lookups"""
    result = {
        'domain': domain,
        'whois': None,
        'dns': None,
        'ip_info': [],
        'is_new_domain': False
    }

    # WHOIS lookup
    whois_result = whois_lookup(domain)
    result['whois'] = whois_result

    # Flag new domains (less than 30 days old)
    if whois_result.get('domain_age_days') is not None:
        if whois_result['domain_age_days'] < 30:
            result['is_new_domain'] = True

    # DNS lookup
    dns_result = dns_lookup(domain)
    result['dns'] = dns_result

    # IP lookups
    if dns_result.get('ips'):
        for ip in dns_result['ips'][:3]:
            ip_info = ip_lookup(ip)
            result['ip_info'].append(ip_info)

    return result


# ============================================================================
# QR Code Detection Functions
# ============================================================================

def decode_qr_codes(image_data):
    """Decode QR codes from image data with enhanced preprocessing for better detection"""
    results = []
    seen_data = set()

    try:
        from pyzbar import pyzbar
        from PIL import Image, ImageEnhance, ImageFilter

        # Try to open the image
        image = Image.open(io.BytesIO(image_data))

        # Store original size for scaling attempts
        original_size = image.size

        # Create list of image variants to try
        image_variants = []

        # Variant 1: Original converted to RGB
        img_rgb = image.convert('RGB') if image.mode not in ('RGB', 'L') else image
        image_variants.append(('original', img_rgb))

        # Variant 2: Grayscale
        img_gray = image.convert('L')
        image_variants.append(('grayscale', img_gray))

        # Variant 3: Enhanced contrast
        try:
            enhancer = ImageEnhance.Contrast(img_gray)
            img_contrast = enhancer.enhance(2.0)
            image_variants.append(('high_contrast', img_contrast))
        except Exception:
            pass

        # Variant 4: Sharpened
        try:
            img_sharp = img_gray.filter(ImageFilter.SHARPEN)
            image_variants.append(('sharpened', img_sharp))
        except Exception:
            pass

        # Variant 5: Scaled up (helps with small QR codes)
        if original_size[0] < 500 or original_size[1] < 500:
            try:
                scale_factor = max(500 / original_size[0], 500 / original_size[1])
                new_size = (int(original_size[0] * scale_factor), int(original_size[1] * scale_factor))
                img_scaled = img_gray.resize(new_size, Image.Resampling.LANCZOS)
                image_variants.append(('scaled_up', img_scaled))
            except Exception:
                pass

        # Variant 6: Thresholded (binarized) - helps with poor contrast
        try:
            threshold = 128
            img_thresh = img_gray.point(lambda p: 255 if p > threshold else 0)
            image_variants.append(('threshold', img_thresh))
        except Exception:
            pass

        # Try decoding each variant
        for variant_name, img_variant in image_variants:
            try:
                decoded_objects = pyzbar.decode(img_variant)

                for obj in decoded_objects:
                    # Accept QR codes and similar 2D codes
                    if obj.type in ('QRCODE', 'PDF417', 'SQCODE'):
                        data = obj.data.decode('utf-8', errors='ignore')

                        # Skip duplicates
                        if data in seen_data:
                            continue
                        seen_data.add(data)

                        qr_info = analyze_qr_data(data)
                        qr_info['raw_data'] = data[:500]
                        qr_info['type'] = obj.type
                        qr_info['rect'] = {
                            'left': obj.rect.left,
                            'top': obj.rect.top,
                            'width': obj.rect.width,
                            'height': obj.rect.height
                        }
                        qr_info['decode_method'] = variant_name
                        results.append(qr_info)
            except Exception:
                continue

            # If we found QR codes, no need to try more variants
            if results:
                break

    except ImportError:
        logging.warning("pyzbar not installed - QR code detection unavailable")
    except Exception as e:
        logging.warning(f"QR code decode error: {e}")

    return results


def analyze_qr_data(data):
    """Analyze QR code data and classify its content"""
    result = {
        'data_type': 'text',
        'urls': [],
        'enriched_urls': [],
        'emails': [],
        'phones': [],
        'wifi': None,
        'is_vcard': False,
        'risk_indicators': []
    }

    # Check for URLs
    urls = QR_URL_PATTERN.findall(data)
    if urls:
        result['data_type'] = 'url'
        result['urls'] = urls[:10]  # Limit to 10 URLs

        # Enrich URLs
        for url in urls[:5]:  # Enrich first 5
            enriched = enrich_url(url)
            download_info = extract_download_info(url)
            enriched['download'] = download_info
            result['enriched_urls'].append(enriched)

            # Check for suspicious URL characteristics
            if download_info.get('is_high_risk'):
                result['risk_indicators'].append({
                    'type': 'high_risk_download',
                    'severity': 'high',
                    'description': f'QR code contains high-risk download: {download_info.get("target_filename")}'
                })

            # Check for URL shorteners (often used to hide malicious URLs)
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
                         'adf.ly', 'j.mp', 'rb.gy', 'shorturl.at', 'cutt.ly']
            parsed_url = urlparse(url)
            if any(shortener in parsed_url.netloc.lower() for shortener in shorteners):
                result['risk_indicators'].append({
                    'type': 'url_shortener',
                    'severity': 'medium',
                    'description': f'QR code uses URL shortener: {parsed_url.netloc}'
                })

    # Check for email addresses
    emails = QR_EMAIL_PATTERN.findall(data)
    if emails:
        result['data_type'] = 'mailto' if not urls else result['data_type']
        result['emails'] = emails[:5]

    # Check for phone numbers
    phones = QR_PHONE_PATTERN.findall(data)
    if phones:
        result['data_type'] = 'tel' if not urls and not emails else result['data_type']
        result['phones'] = [p.strip() for p in phones[:5]]

    # Check for WiFi credentials
    if QR_WIFI_PATTERN.search(data):
        result['data_type'] = 'wifi'
        result['wifi'] = parse_wifi_qr(data)
        result['risk_indicators'].append({
            'type': 'wifi_credentials',
            'severity': 'medium',
            'description': 'QR code contains WiFi network credentials'
        })

    # Check for vCard
    if QR_VCARD_PATTERN.search(data):
        result['data_type'] = 'vcard'
        result['is_vcard'] = True

    # Check for suspicious patterns in data
    suspicious_patterns = [
        (r'password', 'password exposure'),
        (r'credential', 'credential exposure'),
        (r'api[_-]?key', 'API key exposure'),
        (r'secret', 'secret exposure'),
        (r'token', 'token exposure'),
    ]

    data_lower = data.lower()
    for pattern, desc in suspicious_patterns:
        if re.search(pattern, data_lower):
            result['risk_indicators'].append({
                'type': 'sensitive_data',
                'severity': 'high',
                'description': f'QR code may contain {desc}'
            })
            break

    return result


def parse_wifi_qr(data):
    """Parse WiFi QR code data (WIFI:T:WPA;S:network;P:password;;)"""
    wifi_info = {
        'ssid': None,
        'security': None,
        'hidden': False
    }

    try:
        # Extract SSID
        ssid_match = re.search(r'S:([^;]*)', data)
        if ssid_match:
            wifi_info['ssid'] = ssid_match.group(1)

        # Extract security type
        type_match = re.search(r'T:([^;]*)', data)
        if type_match:
            wifi_info['security'] = type_match.group(1)

        # Check if hidden
        if 'H:true' in data.lower():
            wifi_info['hidden'] = True

    except Exception:
        pass

    return wifi_info


def extract_images_from_email(msg):
    """Extract images from email message for QR code scanning"""
    images = []

    try:
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()

                # Check for image attachments
                if content_type.startswith('image/'):
                    try:
                        payload = part.get_payload(decode=True)
                        if payload and len(payload) < 10 * 1024 * 1024:  # Max 10MB per image
                            images.append({
                                'data': payload,
                                'filename': part.get_filename() or 'inline_image',
                                'content_type': content_type,
                                'source': 'attachment'
                            })
                    except Exception:
                        pass

                # Check for inline images in HTML (embedded base64)
                elif content_type == 'text/html':
                    try:
                        html_content = part.get_content()
                        if isinstance(html_content, bytes):
                            html_content = html_content.decode('utf-8', errors='ignore')

                        # Find base64 encoded images
                        img_pattern = re.compile(r'data:image/([^;]+);base64,([A-Za-z0-9+/=]+)', re.IGNORECASE)
                        for match in img_pattern.finditer(html_content):
                            try:
                                img_type = match.group(1)
                                img_data = base64.b64decode(match.group(2))
                                if len(img_data) < 10 * 1024 * 1024:
                                    images.append({
                                        'data': img_data,
                                        'filename': f'inline_base64.{img_type}',
                                        'content_type': f'image/{img_type}',
                                        'source': 'inline_base64'
                                    })
                            except Exception:
                                pass
                    except Exception:
                        pass

    except Exception:
        pass

    return images[:20]  # Limit to 20 images


def extract_images_from_pdf(file_data):
    """Extract images from PDF for QR code scanning"""
    images = []

    try:
        from pypdf import PdfReader
        from PIL import Image

        reader = PdfReader(io.BytesIO(file_data))

        for page_num, page in enumerate(reader.pages[:10]):  # Limit to first 10 pages
            try:
                # Use pypdf's built-in image extraction
                if hasattr(page, 'images'):
                    for img_idx, image in enumerate(page.images):
                        try:
                            img_data = image.data
                            if img_data and len(img_data) < 10 * 1024 * 1024:
                                images.append({
                                    'data': img_data,
                                    'filename': f'page{page_num + 1}_img{img_idx + 1}.{image.name.split(".")[-1] if "." in image.name else "png"}',
                                    'content_type': f'image/{image.name.split(".")[-1] if "." in image.name else "png"}',
                                    'source': f'page_{page_num + 1}'
                                })
                        except Exception:
                            pass

                # Fallback: Manual XObject extraction
                if '/XObject' in page.get('/Resources', {}):
                    xobject = page['/Resources']['/XObject'].get_object()

                    for obj_name in xobject:
                        obj = xobject[obj_name]
                        if hasattr(obj, 'get_object'):
                            obj = obj.get_object()

                        if obj.get('/Subtype') == '/Image':
                            try:
                                width = int(obj.get('/Width', 0))
                                height = int(obj.get('/Height', 0))

                                if width > 0 and height > 0:
                                    # Try to get decoded data using pypdf's get_data()
                                    try:
                                        raw_data = obj.get_data()
                                        if raw_data:
                                            color_space = str(obj.get('/ColorSpace', '/DeviceRGB'))
                                            bits = int(obj.get('/BitsPerComponent', 8))

                                            if '/DeviceGray' in color_space:
                                                mode = 'L'
                                            elif '/DeviceCMYK' in color_space:
                                                mode = 'CMYK'
                                            else:
                                                mode = 'RGB'

                                            try:
                                                img = Image.frombytes(mode, (width, height), raw_data)
                                                if mode == 'CMYK':
                                                    img = img.convert('RGB')
                                                img_buffer = io.BytesIO()
                                                img.save(img_buffer, format='PNG')
                                                img_data = img_buffer.getvalue()
                                                if len(img_data) < 10 * 1024 * 1024:
                                                    images.append({
                                                        'data': img_data,
                                                        'filename': f'page{page_num + 1}_{obj_name}.png',
                                                        'content_type': 'image/png',
                                                        'source': f'page_{page_num + 1}'
                                                    })
                                            except Exception:
                                                pass
                                    except Exception:
                                        pass
                            except Exception:
                                pass
            except Exception:
                pass

    except ImportError:
        pass
    except Exception:
        pass

    return images[:30]  # Limit to 30 images


def generate_pdf_page_screenshots(file_data, max_pages=10, dpi=150):
    """Generate screenshots of PDF pages using PyMuPDF"""
    screenshots = []

    try:
        import fitz  # PyMuPDF

        doc = fitz.open(stream=file_data, filetype="pdf")
        num_pages = min(doc.page_count, max_pages)

        for page_num in range(num_pages):
            try:
                page = doc[page_num]
                # Render page as image
                zoom = dpi / 72  # 72 dpi is the default
                mat = fitz.Matrix(zoom, zoom)
                pix = page.get_pixmap(matrix=mat)

                # Convert to PNG bytes
                img_bytes = pix.tobytes("png")

                # Encode as base64
                img_base64 = base64.b64encode(img_bytes).decode('utf-8')
                screenshots.append(img_base64)

            except Exception as e:
                print(f"[PDF Screenshot] Failed to render page {page_num + 1}: {e}")
                continue

        doc.close()

    except ImportError:
        print("[PDF Screenshot] PyMuPDF (fitz) not installed")
    except Exception as e:
        print(f"[PDF Screenshot] Error: {e}")

    return screenshots


def generate_office_screenshots(file_data, filename, max_pages=10):
    """Generate screenshots of Office documents by converting to PDF first"""
    screenshots = []

    try:
        import subprocess
        import tempfile

        # Check if LibreOffice is available
        result = subprocess.run(['which', 'libreoffice'], capture_output=True, text=True)
        if result.returncode != 0:
            print("[Office Screenshot] LibreOffice not available")
            return screenshots

        with tempfile.TemporaryDirectory() as tmpdir:
            # Save the file temporarily
            input_path = os.path.join(tmpdir, filename)
            with open(input_path, 'wb') as f:
                f.write(file_data)

            # Convert to PDF using LibreOffice
            try:
                subprocess.run([
                    'libreoffice', '--headless', '--convert-to', 'pdf',
                    '--outdir', tmpdir, input_path
                ], capture_output=True, timeout=60)

                # Find the converted PDF
                pdf_filename = os.path.splitext(filename)[0] + '.pdf'
                pdf_path = os.path.join(tmpdir, pdf_filename)

                if os.path.exists(pdf_path):
                    with open(pdf_path, 'rb') as f:
                        pdf_data = f.read()
                    screenshots = generate_pdf_page_screenshots(pdf_data, max_pages)

            except subprocess.TimeoutExpired:
                print("[Office Screenshot] Conversion timed out")
            except Exception as e:
                print(f"[Office Screenshot] Conversion error: {e}")

    except Exception as e:
        print(f"[Office Screenshot] Error: {e}")

    return screenshots


def scan_for_qr_codes(images):
    """Scan a list of images for QR codes"""
    all_qr_codes = []
    seen_data = set()  # Deduplicate based on raw QR data

    for img_info in images:
        try:
            qr_codes = decode_qr_codes(img_info['data'])
            for qr in qr_codes:
                # Deduplicate based on raw data content
                raw_data = qr.get('raw_data', '')
                if raw_data in seen_data:
                    continue
                seen_data.add(raw_data)

                qr['source_image'] = img_info.get('filename', 'unknown')
                qr['source_location'] = img_info.get('source', 'unknown')
                all_qr_codes.append(qr)
        except Exception:
            pass

    return all_qr_codes


def extract_download_info(url):
    """Extract download target information from URL"""
    result = {
        'url': url,
        'is_download': False,
        'target_filename': None,
        'extension': None,
        'is_high_risk': False
    }

    try:
        parsed = urlparse(url)
        path = parsed.path

        # Extract filename from path
        if '/' in path:
            potential_filename = path.split('/')[-1]
            if '.' in potential_filename:
                result['target_filename'] = potential_filename
                ext = '.' + potential_filename.split('.')[-1].lower()
                result['extension'] = ext
                result['is_download'] = True
                result['is_high_risk'] = ext in HIGH_RISK_EXTENSIONS

    except Exception:
        pass

    return result


# ============================================================================
# Analysis Functions
# ============================================================================

def generate_file_analysis_verdict(analysis_type: str, result: dict, filename: str) -> str:
    """Generate a human-readable verdict summary for file analysis"""
    risk_score = result.get('riskScore', 0)
    risk_level = result.get('riskLevel', 'Unknown')

    parts = []

    # Risk assessment
    if risk_score >= 70:
        parts.append(f"HIGH RISK ({risk_score}/100)")
    elif risk_score >= 40:
        parts.append(f"MODERATE RISK ({risk_score}/100)")
    elif risk_score >= 20:
        parts.append(f"LOW RISK ({risk_score}/100)")
    else:
        parts.append(f"CLEAN ({risk_score}/100)")

    if analysis_type == 'email':
        # Email-specific verdict
        subject = result.get('subject', '')[:50]
        sender = result.get('from', '')
        attachments = result.get('attachments', [])
        links = result.get('links', [])
        suspicious = result.get('suspiciousIndicators', [])

        if subject:
            parts.append(f"Subject: \"{subject}{'...' if len(result.get('subject', '')) > 50 else ''}\"")

        if sender:
            parts.append(f"From: {sender}.")

        threats = []
        if attachments:
            dangerous_exts = [a for a in attachments if any(ext in a.get('filename', '').lower()
                            for ext in ['.exe', '.dll', '.js', '.vbs', '.bat', '.ps1', '.scr'])]
            if dangerous_exts:
                threats.append(f"{len(dangerous_exts)} dangerous attachment(s)")
            else:
                parts.append(f"Contains {len(attachments)} attachment(s).")

        if links:
            suspicious_links = [l for l in links if l.get('suspicious')]
            if suspicious_links:
                threats.append(f"{len(suspicious_links)} suspicious link(s)")

        if suspicious:
            threats.extend(suspicious[:3])

        if threats:
            parts.append(f"Detected: {', '.join(threats)}.")
            parts.append("RECOMMENDATION: Do not click links or open attachments. Verify sender identity.")
        elif risk_score < 20:
            parts.append("No obvious phishing indicators detected.")

    elif analysis_type == 'pdf':
        # PDF-specific verdict
        has_js = result.get('hasJavaScript', False)
        has_action = result.get('hasAutoAction', False)
        has_embedded = result.get('hasEmbeddedFiles', False)
        suspicious = result.get('suspiciousElements', [])

        threats = []
        if has_js:
            threats.append("contains JavaScript")
        if has_action:
            threats.append("has auto-open actions")
        if has_embedded:
            threats.append("contains embedded files")

        if threats:
            parts.append(f"PDF {', '.join(threats)}.")
            parts.append("RECOMMENDATION: Open in isolated viewer or sandbox. Do not enable active content.")
        else:
            parts.append("PDF appears to be a standard document without active content.")

    elif analysis_type == 'office':
        # Office document verdict
        has_macros = result.get('hasMacros', False)
        macro_type = result.get('macroType', '')
        suspicious = result.get('suspiciousIndicators', [])
        external = result.get('externalLinks', [])

        threats = []
        if has_macros:
            threats.append(f"contains {macro_type or 'VBA'} macros")
        if external:
            threats.append(f"{len(external)} external link(s)")
        if suspicious:
            threats.extend(suspicious[:2])

        if threats:
            parts.append(f"Document {', '.join(threats)}.")
            if has_macros:
                parts.append("RECOMMENDATION: Do not enable macros. Analyze in sandbox if execution is needed.")
            else:
                parts.append("RECOMMENDATION: Verify document source before opening.")
        else:
            parts.append("Document appears clean with no macros or suspicious content.")

    elif analysis_type == 'qrcode':
        # QR code verdict
        decoded = result.get('decoded', [])
        if decoded:
            urls = [d for d in decoded if d.get('type') == 'url']
            if urls:
                url = urls[0].get('data', '')[:50]
                parts.append(f"QR code links to: {url}{'...' if len(urls[0].get('data', '')) > 50 else ''}")

                if risk_score > 0:
                    parts.append("RECOMMENDATION: Verify URL reputation before visiting.")
                else:
                    parts.append("URL appears safe, but verify before entering credentials.")
        else:
            parts.append("No decodable content found in image.")

    return " ".join(parts)


def analyze_email(file_data):
    """Analyze an email file (.eml) for security indicators"""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(file_data)

        # Extract basic headers
        headers = {
            'from': msg.get('From', ''),
            'to': msg.get('To', ''),
            'subject': msg.get('Subject', ''),
            'date': msg.get('Date', ''),
            'message_id': msg.get('Message-ID', ''),
            'reply_to': msg.get('Reply-To', ''),
            'return_path': msg.get('Return-Path', ''),
        }

        # Extract sender domain and enrich
        sender_domain = None
        sender_domain_info = None
        from_addr = headers.get('from', '')
        domain_match = re.search(r'@([a-zA-Z0-9.-]+)', from_addr)
        if domain_match:
            sender_domain = domain_match.group(1).lower()
            sender_domain_info = enrich_domain(sender_domain)

        # Extract routing path (Received headers) with IP enrichment
        received_headers = msg.get_all('Received', [])
        routing_path = []
        routing_ips = []

        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

        for recv in received_headers[:10]:  # Limit to 10
            recv_str = str(recv)[:200]
            routing_path.append(recv_str)

            # Extract IPs from routing
            ips = ip_pattern.findall(recv_str)
            for ip in ips:
                if not ip.startswith(('10.', '192.168.', '127.')):
                    ip_info = ip_lookup(ip)
                    threat = check_abuse_ipdb(ip)
                    routing_ips.append({
                        'ip': ip,
                        'info': ip_info,
                        'threat': threat
                    })

        # Parse authentication results
        auth_results = parse_authentication_results(msg)

        # Extract URLs from body with enrichment
        urls = extract_urls_from_email(msg)
        enriched_urls = []
        for url in urls[:20]:  # Limit enrichment to 20 URLs
            enriched = enrich_url(url)
            download_info = extract_download_info(url)
            enriched['download'] = download_info
            enriched_urls.append(enriched)

        # Extract attachments
        attachments = extract_attachments(msg)

        # Extract images and scan for QR codes
        images = extract_images_from_email(msg)
        qr_codes = scan_for_qr_codes(images)

        # Collect QR code URLs for phishing detection
        qr_urls = []
        qr_risk_indicators = []
        for qr in qr_codes:
            qr_urls.extend(qr.get('urls', []))
            qr_risk_indicators.extend(qr.get('risk_indicators', []))

        # Perform phishing detection (include QR code URLs)
        all_urls_for_detection = urls + qr_urls
        phishing_indicators = detect_phishing(msg, headers, all_urls_for_detection, attachments, auth_results)

        # Add QR-specific risk indicators
        for indicator in qr_risk_indicators:
            phishing_indicators.append(indicator)

        # Calculate risk score (include QR codes)
        risk_score = calculate_email_risk_score(phishing_indicators, auth_results, attachments, sender_domain_info, qr_codes)

        # Automatic IOC investigation using threat intel APIs
        ioc_investigation = None
        if THREAT_INTEL_AVAILABLE:
            # Collect unique IPs from routing
            investigation_ips = list(set([r['ip'] for r in routing_ips if r.get('ip')]))[:5]
            # Collect unique URLs
            investigation_urls = list(set(urls + qr_urls))[:10]
            # Collect attachment hashes
            investigation_hashes = [a.get('sha256') or a.get('md5') for a in attachments if a.get('sha256') or a.get('md5')][:5]

            if investigation_ips or investigation_urls or investigation_hashes:
                ioc_investigation = investigate_iocs(
                    ips=investigation_ips,
                    urls=investigation_urls,
                    hashes=investigation_hashes,
                    max_per_type=5
                )
                # Update risk score based on IOC findings
                if ioc_investigation.get('summary', {}).get('maliciousIOCs', 0) > 0:
                    ioc_risk = ioc_investigation['summary'].get('overallRiskScore', 0)
                    risk_score = max(risk_score, ioc_risk)
                    phishing_indicators.append({
                        'type': 'threat_intel',
                        'severity': 'high' if ioc_risk > 70 else 'medium',
                        'description': f"Threat intelligence: {ioc_investigation['summary']['maliciousIOCs']} malicious IOCs detected"
                    })

        return {
            'success': True,
            'type': 'email',
            'headers': headers,
            'senderDomain': sender_domain,
            'senderDomainInfo': sender_domain_info,
            'routingPath': routing_path,
            'routingIps': routing_ips[:5],  # Limit to 5
            'authentication': auth_results,
            'urls': urls[:50],  # Raw URLs
            'enrichedUrls': enriched_urls,
            'urlCount': len(urls),
            'attachments': attachments,
            'attachmentCount': len(attachments),
            'qrCodes': qr_codes,
            'qrCodeCount': len(qr_codes),
            'phishingIndicators': phishing_indicators,
            'riskScore': risk_score,
            'riskLevel': get_risk_level(risk_score),
            'iocInvestigation': ioc_investigation
        }
    except Exception as e:
        return {'success': False, 'error': f'Failed to parse email: {str(e)}'}


def parse_authentication_results(msg):
    """Parse SPF, DKIM, and DMARC results from headers"""
    auth_results = {
        'spf': {'status': 'unknown', 'details': ''},
        'dkim': {'status': 'unknown', 'details': ''},
        'dmarc': {'status': 'unknown', 'details': ''}
    }

    # Check Authentication-Results header
    auth_header = msg.get('Authentication-Results', '')
    if auth_header:
        auth_str = str(auth_header).lower()

        # SPF
        spf_match = re.search(r'spf=(pass|fail|softfail|neutral|none|temperror|permerror)', auth_str)
        if spf_match:
            auth_results['spf']['status'] = spf_match.group(1)

        # DKIM
        dkim_match = re.search(r'dkim=(pass|fail|none|neutral|temperror|permerror)', auth_str)
        if dkim_match:
            auth_results['dkim']['status'] = dkim_match.group(1)

        # DMARC
        dmarc_match = re.search(r'dmarc=(pass|fail|none|bestguesspass)', auth_str)
        if dmarc_match:
            auth_results['dmarc']['status'] = dmarc_match.group(1)

    # Also check individual headers
    spf_header = msg.get('Received-SPF', '')
    if spf_header:
        spf_str = str(spf_header).lower()
        if 'pass' in spf_str:
            auth_results['spf']['status'] = 'pass'
        elif 'fail' in spf_str:
            auth_results['spf']['status'] = 'fail'
        elif 'softfail' in spf_str:
            auth_results['spf']['status'] = 'softfail'
        auth_results['spf']['details'] = str(spf_header)[:200]

    dkim_sig = msg.get('DKIM-Signature', '')
    if dkim_sig:
        auth_results['dkim']['details'] = 'DKIM signature present'

    return auth_results


def extract_urls_from_email(msg):
    """Extract URLs from email body (text and HTML)"""
    urls = []
    url_pattern = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)

    # Get email body parts
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ('text/plain', 'text/html'):
                try:
                    body = part.get_content()
                    if isinstance(body, bytes):
                        body = body.decode('utf-8', errors='ignore')
                    found_urls = url_pattern.findall(body)
                    urls.extend(found_urls)
                except Exception:
                    pass
    else:
        try:
            body = msg.get_content()
            if isinstance(body, bytes):
                body = body.decode('utf-8', errors='ignore')
            urls = url_pattern.findall(body)
        except Exception:
            pass

    # Deduplicate and clean
    seen = set()
    unique_urls = []
    for url in urls:
        # Clean up URL
        url = url.rstrip('.,;:)>')
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)

    return unique_urls


def extract_attachments(msg):
    """Extract attachment metadata and data from email"""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get('Content-Disposition', ''))
            if 'attachment' in content_disposition or 'inline' in content_disposition:
                filename = part.get_filename()
                if filename:
                    content_type = part.get_content_type()
                    try:
                        payload = part.get_payload(decode=True) or b''
                        size = len(payload)
                        # Encode attachment data as base64 for frontend download/analysis
                        data_base64 = base64.b64encode(payload).decode('utf-8') if payload else None
                    except Exception:
                        size = 0
                        data_base64 = None

                    # Check if suspicious
                    ext = os.path.splitext(filename)[1].lower()
                    is_suspicious = ext in SUSPICIOUS_EXTENSIONS

                    # Calculate hashes for the attachment
                    att_md5 = None
                    att_sha256 = None
                    if payload:
                        att_md5 = hashlib.md5(payload).hexdigest()
                        att_sha256 = hashlib.sha256(payload).hexdigest()

                    attachments.append({
                        'filename': filename,
                        'contentType': content_type,
                        'size': size,
                        'extension': ext,
                        'isSuspicious': is_suspicious,
                        'data': data_base64,
                        'md5': att_md5,
                        'sha256': att_sha256
                    })

    return attachments


def detect_phishing(msg, headers, urls, attachments, auth_results):
    """Detect phishing indicators in email"""
    indicators = []

    # Check for failed authentication
    if auth_results['spf']['status'] in ('fail', 'softfail'):
        indicators.append({
            'type': 'auth_failure',
            'severity': 'high',
            'description': f"SPF check {auth_results['spf']['status']}"
        })

    if auth_results['dkim']['status'] == 'fail':
        indicators.append({
            'type': 'auth_failure',
            'severity': 'high',
            'description': 'DKIM signature verification failed'
        })

    if auth_results['dmarc']['status'] == 'fail':
        indicators.append({
            'type': 'auth_failure',
            'severity': 'high',
            'description': 'DMARC policy check failed'
        })

    # Check for URL/display text mismatch in HTML
    body_html = get_html_body(msg)
    if body_html:
        link_pattern = re.compile(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>', re.IGNORECASE)
        for match in link_pattern.finditer(body_html):
            href = match.group(1)
            display_text = match.group(2).strip()
            # Check if display text looks like a URL but differs from href
            if re.match(r'https?://', display_text, re.IGNORECASE):
                if href.split('/')[2] != display_text.split('/')[2]:
                    indicators.append({
                        'type': 'url_mismatch',
                        'severity': 'high',
                        'description': f'Link display text ({display_text[:50]}) differs from actual URL domain'
                    })
                    break  # One is enough

    # Check for lookalike domains in URLs
    for url in urls[:20]:  # Check first 20 URLs
        for pattern, brand in LOOKALIKE_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE) and brand not in url.lower():
                indicators.append({
                    'type': 'lookalike_domain',
                    'severity': 'high',
                    'description': f'Possible {brand} lookalike domain detected'
                })
                break

    # Check for urgency keywords in subject
    subject = headers.get('subject', '').lower()
    for keyword in URGENCY_KEYWORDS:
        if keyword in subject:
            indicators.append({
                'type': 'urgency',
                'severity': 'medium',
                'description': f'Urgency keyword detected: "{keyword}"'
            })
            break

    # Check for suspicious attachments
    for att in attachments:
        if att['isSuspicious']:
            indicators.append({
                'type': 'suspicious_attachment',
                'severity': 'high',
                'description': f'Suspicious attachment type: {att["filename"]}'
            })

    # Check for Reply-To mismatch
    from_addr = headers.get('from', '')
    reply_to = headers.get('reply_to', '')
    if reply_to and from_addr:
        from_domain = extract_domain_from_email(from_addr)
        reply_domain = extract_domain_from_email(reply_to)
        if from_domain and reply_domain and from_domain != reply_domain:
            indicators.append({
                'type': 'reply_mismatch',
                'severity': 'medium',
                'description': f'Reply-To domain ({reply_domain}) differs from From domain ({from_domain})'
            })

    return indicators


def get_html_body(msg):
    """Extract HTML body from email"""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/html':
                try:
                    body = part.get_content()
                    if isinstance(body, bytes):
                        body = body.decode('utf-8', errors='ignore')
                    return body
                except Exception:
                    pass
    elif msg.get_content_type() == 'text/html':
        try:
            body = msg.get_content()
            if isinstance(body, bytes):
                body = body.decode('utf-8', errors='ignore')
            return body
        except Exception:
            pass
    return ''


def extract_domain_from_email(email_addr):
    """Extract domain from email address"""
    match = re.search(r'@([a-zA-Z0-9.-]+)', email_addr)
    return match.group(1).lower() if match else None


def calculate_email_risk_score(indicators, auth_results, attachments, sender_domain_info=None, qr_codes=None):
    """Calculate risk score for email (0-100)"""
    score = 0

    # Base score for indicators
    for ind in indicators:
        if ind['severity'] == 'high':
            score += 20
        elif ind['severity'] == 'medium':
            score += 10
        else:
            score += 5

    # Bonus for failed authentication
    failed_auth = 0
    for key in ['spf', 'dkim', 'dmarc']:
        if auth_results[key]['status'] in ('fail', 'softfail'):
            failed_auth += 1
    score += failed_auth * 5

    # Bonus for suspicious attachments
    for att in attachments:
        if att['isSuspicious']:
            score += 15

    # Bonus for new domain (less than 30 days)
    if sender_domain_info and sender_domain_info.get('is_new_domain'):
        score += 15

    # QR code risk scoring
    if qr_codes:
        for qr in qr_codes:
            # QR codes with URLs are suspicious in emails
            if qr.get('urls'):
                score += 10
            # QR codes with URL shorteners are more suspicious
            for indicator in qr.get('risk_indicators', []):
                if indicator['severity'] == 'high':
                    score += 15
                elif indicator['severity'] == 'medium':
                    score += 8

    return min(score, 100)


def analyze_pdf(file_data):
    """Analyze a PDF file for security indicators"""
    try:
        from pypdf import PdfReader

        reader = PdfReader(io.BytesIO(file_data))

        # Extract metadata
        metadata = {}
        if reader.metadata:
            metadata = {
                'author': reader.metadata.get('/Author', ''),
                'creator': reader.metadata.get('/Creator', ''),
                'producer': reader.metadata.get('/Producer', ''),
                'subject': reader.metadata.get('/Subject', ''),
                'title': reader.metadata.get('/Title', ''),
                'creationDate': str(reader.metadata.get('/CreationDate', '')),
                'modDate': str(reader.metadata.get('/ModDate', '')),
            }

        page_count = len(reader.pages)

        # Scan for suspicious content
        javascript_found = []
        embedded_files = []
        urls = []
        forms = []
        external_refs = []
        http_requests = []
        download_urls = []
        process_triggers = []

        # Check document catalog
        if reader.trailer and '/Root' in reader.trailer:
            root = reader.trailer['/Root'].get_object()

            # Check for JavaScript
            if '/Names' in root:
                names = root['/Names']
                if isinstance(names, dict) or hasattr(names, 'get_object'):
                    names_obj = names.get_object() if hasattr(names, 'get_object') else names
                    if '/JavaScript' in names_obj:
                        javascript_found.append('Document-level JavaScript detected')

            # Check for OpenAction (auto-execute)
            if '/OpenAction' in root:
                javascript_found.append('OpenAction detected (auto-execute on open)')

            # Check for AcroForm (interactive forms)
            if '/AcroForm' in root:
                forms.append('Interactive form fields detected')

        # Scan pages for suspicious content
        url_pattern = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
        launch_pattern = re.compile(r'/Launch[^/]*(/F|/Win|/Unix|/Mac)', re.IGNORECASE)
        shell_pattern = re.compile(r'(cmd\.exe|powershell|bash|sh\s+-c)', re.IGNORECASE)

        for page_num, page in enumerate(reader.pages[:20]):  # Limit to first 20 pages
            # Check annotations for links and JavaScript
            if '/Annots' in page:
                try:
                    annots = page['/Annots']
                    if annots:
                        for annot in annots:
                            try:
                                annot_obj = annot.get_object() if hasattr(annot, 'get_object') else annot

                                # Check for JavaScript actions
                                if '/A' in annot_obj:
                                    action = annot_obj['/A']
                                    action_obj = action.get_object() if hasattr(action, 'get_object') else action
                                    if '/S' in action_obj:
                                        action_type = str(action_obj['/S'])
                                        if action_type == '/JavaScript':
                                            javascript_found.append(f'JavaScript action on page {page_num + 1}')
                                            # Check JS content for shell commands
                                            if '/JS' in action_obj:
                                                js_content = str(action_obj['/JS'])
                                                if shell_pattern.search(js_content):
                                                    process_triggers.append({
                                                        'type': 'javascript_shell',
                                                        'location': f'Page {page_num + 1}',
                                                        'pattern': 'Shell command in JavaScript'
                                                    })
                                        elif action_type == '/URI':
                                            if '/URI' in action_obj:
                                                uri = str(action_obj['/URI'])
                                                urls.append(uri)
                                                # Check for downloads
                                                download = extract_download_info(uri)
                                                if download['is_download']:
                                                    download_urls.append(download)
                                        elif action_type == '/Launch':
                                            external_refs.append(f'Launch action on page {page_num + 1}')
                                            process_triggers.append({
                                                'type': 'launch_action',
                                                'location': f'Page {page_num + 1}',
                                                'pattern': 'PDF Launch action'
                                            })
                            except Exception:
                                pass
                except Exception:
                    pass

            # Extract text and look for URLs
            try:
                text = page.extract_text() or ''
                found_urls = url_pattern.findall(text)
                for url in found_urls:
                    urls.append(url)
                    download = extract_download_info(url)
                    if download['is_download']:
                        download_urls.append(download)
            except Exception:
                pass

        # Check for embedded files
        if reader.trailer and '/Root' in reader.trailer:
            root = reader.trailer['/Root'].get_object()
            if '/Names' in root:
                names = root['/Names']
                names_obj = names.get_object() if hasattr(names, 'get_object') else names
                if '/EmbeddedFiles' in names_obj:
                    embedded_files.append('Embedded files detected')

        # Extract images and scan for QR codes
        images = extract_images_from_pdf(file_data)
        qr_codes = scan_for_qr_codes(images)

        # Generate page screenshots
        page_screenshots = generate_pdf_page_screenshots(file_data, max_pages=10)

        # Collect QR code URLs
        qr_urls = []
        qr_risk_indicators = []
        for qr in qr_codes:
            qr_urls.extend(qr.get('urls', []))
            qr_risk_indicators.extend(qr.get('risk_indicators', []))

        # Add QR URLs to main URL list
        urls.extend(qr_urls)

        # Deduplicate URLs and enrich
        urls = list(set(urls))[:50]
        enriched_urls = []
        for url in urls[:20]:
            enriched = enrich_url(url)
            enriched_urls.append(enriched)

        # Detect HTTP request patterns in metadata
        for key, value in metadata.items():
            if value and url_pattern.search(str(value)):
                http_requests.append({
                    'source': f'Metadata: {key}',
                    'url': url_pattern.search(str(value)).group()
                })

        # Calculate risk score (include QR codes)
        risk_score = calculate_pdf_risk_score(javascript_found, embedded_files, external_refs, forms, download_urls, process_triggers, qr_codes)

        # Automatic IOC investigation using threat intel APIs
        ioc_investigation = None
        suspicious_indicators = []
        if THREAT_INTEL_AVAILABLE:
            # Collect unique URLs for investigation
            investigation_urls = list(set(urls))[:10]

            if investigation_urls:
                ioc_investigation = investigate_iocs(
                    urls=investigation_urls,
                    max_per_type=5
                )
                # Update risk score based on IOC findings
                if ioc_investigation.get('summary', {}).get('maliciousIOCs', 0) > 0:
                    ioc_risk = ioc_investigation['summary'].get('overallRiskScore', 0)
                    risk_score = max(risk_score, ioc_risk)
                    suspicious_indicators.append({
                        'type': 'threat_intel',
                        'severity': 'high' if ioc_risk > 70 else 'medium',
                        'description': f"Threat intelligence: {ioc_investigation['summary']['maliciousIOCs']} malicious URLs detected"
                    })

        return {
            'success': True,
            'type': 'pdf',
            'metadata': metadata,
            'pageCount': page_count,
            'javascript': javascript_found,
            'hasJavaScript': len(javascript_found) > 0,
            'embeddedFiles': embedded_files,
            'hasEmbeddedFiles': len(embedded_files) > 0,
            'urls': urls,
            'enrichedUrls': enriched_urls,
            'urlCount': len(urls),
            'forms': forms,
            'hasForms': len(forms) > 0,
            'externalReferences': external_refs,
            'hasExternalRefs': len(external_refs) > 0,
            'httpRequests': http_requests,
            'downloadUrls': download_urls,
            'processTriggers': process_triggers,
            'qrCodes': qr_codes,
            'qrCodeCount': len(qr_codes),
            'pageScreenshots': page_screenshots,
            'riskScore': risk_score,
            'riskLevel': get_risk_level(risk_score),
            'suspiciousIndicators': suspicious_indicators,
            'iocInvestigation': ioc_investigation
        }
    except ImportError:
        return {'success': False, 'error': 'pypdf library not installed. Run: pip install pypdf'}
    except Exception as e:
        return {'success': False, 'error': f'Failed to parse PDF: {str(e)}'}


def calculate_pdf_risk_score(javascript, embedded_files, external_refs, forms, download_urls=None, process_triggers=None, qr_codes=None):
    """Calculate risk score for PDF (0-100)"""
    score = 0

    # JavaScript is high risk
    score += len(javascript) * 25

    # Embedded files are suspicious
    score += len(embedded_files) * 20

    # External references (launch actions)
    score += len(external_refs) * 30

    # Forms are low risk
    score += len(forms) * 5

    # Download URLs with high-risk extensions
    if download_urls:
        for dl in download_urls:
            if dl.get('is_high_risk'):
                score += 20
            else:
                score += 5

    # Process triggers
    if process_triggers:
        score += len(process_triggers) * 25

    # QR codes risk assessment
    if qr_codes:
        for qr in qr_codes:
            qr_risk = qr.get('risk_level', 'low')
            if qr_risk == 'critical':
                score += 30
            elif qr_risk == 'high':
                score += 20
            elif qr_risk == 'medium':
                score += 10
            else:
                score += 3

    return min(score, 100)


def analyze_office(file_data, filename):
    """Analyze an Office document for macros and suspicious content"""
    import zipfile
    import io
    import xml.etree.ElementTree as ET

    results = {
        'success': True,
        'type': 'office',
        'filename': filename,
        'documentType': None,
        'title': None,
        'author': None,
        'lastModifiedBy': None,
        'created': None,
        'modified': None,
        'macros': [],
        'hasMacros': False,
        'autoExecution': [],
        'suspiciousPatterns': [],
        'embeddedObjects': [],
        'externalReferences': [],
        'externalLinks': [],
        'urls': [],
        'enrichedUrls': [],
        'httpRequests': [],
        'downloadTargets': [],
        'processTriggers': [],
        'riskScore': 0,
        'riskLevel': 'Low'
    }

    # URL and dangerous patterns
    url_pattern = re.compile(r'https?://[^\s<>"\'}\]]+', re.IGNORECASE)
    http_patterns = [
        (r'WinHttp', 'WinHTTP request'),
        (r'XMLHTTP', 'XMLHTTP request'),
        (r'ServerXMLHTTP', 'ServerXMLHTTP request'),
        (r'URLDownloadToFile', 'URLDownloadToFile'),
        (r'Inet\.OpenURL', 'Internet Transfer Control'),
        (r'WebClient', 'WebClient request'),
    ]
    process_patterns = [
        (r'Shell\s*[\(\"]', 'Shell() execution'),
        (r'WScript\.Shell', 'WScript.Shell'),
        (r'CreateObject\s*\(\s*["\']?(WScript\.Shell|Shell)', 'Shell.Application'),
        (r'cmd\.exe', 'cmd.exe'),
        (r'powershell', 'PowerShell'),
        (r'cscript', 'cscript.exe'),
        (r'wscript', 'wscript.exe'),
        (r'mshta', 'mshta.exe'),
        (r'regsvr32', 'regsvr32.exe'),
        (r'rundll32', 'rundll32.exe'),
        (r'certutil', 'certutil.exe'),
        (r'bitsadmin', 'bitsadmin.exe'),
    ]
    download_patterns = [
        (r'SaveAs|SaveToFile|\.Write', 'File save operation'),
        (r'ADODB\.Stream', 'ADODB Stream'),
        (r'Scripting\.FileSystemObject', 'FileSystemObject'),
    ]
    auto_triggers = ['autoopen', 'autoclose', 'autonew', 'autoexec',
                    'document_open', 'document_close', 'workbook_open',
                    'workbook_close', 'auto_open', 'auto_close']

    # Determine document type from filename
    ext = filename.lower().split('.')[-1] if '.' in filename else ''
    if ext in ['docx', 'docm', 'dotx', 'dotm']:
        results['documentType'] = 'Word Document'
    elif ext in ['xlsx', 'xlsm', 'xltx', 'xltm', 'xlsb']:
        results['documentType'] = 'Excel Spreadsheet'
    elif ext in ['pptx', 'pptm', 'potx', 'potm']:
        results['documentType'] = 'PowerPoint Presentation'
    elif ext in ['doc', 'xls', 'ppt']:
        results['documentType'] = 'Legacy Office Document'

    # Check if it's a macro-enabled format
    is_macro_format = ext in ['docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm', 'xlsb']

    all_text_content = ""

    # Try to parse as OOXML (ZIP-based format)
    try:
        with zipfile.ZipFile(io.BytesIO(file_data), 'r') as zf:
            file_list = zf.namelist()

            # Check for vbaProject.bin (macros in OOXML)
            vba_files = [f for f in file_list if 'vbaproject.bin' in f.lower()]
            if vba_files:
                results['hasMacros'] = True
                results['suspiciousPatterns'].append({
                    'type': 'Macros',
                    'keyword': 'vbaProject.bin',
                    'description': 'Document contains VBA macro project'
                })

                # Try to extract and analyze the VBA content
                for vba_file in vba_files:
                    try:
                        vba_data = zf.read(vba_file)
                        # Scan binary for suspicious strings
                        vba_text = vba_data.decode('latin-1', errors='ignore')
                        all_text_content += vba_text

                        # Look for macro code indicators
                        if b'Attribute VB_Name' in vba_data or b'Sub ' in vba_data or b'Function ' in vba_data:
                            results['macros'].append({
                                'filename': vba_file,
                                'streamPath': vba_file,
                                'codePreview': 'VBA macro code detected in binary',
                                'codeLength': len(vba_data)
                            })
                    except Exception:
                        pass

            # Extract metadata from core.xml
            if 'docProps/core.xml' in file_list:
                try:
                    core_xml = zf.read('docProps/core.xml').decode('utf-8', errors='ignore')
                    # Parse XML
                    root = ET.fromstring(core_xml)
                    ns = {
                        'dc': 'http://purl.org/dc/elements/1.1/',
                        'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
                        'dcterms': 'http://purl.org/dc/terms/'
                    }
                    title_elem = root.find('.//dc:title', ns)
                    if title_elem is not None and title_elem.text:
                        results['title'] = title_elem.text
                    creator_elem = root.find('.//dc:creator', ns)
                    if creator_elem is not None and creator_elem.text:
                        results['author'] = creator_elem.text
                    modified_by = root.find('.//cp:lastModifiedBy', ns)
                    if modified_by is not None and modified_by.text:
                        results['lastModifiedBy'] = modified_by.text
                    created = root.find('.//dcterms:created', ns)
                    if created is not None and created.text:
                        results['created'] = created.text
                    modified = root.find('.//dcterms:modified', ns)
                    if modified is not None and modified.text:
                        results['modified'] = modified.text
                except Exception:
                    pass

            # Parse relationship files for external references
            rels_files = [f for f in file_list if f.endswith('.rels')]
            for rels_file in rels_files:
                try:
                    rels_xml = zf.read(rels_file).decode('utf-8', errors='ignore')
                    # Look for external targets
                    external_matches = re.findall(r'Target="([^"]+)"[^>]*TargetMode="External"', rels_xml, re.IGNORECASE)
                    for target in external_matches:
                        results['externalReferences'].append({
                            'type': 'External Reference',
                            'target': target,
                            'source': rels_file
                        })
                        if target.startswith('http'):
                            results['urls'].append(target)
                            results['externalLinks'].append(target)

                    # Look for oleObject relationships
                    if 'oleObject' in rels_xml.lower():
                        results['embeddedObjects'].append({
                            'type': 'OLE Object',
                            'description': f'OLE object reference in {rels_file}'
                        })

                    # Look for frame/attachedTemplate (can load remote content)
                    if 'attachedTemplate' in rels_xml.lower() or 'frame' in rels_xml.lower():
                        template_matches = re.findall(r'Target="([^"]+)"', rels_xml)
                        for tmpl in template_matches:
                            if tmpl.startswith('http'):
                                results['externalReferences'].append({
                                    'type': 'Remote Template',
                                    'target': tmpl,
                                    'source': rels_file
                                })
                                results['urls'].append(tmpl)
                except Exception:
                    pass

            # Extract text content from document.xml, sheet*.xml, slide*.xml
            content_files = [f for f in file_list if any(x in f.lower() for x in ['document.xml', 'sheet', 'slide', 'workbook'])]
            for content_file in content_files:
                if content_file.endswith('.xml'):
                    try:
                        content = zf.read(content_file).decode('utf-8', errors='ignore')
                        all_text_content += content

                        # Extract URLs from content
                        found_urls = url_pattern.findall(content)
                        results['urls'].extend(found_urls)

                        # Look for hyperlinks
                        hyperlinks = re.findall(r'<[^>]*hyperlink[^>]*r:id="([^"]+)"', content, re.IGNORECASE)
                        if hyperlinks:
                            results['suspiciousPatterns'].append({
                                'type': 'Hyperlinks',
                                'keyword': 'hyperlink',
                                'description': f'{len(hyperlinks)} hyperlink(s) found in document'
                            })
                    except Exception:
                        pass

            # Check for embedded files in the archive
            embedded_files = [f for f in file_list if any(x in f.lower() for x in ['embeddings/', 'activeX/', 'oleObject'])]
            for emb_file in embedded_files:
                results['embeddedObjects'].append({
                    'type': 'Embedded File',
                    'description': emb_file
                })

    except zipfile.BadZipFile:
        # Not a ZIP-based format, try OLE parsing
        pass
    except Exception as e:
        results['parseWarning'] = f'OOXML parsing: {str(e)}'

    # Try oletools VBA parsing
    try:
        from oletools.olevba import VBA_Parser

        vba_parser = VBA_Parser(filename, data=file_data)

        if vba_parser.detect_vba_macros():
            results['hasMacros'] = True

            # Extract macro information
            for (filename_vba, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                macro_info = {
                    'filename': vba_filename,
                    'streamPath': stream_path,
                    'codePreview': vba_code[:2000] if vba_code else '',
                    'codeLength': len(vba_code) if vba_code else 0
                }
                results['macros'].append(macro_info)

                if vba_code:
                    all_text_content += vba_code + "\n"
                    code_lower = vba_code.lower()

                    # Check for auto-execution triggers
                    for trigger in auto_triggers:
                        if trigger in code_lower:
                            results['autoExecution'].append({
                                'trigger': trigger,
                                'location': vba_filename
                            })

                    # Extract URLs
                    found_urls = url_pattern.findall(vba_code)
                    results['urls'].extend(found_urls)

                    # Detect HTTP requests
                    for pattern, desc in http_patterns:
                        if re.search(pattern, vba_code, re.IGNORECASE):
                            results['httpRequests'].append({
                                'pattern': desc,
                                'location': vba_filename
                            })

                    # Detect process execution
                    for pattern, desc in process_patterns:
                        matches = re.findall(pattern, vba_code, re.IGNORECASE)
                        for match in matches:
                            results['processTriggers'].append({
                                'type': desc,
                                'location': vba_filename,
                                'match': match[:50] if len(match) > 50 else match
                            })

                    # Detect download/save operations
                    for pattern, desc in download_patterns:
                        if re.search(pattern, vba_code, re.IGNORECASE):
                            results['downloadTargets'].append({
                                'pattern': desc,
                                'location': vba_filename
                            })

            # Analyze suspicious patterns with oletools
            analysis = vba_parser.analyze_macros()
            for kw_type, keyword, description in analysis:
                if kw_type in ('AutoExec', 'Suspicious', 'IOC', 'Hex Strings', 'Base64 Strings', 'Dridex Strings', 'VBA Stomping'):
                    results['suspiciousPatterns'].append({
                        'type': kw_type,
                        'keyword': keyword,
                        'description': description
                    })

        vba_parser.close()

    except ImportError:
        results['parseWarning'] = 'oletools not installed - VBA analysis limited'
    except Exception as e:
        if 'parseError' not in results:
            results['parseError'] = str(e)

    # Scan all collected text for suspicious patterns
    if all_text_content:
        content_lower = all_text_content.lower()

        # Check for auto-execution triggers in raw content
        for trigger in auto_triggers:
            if trigger in content_lower and not any(t['trigger'] == trigger for t in results['autoExecution']):
                results['autoExecution'].append({
                    'trigger': trigger,
                    'location': 'document content'
                })

        # Check for process execution patterns
        for pattern, desc in process_patterns:
            if re.search(pattern, all_text_content, re.IGNORECASE):
                if not any(t['type'] == desc for t in results['processTriggers']):
                    results['processTriggers'].append({
                        'type': desc,
                        'location': 'document content',
                        'match': ''
                    })

        # Check for HTTP patterns
        for pattern, desc in http_patterns:
            if re.search(pattern, all_text_content, re.IGNORECASE):
                if not any(r['pattern'] == desc for r in results['httpRequests']):
                    results['httpRequests'].append({
                        'pattern': desc,
                        'location': 'document content'
                    })

        # Extract any remaining URLs
        found_urls = url_pattern.findall(all_text_content)
        results['urls'].extend(found_urls)

    # Try OLE analysis for embedded objects
    try:
        from oletools import oleobj
        for ole in oleobj.find_ole(filename, file_data):
            if ole:
                results['embeddedObjects'].append({
                    'type': 'OLE Object',
                    'description': 'Embedded OLE object detected by oleobj'
                })
    except Exception:
        pass

    # Deduplicate URLs and external references
    results['urls'] = list(set(results['urls']))[:50]
    results['externalLinks'] = list(set(results['externalLinks']))[:20]

    # Deduplicate process triggers
    seen_triggers = set()
    unique_triggers = []
    for trigger in results['processTriggers']:
        key = (trigger['type'], trigger.get('location', ''))
        if key not in seen_triggers:
            seen_triggers.add(key)
            unique_triggers.append(trigger)
    results['processTriggers'] = unique_triggers

    # Deduplicate auto-execution
    seen_auto = set()
    unique_auto = []
    for auto in results['autoExecution']:
        key = auto['trigger']
        if key not in seen_auto:
            seen_auto.add(key)
            unique_auto.append(auto)
    results['autoExecution'] = unique_auto

    # Enrich URLs
    for url in results['urls'][:20]:
        enriched = enrich_url(url)
        download_info = extract_download_info(url)
        enriched['download'] = download_info
        results['enrichedUrls'].append(enriched)

    # Calculate risk score
    results['riskScore'] = calculate_office_risk_score(results)
    results['riskLevel'] = get_risk_level(results['riskScore'])

    # Automatic IOC investigation using threat intel APIs
    if THREAT_INTEL_AVAILABLE and results['urls']:
        investigation_urls = list(set(results['urls']))[:10]
        ioc_investigation = investigate_iocs(
            urls=investigation_urls,
            max_per_type=5
        )
        results['iocInvestigation'] = ioc_investigation

        # Update risk score based on IOC findings
        if ioc_investigation.get('summary', {}).get('maliciousIOCs', 0) > 0:
            ioc_risk = ioc_investigation['summary'].get('overallRiskScore', 0)
            results['riskScore'] = max(results['riskScore'], ioc_risk)
            results['riskLevel'] = get_risk_level(results['riskScore'])
            results['suspiciousPatterns'].append({
                'type': 'ThreatIntel',
                'keyword': 'malicious_url',
                'description': f"Threat intelligence: {ioc_investigation['summary']['maliciousIOCs']} malicious URLs detected"
            })

    # Generate document screenshots (convert to PDF first, then render pages)
    results['documentScreenshots'] = generate_office_screenshots(file_data, filename, max_pages=10)

    return results


def calculate_office_risk_score(results):
    """Calculate risk score for Office document (0-100)"""
    score = 0

    # Has macros is already suspicious
    if results.get('hasMacros'):
        score += 25

    # Auto-execution is high risk
    score += len(results.get('autoExecution', [])) * 20

    # Suspicious patterns
    for pattern in results.get('suspiciousPatterns', []):
        ptype = pattern.get('type', '')
        if ptype == 'AutoExec':
            score += 20
        elif ptype == 'Suspicious':
            score += 15
        elif ptype == 'IOC':
            score += 25
        elif ptype == 'Macros':
            score += 15
        elif ptype == 'ThreatIntel':
            score += 30
        else:
            score += 10

    # Embedded objects
    score += min(len(results.get('embeddedObjects', [])) * 10, 30)

    # External references (can load remote content)
    score += min(len(results.get('externalReferences', [])) * 15, 45)

    # External links
    score += min(len(results.get('externalLinks', [])) * 5, 20)

    # Process triggers (Shell, PowerShell, etc.)
    score += min(len(results.get('processTriggers', [])) * 15, 45)

    # HTTP requests in macros
    score += min(len(results.get('httpRequests', [])) * 10, 30)

    # Download targets
    score += min(len(results.get('downloadTargets', [])) * 10, 30)

    # URLs in document (especially if many)
    url_count = len(results.get('urls', []))
    if url_count > 5:
        score += 10
    elif url_count > 0:
        score += 5

    return min(score, 100)


def get_risk_level(score):
    """Convert numeric risk score to level string"""
    if score >= 75:
        return 'Critical'
    elif score >= 50:
        return 'High'
    elif score >= 25:
        return 'Medium'
    else:
        return 'Low'


def analyze_qrcode(file_data):
    """Analyze image file for QR codes"""
    result = {
        'success': True,
        'file_type': 'qrcode',
        'qr_codes': [],
        'total_codes': 0,
        'image_info': {}
    }

    try:
        from PIL import Image

        # Get image info
        img = Image.open(io.BytesIO(file_data))
        result['image_info'] = {
            'format': img.format,
            'mode': img.mode,
            'width': img.width,
            'height': img.height
        }

        # Decode QR codes
        qr_codes = decode_qr_codes(file_data)
        result['qr_codes'] = qr_codes
        result['total_codes'] = len(qr_codes)

        # Calculate overall risk score
        max_risk = 0
        for qr in qr_codes:
            for indicator in qr.get('risk_indicators', []):
                severity = indicator.get('severity', 'low')
                if severity == 'high':
                    max_risk = max(max_risk, 75)
                elif severity == 'medium':
                    max_risk = max(max_risk, 50)
                else:
                    max_risk = max(max_risk, 25)

        result['risk_score'] = max_risk
        result['risk_level'] = get_risk_level(max_risk)

        if not qr_codes:
            result['message'] = 'No QR codes detected in the image'

    except ImportError as e:
        result['success'] = False
        result['error'] = 'Required libraries not installed (PIL, pyzbar)'
    except Exception as e:
        result['success'] = False
        result['error'] = f'Failed to analyze image: {str(e)}'

    return result


# ============================================================================
# HTTP Handler
# ============================================================================

class IPLookupHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Prefer React build if available, fallback to public directory
        react_dist = os.path.join(os.path.dirname(__file__), 'frontend', 'dist')
        public_dir = os.path.join(os.path.dirname(__file__), 'public')
        static_dir = react_dist if os.path.isdir(react_dist) else public_dir
        super().__init__(*args, directory=static_dir, **kwargs)

    def do_GET(self):
        if self.path == '/api/my-ip':
            self.handle_my_ip()
        elif self.path.startswith('/api/lookup'):
            self.handle_lookup()
        elif self.path == '/api/status':
            self.handle_status()
        elif self.path == '/api/threat-intel/status':
            self.handle_threat_intel_status()
        elif self.path == '/api/threat-intel/cache/stats':
            self.handle_cache_stats()
        elif self.path.startswith('/api/threat-intel/cache/search'):
            self.handle_cache_search()
        elif self.path.startswith('/api/ioc/export/ips'):
            self.handle_ioc_export_ips()
        elif self.path.startswith('/api/ioc/export/urls'):
            self.handle_ioc_export_urls()
        elif self.path.startswith('/api/ioc/export/hashes'):
            self.handle_ioc_export_hashes()
        elif self.path.startswith('/api/ioc/export'):
            self.handle_ioc_export()
        elif self.path == '/api/ioc/stats':
            self.handle_ioc_stats()
        elif self.path == '/api/screenshot/status':
            self.handle_screenshot_status()
        elif self.path == '/api/export/pdf/status':
            self.handle_pdf_export_status()
        elif self.path == '/api/sandbox/status':
            self.handle_sandbox_status()
        else:
            # For SPA routing: serve index.html for non-file paths
            if not self.path.startswith('/api') and '.' not in self.path.split('/')[-1]:
                self.path = '/index.html'
            super().do_GET()

    def do_POST(self):
        """Handle POST requests for file analysis and result retrieval"""
        if self.path == '/api/analyze/email':
            self.handle_file_analysis('email')
        elif self.path == '/api/analyze/pdf':
            self.handle_file_analysis('pdf')
        elif self.path == '/api/analyze/office':
            self.handle_file_analysis('office')
        elif self.path == '/api/analyze/qrcode':
            self.handle_file_analysis('qrcode')
        elif self.path.startswith('/api/results/'):
            self.handle_results_get()
        elif self.path == '/api/threat-intel/investigate':
            self.handle_ioc_investigation()
        elif self.path == '/api/threat-intel/investigate/ip':
            self.handle_ip_investigation()
        elif self.path == '/api/threat-intel/investigate/url':
            self.handle_url_investigation()
        elif self.path == '/api/threat-intel/investigate/hash':
            self.handle_hash_investigation()
        elif self.path == '/api/threat-intel/cache/clear':
            self.handle_cache_clear()
        elif self.path == '/api/threat-intel/cache/cleanup':
            self.handle_cache_cleanup()
        elif self.path == '/api/screenshot/url':
            self.handle_screenshot_capture()
        elif self.path == '/api/export/pdf':
            self.handle_pdf_export()
        elif self.path.startswith('/api/retrieve/'):
            self.handle_retrieve()
        elif self.path == '/api/sandbox/analyze':
            self.handle_sandbox_analyze()
        elif self.path == '/api/sandbox/url':
            self.handle_sandbox_url()
        else:
            self.send_json({'error': 'Not found'}, 404)

    def do_DELETE(self):
        """Handle DELETE requests for result deletion"""
        if self.path.startswith('/api/results/'):
            self.handle_results_delete()
        else:
            self.send_json({'error': 'Not found'}, 404)

    def handle_status(self):
        """Return service health and storage stats"""
        storage = get_storage()
        stats = storage.get_stats()

        # Cleanup expired entries
        cleaned = storage.cleanup_expired(self.get_client_ip())

        # Check QR code detection availability
        qr_available = False
        try:
            from pyzbar import pyzbar
            qr_available = True
        except (ImportError, Exception):
            qr_available = False

        # Check screenshot service availability
        screenshot_available = SCREENSHOT_AVAILABLE
        if screenshot_available:
            try:
                ss_status = screenshot_service.check_browser_available()
                screenshot_available = any(ss_status.values())
            except:
                screenshot_available = False

        # Check PDF export availability
        pdf_available = PDF_EXPORT_AVAILABLE
        if pdf_available:
            try:
                pdf_caps = pdf_export.check_pdf_available()
                pdf_available = pdf_caps.get('pdf_generation', False)
            except:
                pdf_available = False

        # Check sandbox service availability
        sandbox_available = SANDBOX_AVAILABLE
        if sandbox_available:
            try:
                sb_service = sandbox_service.get_service()
                sb_status = sb_service.get_status()
                sandbox_available = sb_status.get('status') in ('available', 'limited')
            except:
                sandbox_available = False

        self.send_json({
            'status': 'healthy',
            'storage': stats,
            'cleanedExpired': cleaned,
            'expirationDays': EXPIRATION_DAYS,
            'features': {
                'qrCodeDetection': qr_available,
                'threatIntel': THREAT_INTEL_AVAILABLE,
                'screenshot': screenshot_available,
                'pdfExport': pdf_available,
                'sandbox': sandbox_available
            }
        })

    def handle_threat_intel_status(self):
        """Return threat intelligence service status"""
        status = get_threat_intel_status()
        self.send_json(status)

    def handle_ioc_investigation(self):
        """Handle POST /api/threat-intel/investigate - investigate multiple IOCs"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(body) if body else {}

            ips = data.get('ips', [])
            urls = data.get('urls', [])
            hashes = data.get('hashes', [])
            max_per_type = data.get('maxPerType', 5)

            if not ips and not urls and not hashes:
                self.send_json({'error': 'No IOCs provided. Include ips, urls, or hashes array.'}, 400)
                return

            result = investigate_iocs(ips=ips, urls=urls, hashes=hashes, max_per_type=max_per_type)
            self.send_json(result)

        except json.JSONDecodeError:
            self.send_json({'error': 'Invalid JSON'}, 400)
        except Exception as e:
            self.send_json({'error': str(e)}, 500)

    def handle_ip_investigation(self):
        """Handle POST /api/threat-intel/investigate/ip - investigate single IP"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(body) if body else {}

            ip = data.get('ip')
            if not ip:
                self.send_json({'error': 'IP address required'}, 400)
                return

            if THREAT_INTEL_AVAILABLE:
                result = threat_intel.investigate_ip(ip)

                # Apply AI validation to adjust risk score
                if AI_VALIDATOR_AVAILABLE:
                    ai_analysis = ai_validator.validate_ip(result)
                    result['aiValidation'] = ai_analysis
                    # Update summary with AI-validated score
                    if 'summary' in result:
                        result['summary']['aiValidatedScore'] = ai_analysis.get('validatedScore', result['summary'].get('riskScore', 0))
                        result['summary']['aiConfidence'] = ai_analysis.get('confidence', 0)
                        result['summary']['aiRecommendation'] = ai_analysis.get('recommendation', '')

                self.send_json(result)
            else:
                self.send_json({'error': 'Threat intelligence module not available'}, 503)

        except json.JSONDecodeError:
            self.send_json({'error': 'Invalid JSON'}, 400)
        except Exception as e:
            self.send_json({'error': str(e)}, 500)

    def handle_url_investigation(self):
        """Handle POST /api/threat-intel/investigate/url - investigate single URL"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(body) if body else {}

            url = data.get('url')
            if not url:
                self.send_json({'error': 'URL required'}, 400)
                return

            # Normalize URL to handle encoding issues
            normalized_url = normalize_url_for_api(url)

            if THREAT_INTEL_AVAILABLE:
                result = threat_intel.investigate_url(normalized_url)
                # Include original URL if different from normalized
                if normalized_url != url:
                    result['originalUrl'] = url
                    result['normalizedUrl'] = normalized_url

                # Apply AI validation to adjust risk score
                if AI_VALIDATOR_AVAILABLE:
                    ai_analysis = ai_validator.validate_url(result)
                    result['aiValidation'] = ai_analysis
                    # Update summary with AI-validated score
                    if 'summary' in result:
                        result['summary']['aiValidatedScore'] = ai_analysis.get('validatedScore', result['summary'].get('riskScore', 0))
                        result['summary']['aiConfidence'] = ai_analysis.get('confidence', 0)
                        result['summary']['aiRecommendation'] = ai_analysis.get('recommendation', '')

                # Generate AI attack flow diagram
                if AI_FLOW_AVAILABLE:
                    try:
                        flow_analysis = ai_flow_analyzer.analyze_url_flow(result)
                        result['attackFlow'] = flow_analysis
                    except Exception as e:
                        print(f"[Warning] URL flow analysis failed: {e}")

                self.send_json(result)
            else:
                self.send_json({'error': 'Threat intelligence module not available'}, 503)

        except json.JSONDecodeError:
            self.send_json({'error': 'Invalid JSON'}, 400)
        except Exception as e:
            self.send_json({'error': str(e)}, 500)

    def handle_hash_investigation(self):
        """Handle POST /api/threat-intel/investigate/hash - investigate file hash"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(body) if body else {}

            file_hash = data.get('hash')
            if not file_hash:
                self.send_json({'error': 'File hash required'}, 400)
                return

            if THREAT_INTEL_AVAILABLE:
                result = threat_intel.investigate_hash(file_hash)

                # Apply AI validation to adjust risk score
                if AI_VALIDATOR_AVAILABLE:
                    ai_analysis = ai_validator.validate_hash(result)
                    result['aiValidation'] = ai_analysis
                    # Update summary with AI-validated score
                    if 'summary' in result:
                        result['summary']['aiValidatedScore'] = ai_analysis.get('validatedScore', result['summary'].get('riskScore', 0))
                        result['summary']['aiConfidence'] = ai_analysis.get('confidence', 0)
                        result['summary']['aiRecommendation'] = ai_analysis.get('recommendation', '')

                self.send_json(result)
            else:
                self.send_json({'error': 'Threat intelligence module not available'}, 503)

        except json.JSONDecodeError:
            self.send_json({'error': 'Invalid JSON'}, 400)
        except Exception as e:
            self.send_json({'error': str(e)}, 500)

    def handle_cache_stats(self):
        """Handle GET /api/threat-intel/cache/stats - get cache statistics"""
        if THREAT_INTEL_AVAILABLE:
            stats = threat_intel.get_cache_stats()
            self.send_json(stats)
        else:
            self.send_json({'error': 'Threat intelligence module not available'}, 503)

    def handle_cache_search(self):
        """Handle GET /api/threat-intel/cache/search?q=query - search cache"""
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            query = params.get('q', [''])[0]
            limit = int(params.get('limit', [50])[0])

            if not query:
                self.send_json({'error': 'Query parameter "q" required'}, 400)
                return

            if THREAT_INTEL_AVAILABLE:
                results = threat_intel.search_cache(query, limit)
                self.send_json({
                    'query': query,
                    'count': len(results),
                    'results': results
                })
            else:
                self.send_json({'error': 'Threat intelligence module not available'}, 503)

        except Exception as e:
            self.send_json({'error': str(e)}, 500)

    def handle_cache_clear(self):
        """Handle POST /api/threat-intel/cache/clear - clear cache entries"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
            data = json.loads(body) if body else {}

            ioc_type = data.get('type')  # Optional: ip, url, hash
            source = data.get('source')  # Optional: virustotal, abuseipdb, etc.

            if THREAT_INTEL_AVAILABLE:
                deleted = threat_intel.clear_cache(ioc_type=ioc_type, source=source)
                self.send_json({
                    'success': True,
                    'deleted': deleted,
                    'filter': {
                        'type': ioc_type,
                        'source': source
                    }
                })
            else:
                self.send_json({'error': 'Threat intelligence module not available'}, 503)

        except json.JSONDecodeError:
            self.send_json({'error': 'Invalid JSON'}, 400)
        except Exception as e:
            self.send_json({'error': str(e)}, 500)

    def handle_cache_cleanup(self):
        """Handle POST /api/threat-intel/cache/cleanup - remove expired entries"""
        if THREAT_INTEL_AVAILABLE:
            cleaned = threat_intel.cleanup_expired_cache()
            self.send_json({
                'success': True,
                'expiredRemoved': cleaned
            })
        else:
            self.send_json({'error': 'Threat intelligence module not available'}, 503)

    def handle_ioc_export(self):
        """Handle GET /api/ioc/export - export IOCs for SIEM/Sentinel"""
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)

            ioc_type = params.get('type', [None])[0]  # ip, url, hash, or None for all
            malicious_only = params.get('malicious', ['false'])[0].lower() == 'true'
            min_risk = int(params.get('min_risk', [0])[0])
            format_type = params.get('format', ['json'])[0]  # json, csv, sentinel
            limit = int(params.get('limit', [1000])[0])

            if THREAT_INTEL_AVAILABLE:
                result = threat_intel.export_iocs(
                    ioc_type=ioc_type,
                    malicious_only=malicious_only,
                    min_risk_score=min_risk,
                    format=format_type,
                    limit=limit
                )
                self.send_json(result)
            else:
                self.send_json({'error': 'Threat intelligence module not available'}, 503)

        except Exception as e:
            self.send_json({'error': str(e)}, 500)

    def handle_ioc_stats(self):
        """Handle GET /api/ioc/stats - get IOC statistics"""
        if THREAT_INTEL_AVAILABLE:
            stats = threat_intel.get_ioc_stats()
            self.send_json(stats)
        else:
            self.send_json({'error': 'Threat intelligence module not available'}, 503)

    def handle_ioc_export_ips(self):
        """Handle GET /api/ioc/export/ips - export only IP IOCs"""
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)

            malicious_only = params.get('malicious', ['false'])[0].lower() == 'true'
            min_risk = int(params.get('min_risk', [0])[0])
            format_type = params.get('format', ['json'])[0]
            limit = int(params.get('limit', [1000])[0])

            if THREAT_INTEL_AVAILABLE:
                result = threat_intel.export_iocs(
                    ioc_type='ip',
                    malicious_only=malicious_only,
                    min_risk_score=min_risk,
                    format=format_type,
                    limit=limit
                )
                self.send_json(result)
            else:
                self.send_json({'error': 'Threat intelligence module not available'}, 503)

        except Exception as e:
            self.send_json({'error': str(e)}, 500)

    def handle_ioc_export_urls(self):
        """Handle GET /api/ioc/export/urls - export only URL IOCs"""
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)

            malicious_only = params.get('malicious', ['false'])[0].lower() == 'true'
            min_risk = int(params.get('min_risk', [0])[0])
            format_type = params.get('format', ['json'])[0]
            limit = int(params.get('limit', [1000])[0])

            if THREAT_INTEL_AVAILABLE:
                result = threat_intel.export_iocs(
                    ioc_type='url',
                    malicious_only=malicious_only,
                    min_risk_score=min_risk,
                    format=format_type,
                    limit=limit
                )
                self.send_json(result)
            else:
                self.send_json({'error': 'Threat intelligence module not available'}, 503)

        except Exception as e:
            self.send_json({'error': str(e)}, 500)

    def handle_ioc_export_hashes(self):
        """Handle GET /api/ioc/export/hashes - export only Hash IOCs"""
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)

            malicious_only = params.get('malicious', ['false'])[0].lower() == 'true'
            min_risk = int(params.get('min_risk', [0])[0])
            format_type = params.get('format', ['json'])[0]
            limit = int(params.get('limit', [1000])[0])

            if THREAT_INTEL_AVAILABLE:
                result = threat_intel.export_iocs(
                    ioc_type='hash',
                    malicious_only=malicious_only,
                    min_risk_score=min_risk,
                    format=format_type,
                    limit=limit
                )
                self.send_json(result)
            else:
                self.send_json({'error': 'Threat intelligence module not available'}, 503)

        except Exception as e:
            self.send_json({'error': str(e)}, 500)

    def handle_screenshot_status(self):
        """Handle GET /api/screenshot/status - get screenshot service status"""
        if SCREENSHOT_AVAILABLE:
            status = screenshot_service.get_service_status()
            self.send_json(status)
        else:
            self.send_json({
                'service': 'screenshot',
                'status': 'unavailable',
                'error': 'Screenshot module not loaded'
            })

    def handle_pdf_export_status(self):
        """Handle GET /api/export/pdf/status - get PDF export service status"""
        if PDF_EXPORT_AVAILABLE:
            status = pdf_export.get_export_status()
            self.send_json(status)
        else:
            self.send_json({
                'service': 'pdf_export',
                'status': 'unavailable',
                'error': 'PDF export module not loaded'
            })

    def handle_screenshot_capture(self):
        """Handle POST /api/screenshot/url - capture URL screenshot"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(body) if body else {}

            url = data.get('url')
            if not url:
                self.send_json({'error': 'URL is required'}, 400)
                return

            if not SCREENSHOT_AVAILABLE:
                self.send_json({'error': 'Screenshot service not available'}, 503)
                return

            # Optional parameters
            user_agent = data.get('userAgent')
            browser = data.get('browser', 'auto')
            width = data.get('width', 1920)
            height = data.get('height', 1080)
            timeout = min(data.get('timeout', 30), 60)  # Max 60 seconds

            result = screenshot_service.capture_url_screenshot(
                url=url,
                user_agent=user_agent,
                browser=browser,
                width=width,
                height=height,
                timeout=timeout
            )

            self.send_json(result)

        except json.JSONDecodeError:
            self.send_json({'error': 'Invalid JSON'}, 400)
        except Exception as e:
            self.send_json({'error': str(e)}, 500)

    def handle_pdf_export(self):
        """Handle POST /api/export/pdf - export analysis to encrypted PDF"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(body) if body else {}

            # Get required parameters
            entry_ref = data.get('entryRef')
            secret_key = data.get('secretKey')

            if not entry_ref:
                self.send_json({'error': 'entryRef is required'}, 400)
                return

            if not secret_key:
                self.send_json({'error': 'secretKey is required'}, 400)
                return

            if len(secret_key) < MIN_SECRET_KEY_LENGTH:
                self.send_json({'error': f'Secret key must be at least {MIN_SECRET_KEY_LENGTH} characters'}, 400)
                return

            if not PDF_EXPORT_AVAILABLE:
                self.send_json({'error': 'PDF export service not available'}, 503)
                return

            # First retrieve the analysis result
            storage = get_storage()
            raw_result, error = storage.retrieve(entry_ref.upper(), secret_key, self.get_client_ip())

            if error:
                status = 404 if 'not found' in error.lower() else 401
                self.send_json({'error': error}, status)
                return

            # Flatten the result - merge metadata and actual analysis results
            analysis_result = {
                'entryRef': raw_result.get('entryRef'),
                'filename': raw_result.get('originalFilename'),
                'riskScore': raw_result.get('riskScore'),
                'riskLevel': raw_result.get('riskLevel'),
                'type': raw_result.get('fileType', raw_result.get('type', 'unknown')),
                'storedAt': raw_result.get('storedAt'),
                'expiresAt': raw_result.get('expiresAt'),
            }
            # Merge in the nested results while preserving top-level keys
            if raw_result.get('results'):
                results_data = raw_result['results']
                # Don't overwrite type if already set from fileType
                if 'type' in results_data and not analysis_result.get('type'):
                    analysis_result['type'] = results_data['type']
                for key, value in results_data.items():
                    if key not in analysis_result or not analysis_result[key]:
                        analysis_result[key] = value

            # Optional: capture screenshots for URLs in the result
            include_screenshots = data.get('includeScreenshots', False)
            if include_screenshots and SCREENSHOT_AVAILABLE:
                urls = analysis_result.get('urls', [])[:5]  # Limit to 5 URLs
                screenshots = []
                for url in urls:
                    try:
                        screenshot_result = screenshot_service.capture_url_screenshot(
                            url=url,
                            width=1280,
                            height=720,
                            timeout=20
                        )
                        if screenshot_result.get('success'):
                            screenshots.append(screenshot_result)
                    except:
                        pass
                analysis_result['screenshots'] = screenshots

            # Export to PDF
            result = pdf_export.export_analysis_to_pdf(
                analysis_result=analysis_result,
                secret_key=secret_key,
                include_screenshot=include_screenshots
            )

            self.send_json(result)

        except json.JSONDecodeError:
            self.send_json({'error': 'Invalid JSON'}, 400)
        except Exception as e:
            self.send_json({'error': str(e)}, 500)

    def handle_retrieve(self):
        """Handle POST /api/retrieve/{entryRef} - retrieve analysis results"""
        try:
            # Extract entry_ref from path
            entry_ref = self.path.split('/api/retrieve/')[-1]
            if not entry_ref:
                self.send_json({'error': 'Entry reference is required'}, 400)
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(body) if body else {}

            secret_key = data.get('secretKey')
            if not secret_key:
                self.send_json({'error': 'secretKey is required'}, 400)
                return

            if len(secret_key) < MIN_SECRET_KEY_LENGTH:
                self.send_json({'error': f'Secret key must be at least {MIN_SECRET_KEY_LENGTH} characters'}, 400)
                return

            # Retrieve the analysis result
            storage = get_storage()
            result, error = storage.retrieve(entry_ref.upper(), secret_key, self.get_client_ip())

            if error:
                status = 404 if 'not found' in error.lower() else 401
                self.send_json({'success': False, 'error': error}, status)
                return

            # Flatten the results into the top-level object for easier frontend consumption
            # The storage returns: {entryRef, originalFilename, fileType, ..., results: {actual analysis data}}
            # We want to merge results into the top level
            flattened = {
                'success': True,
                'entryRef': result.get('entryRef'),
                'originalFilename': result.get('originalFilename'),
                'fileType': result.get('fileType'),
                'fileHash': result.get('fileHash'),
                'fileSize': result.get('fileSize'),
                'riskScore': result.get('riskScore'),
                'riskLevel': result.get('riskLevel'),
                'createdAt': result.get('createdAt'),
                'expiresAt': result.get('expiresAt'),
                'storedAt': result.get('createdAt'),  # Alias for frontend
                'accessCount': result.get('accessCount'),
            }

            # Merge the actual analysis results
            if result.get('results'):
                flattened.update(result['results'])

            self.send_json(flattened)

        except json.JSONDecodeError:
            self.send_json({'error': 'Invalid JSON'}, 400)
        except Exception as e:
            self.send_json({'error': str(e)}, 500)

    def handle_sandbox_status(self):
        """Handle GET /api/sandbox/status - get sandbox service status"""
        if SANDBOX_AVAILABLE:
            service = sandbox_service.get_service()
            status = service.get_status()
            self.send_json(status)
        else:
            self.send_json({
                'service': 'sandbox',
                'status': 'unavailable',
                'error': 'Sandbox module not loaded',
                'backends': {'docker': False, 'bubblewrap': False},
                'capabilities': {'scripts': False, 'executables': False, 'documents': False}
            })

    def handle_sandbox_analyze(self):
        """Handle POST /api/sandbox/analyze - analyze file in sandbox"""
        try:
            if not SANDBOX_AVAILABLE:
                self.send_json({'error': 'Sandbox service not available'}, 503)
                return

            # Parse multipart form data
            content_type = self.headers.get('Content-Type', '')
            if 'multipart/form-data' not in content_type:
                self.send_json({'error': 'Content-Type must be multipart/form-data'}, 400)
                return

            # Parse boundary
            boundary = None
            for part in content_type.split(';'):
                part = part.strip()
                if part.startswith('boundary='):
                    boundary = part[9:].strip('"')
                    break

            if not boundary:
                self.send_json({'error': 'Multipart boundary not found'}, 400)
                return

            # Read content
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 50 * 1024 * 1024:  # 50MB limit for sandbox
                self.send_json({'error': 'File too large. Maximum size is 50MB'}, 400)
                return

            body = self.rfile.read(content_length)

            # Parse multipart data
            file_data = None
            filename = None
            secret_key = None
            timeout = 30

            boundary_bytes = boundary.encode()
            parts = body.split(b'--' + boundary_bytes)

            for part in parts:
                if b'Content-Disposition' not in part:
                    continue

                # Extract headers and content
                header_end = part.find(b'\r\n\r\n')
                if header_end == -1:
                    continue

                headers = part[:header_end].decode('utf-8', errors='replace')
                content = part[header_end + 4:]

                # Remove trailing boundary markers
                if content.endswith(b'\r\n'):
                    content = content[:-2]
                if content.endswith(b'--'):
                    content = content[:-2]
                if content.endswith(b'\r\n'):
                    content = content[:-2]

                # Check field name
                if 'name="file"' in headers:
                    file_data = content
                    # Extract filename
                    for header_part in headers.split('\r\n'):
                        if 'filename="' in header_part:
                            start = header_part.find('filename="') + 10
                            end = header_part.find('"', start)
                            if end > start:
                                filename = header_part[start:end]

                elif 'name="secretKey"' in headers:
                    secret_key = content.decode('utf-8').strip()

                elif 'name="timeout"' in headers:
                    try:
                        timeout = min(int(content.decode('utf-8').strip()), 300)
                    except ValueError:
                        pass

            if not file_data:
                self.send_json({'error': 'No file provided'}, 400)
                return

            if not filename:
                filename = 'unknown_sample'

            if not secret_key:
                self.send_json({'error': 'secretKey is required'}, 400)
                return

            if len(secret_key) < MIN_SECRET_KEY_LENGTH:
                self.send_json({'error': f'Secret key must be at least {MIN_SECRET_KEY_LENGTH} characters'}, 400)
                return

            # Analyze file in sandbox
            service = sandbox_service.get_service()
            result = service.analyze_file(
                file_data=file_data,
                filename=filename,
                secret_key=secret_key,
                timeout=timeout
            )
            result['type'] = 'sandbox'

            # Automatic threat intel lookup for file hash
            if result.get('success') and THREAT_INTEL_AVAILABLE:
                file_hashes = result.get('fileAnalysis', {}).get('hashes', {})
                sha256 = file_hashes.get('sha256')
                if sha256:
                    ioc_investigation = investigate_iocs(hashes=[sha256], max_per_type=1)
                    result['iocInvestigation'] = ioc_investigation

                    # Update risk based on threat intel findings
                    if ioc_investigation.get('summary', {}).get('maliciousIOCs', 0) > 0:
                        # File is known malware - significantly increase risk
                        current_risk = result.get('riskScore', 0)
                        threat_risk = ioc_investigation['summary'].get('overallRiskScore', 0)
                        result['riskScore'] = max(current_risk, threat_risk, 80)
                        result['riskLevel'] = 'Critical' if result['riskScore'] >= 80 else 'High'

                        # Add to summary findings
                        if result.get('summary'):
                            findings = ioc_investigation.get('summary', {}).get('findings', [])
                            result['summary']['findings'].extend(findings)
                            result['summary']['verdict'] = 'MALICIOUS - Known malware'
                            result['summary']['riskAssessment'] = 'This file is identified as KNOWN MALWARE in threat intelligence databases. Do NOT execute under any circumstances.'

            # Apply AI validation to sandbox results
            if AI_VALIDATOR_AVAILABLE and result.get('success'):
                ai_analysis = ai_validator.validate_sandbox(result)
                result['aiValidation'] = ai_analysis
                # Update summary with AI-validated score
                result['aiValidatedScore'] = ai_analysis.get('validatedScore', result.get('riskScore', 0))
                result['aiValidatedRiskLevel'] = ai_analysis.get('validatedRiskLevel', result.get('riskLevel', 'Unknown'))
                result['aiConfidence'] = ai_analysis.get('confidence', 0)
                result['aiRecommendation'] = ai_analysis.get('recommendation', '')

            # Generate AI attack flow diagram for sandbox
            if AI_FLOW_AVAILABLE and result.get('success'):
                try:
                    flow_analysis = ai_flow_analyzer.analyze_sandbox_flow(result)
                    result['attackFlow'] = flow_analysis
                except Exception as e:
                    print(f"[Warning] Sandbox flow analysis failed: {e}")

            # Store result if analysis was successful
            if result.get('success'):
                storage = get_storage()
                entry_ref, expires_at = storage.store(
                    filename=filename,
                    file_type='sandbox',
                    file_data=file_data,
                    results={
                        'type': 'sandbox',
                        'filename': filename,
                        **result
                    },
                    secret_key=secret_key,
                    client_ip=self.get_client_ip()
                )
                result['entryRef'] = entry_ref
                result['expiresAt'] = expires_at

            self.send_json(result)

        except Exception as e:
            import traceback
            traceback.print_exc()
            self.send_json({'error': str(e)}, 500)

    def handle_sandbox_url(self):
        """Handle POST /api/sandbox/url - analyze URL in sandbox"""
        try:
            if not SANDBOX_AVAILABLE:
                self.send_json({'error': 'Sandbox service not available'}, 503)
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(body) if body else {}

            url = data.get('url')
            if not url:
                self.send_json({'error': 'URL is required'}, 400)
                return

            # Normalize URL to handle encoding issues
            normalized_url = normalize_url_for_api(url)

            secret_key = data.get('secretKey')
            if not secret_key:
                self.send_json({'error': 'secretKey is required'}, 400)
                return

            if len(secret_key) < MIN_SECRET_KEY_LENGTH:
                self.send_json({'error': f'Secret key must be at least {MIN_SECRET_KEY_LENGTH} characters'}, 400)
                return

            mode = data.get('mode', 'http')
            if mode not in ('http', 'browser'):
                self.send_json({'error': 'mode must be "http" or "browser"'}, 400)
                return

            timeout = min(data.get('timeout', 30), 300)

            # Analyze URL in sandbox
            service = sandbox_service.get_service()
            result = service.analyze_url(
                url=normalized_url,
                mode=mode,
                secret_key=secret_key,
                timeout=timeout
            )

            # Include original URL if different from normalized
            if normalized_url != url:
                result['originalUrl'] = url
                result['normalizedUrl'] = normalized_url

            # Generate AI attack flow diagram
            if AI_FLOW_AVAILABLE and result.get('success'):
                try:
                    flow_analysis = ai_flow_analyzer.analyze_url_flow(result.get('analysis', result))
                    result['attackFlow'] = flow_analysis
                except Exception as e:
                    print(f"[Warning] Flow analysis failed: {e}")

            # Store result if analysis was successful
            if result.get('success'):
                storage = get_storage()
                # Use URL as "file data" for hashing
                url_bytes = url.encode('utf-8')
                entry_ref, expires_at = storage.store(
                    filename=url,
                    file_type='sandbox_url',
                    file_data=url_bytes,
                    results={
                        'type': 'sandbox_url',
                        'url': url,
                        **result
                    },
                    secret_key=secret_key,
                    client_ip=self.get_client_ip()
                )
                result['entryRef'] = entry_ref
                result['expiresAt'] = expires_at

            self.send_json(result)

        except json.JSONDecodeError:
            self.send_json({'error': 'Invalid JSON'}, 400)
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.send_json({'error': str(e)}, 500)

    def handle_results_get(self):
        """Handle POST /api/results/{entry_ref} for result retrieval"""
        try:
            # Extract entry ref from path
            entry_ref = self.path.split('/')[-1].upper()

            # Parse request body for secret key
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_json({'error': 'Request body required with secretKey'}, 400)
                return

            body = self.rfile.read(content_length)
            try:
                data = json.loads(body.decode('utf-8'))
            except json.JSONDecodeError:
                self.send_json({'error': 'Invalid JSON'}, 400)
                return

            secret_key = data.get('secretKey')
            if not secret_key:
                self.send_json({'error': 'secretKey is required'}, 400)
                return

            # Retrieve results
            storage = get_storage()
            result, error = storage.retrieve(entry_ref, secret_key, self.get_client_ip())

            if error:
                status = 404 if 'not found' in error.lower() else 401
                self.send_json({'error': error}, status)
                return

            self.send_json({
                'success': True,
                **result
            })

        except Exception as e:
            self.send_json({'error': f'Retrieval failed: {str(e)}'}, 500)

    def handle_results_delete(self):
        """Handle DELETE /api/results/{entry_ref} for result deletion"""
        try:
            # Extract entry ref from path
            entry_ref = self.path.split('/')[-1].upper()

            # Parse request body for secret key
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_json({'error': 'Request body required with secretKey'}, 400)
                return

            body = self.rfile.read(content_length)
            try:
                data = json.loads(body.decode('utf-8'))
            except json.JSONDecodeError:
                self.send_json({'error': 'Invalid JSON'}, 400)
                return

            secret_key = data.get('secretKey')
            if not secret_key:
                self.send_json({'error': 'secretKey is required'}, 400)
                return

            # Delete result
            storage = get_storage()
            success, error = storage.delete(entry_ref, secret_key, self.get_client_ip())

            if error:
                status = 404 if 'not found' in error.lower() else 401
                self.send_json({'error': error}, status)
                return

            self.send_json({
                'success': True,
                'message': f'Entry {entry_ref} deleted successfully'
            })

        except Exception as e:
            self.send_json({'error': f'Deletion failed: {str(e)}'}, 500)

    def handle_file_analysis(self, analysis_type):
        """Handle file upload and analysis"""
        try:
            # Check content length
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > MAX_FILE_SIZE:
                self.send_json({'error': 'File too large. Maximum size is 15MB.'}, 413)
                return

            if content_length == 0:
                self.send_json({'error': 'No file uploaded'}, 400)
                return

            # Parse multipart form data
            content_type = self.headers.get('Content-Type', '')

            if 'multipart/form-data' in content_type:
                # Parse boundary
                boundary = None
                for part in content_type.split(';'):
                    part = part.strip()
                    if part.startswith('boundary='):
                        boundary = part[9:].strip('"')
                        break

                if not boundary:
                    self.send_json({'error': 'Invalid multipart form data'}, 400)
                    return

                # Read and parse body
                body = self.rfile.read(content_length)

                # Parse multipart data
                file_data, filename, secret_key = self.parse_multipart_with_secret(body, boundary)

                if not file_data:
                    self.send_json({'error': 'No file found in request'}, 400)
                    return

                # Validate secret key
                if not secret_key:
                    self.send_json({'error': 'Secret key is required (minimum 8 characters)'}, 400)
                    return

                if len(secret_key) < MIN_SECRET_KEY_LENGTH:
                    self.send_json({'error': f'Secret key must be at least {MIN_SECRET_KEY_LENGTH} characters'}, 400)
                    return

            else:
                self.send_json({'error': 'Multipart form data required'}, 400)
                return

            # Validate file type and analyze
            if analysis_type == 'email':
                if not filename.lower().endswith('.eml'):
                    # Try to detect by content
                    if not (b'From:' in file_data or b'Subject:' in file_data or b'MIME-Version:' in file_data):
                        self.send_json({'error': 'Invalid email file. Please upload a .eml file.'}, 400)
                        return
                result = analyze_email(file_data)

            elif analysis_type == 'pdf':
                if not file_data.startswith(b'%PDF'):
                    self.send_json({'error': 'Invalid PDF file.'}, 400)
                    return
                result = analyze_pdf(file_data)

            elif analysis_type == 'office':
                # Check magic bytes for Office documents
                is_ole = file_data[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'  # OLE compound file
                is_ooxml = file_data[:4] == b'PK\x03\x04'  # ZIP (OOXML format)

                if not (is_ole or is_ooxml):
                    self.send_json({'error': 'Invalid Office document.'}, 400)
                    return

                result = analyze_office(file_data, filename)

            elif analysis_type == 'qrcode':
                # Check for image magic bytes
                is_png = file_data[:8] == b'\x89PNG\r\n\x1a\n'
                is_jpeg = file_data[:2] == b'\xff\xd8'
                is_gif = file_data[:6] in (b'GIF87a', b'GIF89a')
                is_bmp = file_data[:2] == b'BM'
                is_webp = file_data[:4] == b'RIFF' and file_data[8:12] == b'WEBP'

                if not (is_png or is_jpeg or is_gif or is_bmp or is_webp):
                    self.send_json({'error': 'Invalid image file. Supported formats: PNG, JPEG, GIF, BMP, WebP'}, 400)
                    return

                result = analyze_qrcode(file_data)
            else:
                self.send_json({'error': 'Unknown analysis type'}, 400)
                return

            # Generate AI-style verdict for file analysis
            if result.get('success'):
                result['verdict'] = generate_file_analysis_verdict(analysis_type, result, filename)

            # Apply AI validation to file analysis results
            if AI_VALIDATOR_AVAILABLE and result.get('success') and analysis_type in ['email', 'pdf', 'office']:
                ai_analysis = ai_validator.validate_file(result, analysis_type)
                result['aiValidation'] = ai_analysis
                result['aiValidatedScore'] = ai_analysis.get('validatedScore', result.get('riskScore', 0))
                result['aiConfidence'] = ai_analysis.get('confidence', 0)
                result['aiRecommendation'] = ai_analysis.get('recommendation', '')

            # If analysis successful, store results
            if result.get('success'):
                storage = get_storage()
                entry_ref, expires_at = storage.store(
                    filename,
                    analysis_type,
                    file_data,
                    result,
                    secret_key,
                    self.get_client_ip()
                )

                # Add storage info to result
                result['entryRef'] = entry_ref
                result['expiresAt'] = expires_at
                result['storedAt'] = datetime.now().isoformat()

            self.send_json(result)

        except Exception as e:
            self.send_json({'error': f'Analysis failed: {str(e)}'}, 500)

    def parse_multipart_with_secret(self, body, boundary):
        """Parse multipart form data and extract file and secret key"""
        boundary_bytes = boundary.encode()
        parts = body.split(b'--' + boundary_bytes)

        file_data = None
        filename = 'uploaded_file'
        secret_key = None

        for part in parts:
            if b'Content-Disposition' not in part:
                continue

            # Split headers from content
            if b'\r\n\r\n' in part:
                headers_part, content = part.split(b'\r\n\r\n', 1)
            elif b'\n\n' in part:
                headers_part, content = part.split(b'\n\n', 1)
            else:
                continue

            headers_str = headers_part.decode('utf-8', errors='ignore')

            # Check if this is a file field
            if 'filename=' in headers_str:
                # Extract filename
                filename_match = re.search(r'filename="([^"]+)"', headers_str)
                if not filename_match:
                    filename_match = re.search(r"filename='([^']+)'", headers_str)

                filename = filename_match.group(1) if filename_match else 'uploaded_file'

                # Remove trailing boundary markers
                content = content.rstrip(b'\r\n')
                if content.endswith(b'--'):
                    content = content[:-2].rstrip(b'\r\n')

                file_data = content

            # Check for secretKey field
            elif 'name="secretKey"' in headers_str or "name='secretKey'" in headers_str:
                content = content.rstrip(b'\r\n')
                if content.endswith(b'--'):
                    content = content[:-2].rstrip(b'\r\n')
                secret_key = content.decode('utf-8', errors='ignore').strip()

        return file_data, filename, secret_key

    def get_client_ip(self):
        forwarded = self.headers.get('X-Forwarded-For')
        if forwarded:
            return forwarded.split(',')[0].strip()
        return self.client_address[0]

    def handle_my_ip(self):
        ip = self.get_client_ip()
        self.send_json({'ip': ip})

    def handle_lookup(self):
        path_parts = self.path.split('/')
        ip = path_parts[3] if len(path_parts) > 3 and path_parts[3] else ''

        # Handle localhost/private IPs
        if not ip:
            ip = self.get_client_ip()

        if ip in ('127.0.0.1', '::1') or ip.startswith('192.168.') or ip.startswith('10.'):
            ip = ''  # ip-api.com returns requester's public IP when empty

        try:
            api_url = f'http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query'

            req = urllib.request.Request(api_url, headers={'User-Agent': 'IPLookup/1.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())

            if data.get('status') == 'fail':
                self.send_json({'error': data.get('message', 'Invalid IP address')}, 400)
                return

            # Get threat intelligence from AbuseIPDB
            threat_data = check_abuse_ipdb(data.get('query'))

            threat_info = {
                'abuseScore': 0,
                'totalReports': 0,
                'lastReported': None,
                'isWhitelisted': False,
                'categories': [],
                'recentReports': [],
                'riskLevel': 'Low',
                'apiConfigured': bool(ABUSEIPDB_API_KEY)
            }

            if threat_data:
                abuse_score = threat_data.get('abuseConfidenceScore', 0)
                threat_info = {
                    'abuseScore': abuse_score,
                    'totalReports': threat_data.get('totalReports', 0),
                    'numDistinctUsers': threat_data.get('numDistinctUsers', 0),
                    'lastReported': threat_data.get('lastReportedAt'),
                    'isWhitelisted': threat_data.get('isWhitelisted', False),
                    'isTor': threat_data.get('isTor', False),
                    'usageType': threat_data.get('usageType', 'Unknown'),
                    'domain': threat_data.get('domain'),
                    'hostnames': threat_data.get('hostnames', []),
                    'categories': [],
                    'recentReports': [],
                    'riskLevel': 'Low',
                    'apiConfigured': True
                }

                # Determine risk level
                if abuse_score >= 75:
                    threat_info['riskLevel'] = 'Critical'
                elif abuse_score >= 50:
                    threat_info['riskLevel'] = 'High'
                elif abuse_score >= 25:
                    threat_info['riskLevel'] = 'Medium'
                else:
                    threat_info['riskLevel'] = 'Low'

                # Get reported categories
                reports = threat_data.get('reports', [])
                category_ids = set()
                for report in reports[:10]:  # Last 10 reports
                    for cat_id in report.get('categories', []):
                        category_ids.add(cat_id)
                    threat_info['recentReports'].append({
                        'date': report.get('reportedAt'),
                        'comment': report.get('comment', '')[:200],
                        'categories': [ABUSE_CATEGORIES.get(c, f'Unknown ({c})') for c in report.get('categories', [])]
                    })

                threat_info['categories'] = [ABUSE_CATEGORIES.get(c, f'Unknown ({c})') for c in category_ids]

            result = {
                'ip': data.get('query'),
                'location': {
                    'continent': data.get('continent'),
                    'continentCode': data.get('continentCode'),
                    'country': data.get('country'),
                    'countryCode': data.get('countryCode'),
                    'region': data.get('regionName'),
                    'regionCode': data.get('region'),
                    'city': data.get('city'),
                    'district': data.get('district'),
                    'zipCode': data.get('zip'),
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon'),
                    'timezone': data.get('timezone'),
                    'utcOffset': data.get('offset')
                },
                'network': {
                    'isp': data.get('isp'),
                    'organization': data.get('org'),
                    'asn': data.get('as'),
                    'asName': data.get('asname'),
                    'hostname': data.get('reverse')
                },
                'security': {
                    'isMobile': data.get('mobile'),
                    'isProxy': data.get('proxy'),
                    'isHosting': data.get('hosting')
                },
                'threat': threat_info,
                'currency': data.get('currency')
            }
            self.send_json(result)

        except urllib.error.URLError as e:
            self.send_json({'error': f'Failed to fetch IP information: {str(e)}'}, 500)
        except Exception as e:
            self.send_json({'error': f'Server error: {str(e)}'}, 500)

    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {args[0]}")


class ReuseAddrHTTPServer(HTTPServer):
    """HTTPServer with SO_REUSEADDR enabled to prevent address already in use errors"""
    allow_reuse_address = True


def main():
    # Initialize storage on startup
    get_storage()
    print(f"Database initialized at {DATABASE_FILE}")

    server = ReuseAddrHTTPServer(('0.0.0.0', PORT), IPLookupHandler)

    # Get local IP addresses
    import socket
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except:
        local_ip = '127.0.0.1'

    print(f"\n{'='*50}")
    print(f"  ShieldTier Server Started")
    print(f"{'='*50}")
    print(f"  Local:   http://localhost:{PORT}")
    print(f"  Network: http://{local_ip}:{PORT}")
    print(f"{'='*50}")
    print(f"  Press Ctrl+C to stop the server")
    print(f"{'='*50}\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.shutdown()


if __name__ == '__main__':
    main()
