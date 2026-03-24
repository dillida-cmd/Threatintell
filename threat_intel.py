#!/usr/bin/env python3
"""
Threat Intelligence Module
Integrates multiple threat intelligence APIs for IOC investigation
With persistent SQLite cache for IOC results
"""

import json
import os
import hashlib
import time
import urllib.request
import urllib.error
import urllib.parse
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from functools import lru_cache
import base64
import re

# =============================================================================
# AITM (Adversary-in-the-Middle) Phishing Platform Signatures
# =============================================================================

AITM_PLATFORMS = {
    'evilproxy': {
        'name': 'EvilProxy',
        'domain_patterns': [r'login\.evilproxy', r'evilproxy\.(com|net|io)', r'ep-auth\.'],
        'url_path_patterns': [r'/lure/', r'/proxy/', r'/rp/', r'/evilginx/'],
        'severity': 'critical',
        'mitre': ['T1557.001', 'T1556.006'],
        'description': 'Phishing-as-a-Service platform targeting MFA with reverse proxy'
    },
    'evilginx2': {
        'name': 'EvilGinx2',
        'domain_patterns': [r'evilginx', r'ginx2?\.'],
        'url_path_patterns': [r'/phishlet/', r'/lure/', r'/o365/', r'/outlook/'],
        'severity': 'critical',
        'mitre': ['T1557.001', 'T1556.006'],
        'description': 'Open-source MITM framework for phishing login credentials and session cookies'
    },
    'tycoon2fa': {
        'name': 'Tycoon 2FA',
        'domain_patterns': [r'tycoon', r't2fa\.'],
        'url_path_patterns': [r'/2fa/', r'/auth-verify/', r'/mfa-check/'],
        'severity': 'critical',
        'mitre': ['T1557.001', 'T1539'],
        'description': 'Phishing kit targeting Microsoft 365 and Google with 2FA bypass'
    },
    'greatness': {
        'name': 'Greatness',
        'domain_patterns': [r'greatness', r'grt-phish'],
        'url_path_patterns': [r'/greatness/', r'/grt/', r'/phish-page/'],
        'severity': 'high',
        'mitre': ['T1557.001', 'T1539'],
        'description': 'Microsoft 365 phishing kit with MFA bypass and Telegram bot exfil'
    },
    'caffeine': {
        'name': 'Caffeine',
        'domain_patterns': [r'caffeine-phish', r'caff\.'],
        'url_path_patterns': [r'/caffeine/', r'/caff-auth/'],
        'severity': 'high',
        'mitre': ['T1557.001'],
        'description': 'Subscription-based phishing platform'
    },
    'w3ll': {
        'name': 'W3LL Panel',
        'domain_patterns': [r'w3ll', r'well-panel'],
        'url_path_patterns': [r'/w3ll/', r'/panel-auth/', r'/o365-auth/'],
        'severity': 'critical',
        'mitre': ['T1557.001', 'T1539'],
        'description': 'BEC-focused phishing kit with Microsoft 365 session hijacking'
    },
    'nakedpages': {
        'name': 'NakedPages',
        'domain_patterns': [r'nakedpages', r'naked-page'],
        'url_path_patterns': [r'/naked/', r'/np-auth/'],
        'severity': 'high',
        'mitre': ['T1557.001'],
        'description': 'Phishing kit with anti-bot and detection evasion'
    },
    'dadsec': {
        'name': 'DadSec/Phoenix',
        'domain_patterns': [r'dadsec', r'phoenix-auth', r'phnx\.'],
        'url_path_patterns': [r'/dadsec/', r'/phoenix/', r'/phnx-auth/'],
        'severity': 'critical',
        'mitre': ['T1557.001', 'T1539'],
        'description': 'Advanced phishing platform with rotating infrastructure'
    }
}

AITM_GENERIC_INDICATORS = {
    'brand_impersonation': {
        'brands': ['microsoft', 'office365', 'outlook', 'onedrive', 'sharepoint',
                   'google', 'gmail', 'facebook', 'instagram', 'apple', 'icloud',
                   'amazon', 'netflix', 'paypal', 'linkedin', 'dropbox', 'adobe',
                   'docusign', 'zoom', 'slack', 'teams', 'webex'],
        'legitimate_domains': ['microsoft.com', 'office.com', 'live.com', 'outlook.com',
                               'google.com', 'gmail.com', 'facebook.com', 'instagram.com',
                               'apple.com', 'icloud.com', 'amazon.com', 'netflix.com',
                               'paypal.com', 'linkedin.com', 'dropbox.com', 'adobe.com',
                               'docusign.com', 'zoom.us', 'slack.com', 'teams.microsoft.com',
                               'webex.com']
    },
    'suspicious_tlds': ['.xyz', '.top', '.work', '.click', '.link', '.gq', '.ml', '.cf',
                        '.tk', '.ga', '.buzz', '.rest', '.surf', '.monster', '.quest',
                        '.sbs', '.cfd', '.icu', '.cam', '.fun'],
    'login_path_patterns': [
        r'/login', r'/signin', r'/auth', r'/authenticate', r'/verify',
        r'/security-check', r'/account-verify', r'/password-reset',
        r'/mfa', r'/2fa', r'/otp', r'/session', r'/sso'
    ]
}


def check_aitm_indicators(url: str, domain: str, whois_data: Dict = None, dns_data: Dict = None) -> Dict:
    """Check URL/domain for Adversary-in-the-Middle phishing indicators"""
    result = {
        'detected': False,
        'confidence': 0,
        'platforms': [],
        'indicators': [],
        'severity': 'none',
        'mitre': [],
        'recommendation': ''
    }

    if not url and not domain:
        return result

    url_lower = (url or '').lower()
    domain_lower = (domain or '').lower()
    confidence = 0
    severity_levels = []

    # 1. Check against known AITM platform signatures
    for platform_key, platform in AITM_PLATFORMS.items():
        matched = False
        # Domain pattern match
        for pattern in platform['domain_patterns']:
            if re.search(pattern, domain_lower):
                result['platforms'].append(platform['name'])
                result['indicators'].append({
                    'type': 'platform_domain',
                    'detail': f"Domain matches {platform['name']} pattern: {pattern}",
                    'severity': platform['severity']
                })
                result['mitre'].extend(platform['mitre'])
                confidence += 40
                severity_levels.append(platform['severity'])
                matched = True
                break
        # URL path pattern match
        if not matched:
            for pattern in platform['url_path_patterns']:
                if re.search(pattern, url_lower):
                    result['platforms'].append(platform['name'])
                    result['indicators'].append({
                        'type': 'platform_url_path',
                        'detail': f"URL path matches {platform['name']} pattern: {pattern}",
                        'severity': platform['severity']
                    })
                    result['mitre'].extend(platform['mitre'])
                    confidence += 30
                    severity_levels.append(platform['severity'])
                    break

    # 2. Brand impersonation check
    brand_info = AITM_GENERIC_INDICATORS['brand_impersonation']
    is_legitimate = any(domain_lower.endswith(legit) for legit in brand_info['legitimate_domains'])

    if not is_legitimate:
        for brand in brand_info['brands']:
            if brand in domain_lower:
                result['indicators'].append({
                    'type': 'brand_impersonation',
                    'detail': f"Domain contains '{brand}' but is not an official {brand} domain",
                    'severity': 'high'
                })
                confidence += 25
                severity_levels.append('high')
                break

    # 3. Suspicious TLD check
    for tld in AITM_GENERIC_INDICATORS['suspicious_tlds']:
        if domain_lower.endswith(tld):
            result['indicators'].append({
                'type': 'suspicious_tld',
                'detail': f"Uses suspicious TLD: {tld}",
                'severity': 'medium'
            })
            confidence += 10
            severity_levels.append('medium')
            break

    # 4. Login path pattern check
    for pattern in AITM_GENERIC_INDICATORS['login_path_patterns']:
        if re.search(pattern, url_lower):
            result['indicators'].append({
                'type': 'login_path',
                'detail': f"URL contains login/auth path pattern",
                'severity': 'medium'
            })
            confidence += 10
            break

    # 5. Cross-reference domain age from WHOIS
    if whois_data and not whois_data.get('error'):
        domain_age = whois_data.get('domainAge', {})
        days = domain_age.get('days', 999)
        if days < 30 and confidence > 0:
            result['indicators'].append({
                'type': 'new_domain',
                'detail': f"Domain is only {days} days old — combined with AITM patterns, highly suspicious",
                'severity': 'critical'
            })
            confidence += 20
            severity_levels.append('critical')
        elif days < 90 and confidence > 0:
            result['indicators'].append({
                'type': 'young_domain',
                'detail': f"Domain is {days} days old — relatively new for a login page",
                'severity': 'high'
            })
            confidence += 10
            severity_levels.append('high')

    # 6. Determine overall severity
    severity_rank = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'none': 0}
    if severity_levels:
        max_severity = max(severity_levels, key=lambda s: severity_rank.get(s, 0))
        result['severity'] = max_severity

    # 7. Finalize result
    confidence = min(confidence, 100)
    result['confidence'] = confidence
    result['mitre'] = list(set(result['mitre']))

    if confidence >= 50:
        result['detected'] = True
        platform_names = ', '.join(result['platforms']) if result['platforms'] else 'Generic AITM'
        result['recommendation'] = (
            f"HIGH RISK: This URL/domain exhibits strong indicators of an Adversary-in-the-Middle "
            f"phishing attack ({platform_names}). Do NOT enter credentials. Block this domain immediately "
            f"and check for compromised sessions if any user has visited this URL."
        )
    elif confidence >= 25:
        result['recommendation'] = (
            "SUSPICIOUS: This URL/domain shows some indicators associated with phishing infrastructure. "
            "Exercise caution and verify the domain legitimacy before entering any credentials."
        )

    return result


# Configuration file path
CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'api_keys.json')
CACHE_DB_FILE = os.path.join(os.path.dirname(__file__), 'ioc_cache.db')

# Cache duration settings (in hours)
CACHE_DURATION_HOURS = 24  # Default cache duration
CACHE_DURATION = timedelta(hours=CACHE_DURATION_HOURS)

# Rate limiting (in-memory)
_rate_limits: Dict[str, List[datetime]] = {}

# Database lock for thread safety
_db_lock = threading.Lock()


# =============================================================================
# SQLite Cache Database
# =============================================================================

def init_cache_db():
    """Initialize the cache database"""
    with _db_lock:
        conn = sqlite3.connect(CACHE_DB_FILE)
        cursor = conn.cursor()

        # Create cache table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ioc_cache (
                cache_key TEXT PRIMARY KEY,
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL,
                source TEXT NOT NULL,
                result TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                hit_count INTEGER DEFAULT 1
            )
        ''')

        # Create index for faster lookups
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ioc_cache_type_value
            ON ioc_cache(ioc_type, ioc_value)
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ioc_cache_expires
            ON ioc_cache(expires_at)
        ''')

        # Create stats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cache_stats (
                id INTEGER PRIMARY KEY,
                total_hits INTEGER DEFAULT 0,
                total_misses INTEGER DEFAULT 0,
                api_calls_saved INTEGER DEFAULT 0,
                last_cleanup TEXT
            )
        ''')

        # Initialize stats if not exists
        cursor.execute('SELECT COUNT(*) FROM cache_stats')
        if cursor.fetchone()[0] == 0:
            cursor.execute('''
                INSERT INTO cache_stats (total_hits, total_misses, api_calls_saved, last_cleanup)
                VALUES (0, 0, 0, ?)
            ''', (datetime.now().isoformat(),))

        # =============================================================================
        # Separate IOC Tables for SIEM/Sentinel Export
        # =============================================================================

        # IP IOC Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ioc_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                is_malicious BOOLEAN DEFAULT FALSE,
                risk_score INTEGER DEFAULT 0,
                abuse_score INTEGER DEFAULT 0,
                total_reports INTEGER DEFAULT 0,
                is_tor BOOLEAN DEFAULT FALSE,
                is_proxy BOOLEAN DEFAULT FALSE,
                is_vpn BOOLEAN DEFAULT FALSE,
                is_hosting BOOLEAN DEFAULT FALSE,
                country TEXT,
                country_code TEXT,
                city TEXT,
                isp TEXT,
                org TEXT,
                asn TEXT,
                tags TEXT,
                malware_families TEXT,
                threat_types TEXT,
                first_seen TEXT,
                last_seen TEXT,
                last_updated TEXT NOT NULL,
                raw_data TEXT
            )
        ''')

        # URL IOC Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ioc_urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL UNIQUE,
                domain TEXT,
                is_malicious BOOLEAN DEFAULT FALSE,
                risk_score INTEGER DEFAULT 0,
                vt_malicious INTEGER DEFAULT 0,
                vt_suspicious INTEGER DEFAULT 0,
                vt_harmless INTEGER DEFAULT 0,
                urlhaus_status TEXT,
                threat_type TEXT,
                malware_family TEXT,
                tags TEXT,
                categories TEXT,
                first_seen TEXT,
                last_seen TEXT,
                last_updated TEXT NOT NULL,
                raw_data TEXT
            )
        ''')

        # Hash IOC Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ioc_hashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash_value TEXT NOT NULL UNIQUE,
                hash_type TEXT,
                is_malicious BOOLEAN DEFAULT FALSE,
                risk_score INTEGER DEFAULT 0,
                vt_malicious INTEGER DEFAULT 0,
                vt_suspicious INTEGER DEFAULT 0,
                vt_harmless INTEGER DEFAULT 0,
                file_name TEXT,
                file_type TEXT,
                file_size INTEGER,
                malware_family TEXT,
                threat_type TEXT,
                tags TEXT,
                av_detections TEXT,
                first_seen TEXT,
                last_seen TEXT,
                last_updated TEXT NOT NULL,
                raw_data TEXT
            )
        ''')

        # Create indexes for IOC tables
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc_ips_malicious ON ioc_ips(is_malicious)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc_ips_risk ON ioc_ips(risk_score)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc_urls_malicious ON ioc_urls(is_malicious)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc_urls_domain ON ioc_urls(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc_hashes_malicious ON ioc_hashes(is_malicious)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc_hashes_type ON ioc_hashes(hash_type)')

        conn.commit()
        conn.close()


def get_cached_db(cache_key: str) -> Optional[Dict]:
    """Get cached response from database if not expired"""
    with _db_lock:
        try:
            conn = sqlite3.connect(CACHE_DB_FILE)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT result, expires_at, hit_count FROM ioc_cache
                WHERE cache_key = ?
            ''', (cache_key,))

            row = cursor.fetchone()
            if row:
                result_json, expires_at, hit_count = row
                expires = datetime.fromisoformat(expires_at)

                if datetime.now() < expires:
                    # Update hit count
                    cursor.execute('''
                        UPDATE ioc_cache SET hit_count = ? WHERE cache_key = ?
                    ''', (hit_count + 1, cache_key))

                    # Update stats
                    cursor.execute('''
                        UPDATE cache_stats SET total_hits = total_hits + 1,
                        api_calls_saved = api_calls_saved + 1
                    ''')

                    conn.commit()
                    conn.close()

                    result = json.loads(result_json)
                    result['_cached'] = True
                    result['_cache_hit_count'] = hit_count + 1
                    return result
                else:
                    # Expired, delete it
                    cursor.execute('DELETE FROM ioc_cache WHERE cache_key = ?', (cache_key,))
                    conn.commit()

            # Cache miss
            cursor.execute('UPDATE cache_stats SET total_misses = total_misses + 1')
            conn.commit()
            conn.close()
            return None

        except Exception as e:
            print(f"[ThreatIntel Cache] DB read error: {e}")
            return None


def set_cached_db(cache_key: str, ioc_type: str, ioc_value: str, source: str, value: Dict):
    """Cache a response in the database"""
    with _db_lock:
        try:
            conn = sqlite3.connect(CACHE_DB_FILE)
            cursor = conn.cursor()

            now = datetime.now()
            expires = now + CACHE_DURATION

            # Remove _cached flag if present before storing
            value_to_store = {k: v for k, v in value.items() if not k.startswith('_')}

            cursor.execute('''
                INSERT OR REPLACE INTO ioc_cache
                (cache_key, ioc_type, ioc_value, source, result, created_at, expires_at, hit_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            ''', (
                cache_key,
                ioc_type,
                ioc_value,
                source,
                json.dumps(value_to_store),
                now.isoformat(),
                expires.isoformat()
            ))

            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[ThreatIntel Cache] DB write error: {e}")


def cleanup_expired_cache() -> int:
    """Remove expired cache entries, returns count of removed entries"""
    with _db_lock:
        try:
            conn = sqlite3.connect(CACHE_DB_FILE)
            cursor = conn.cursor()

            now = datetime.now().isoformat()

            cursor.execute('SELECT COUNT(*) FROM ioc_cache WHERE expires_at < ?', (now,))
            expired_count = cursor.fetchone()[0]

            cursor.execute('DELETE FROM ioc_cache WHERE expires_at < ?', (now,))

            cursor.execute('UPDATE cache_stats SET last_cleanup = ?', (now,))

            conn.commit()
            conn.close()

            return expired_count
        except Exception as e:
            print(f"[ThreatIntel Cache] Cleanup error: {e}")
            return 0


def get_cache_stats() -> Dict:
    """Get cache statistics"""
    with _db_lock:
        try:
            conn = sqlite3.connect(CACHE_DB_FILE)
            cursor = conn.cursor()

            # Get stats
            cursor.execute('SELECT total_hits, total_misses, api_calls_saved, last_cleanup FROM cache_stats LIMIT 1')
            row = cursor.fetchone()

            # Get cache size
            cursor.execute('SELECT COUNT(*) FROM ioc_cache')
            total_entries = cursor.fetchone()[0]

            # Get entries by type
            cursor.execute('SELECT ioc_type, COUNT(*) FROM ioc_cache GROUP BY ioc_type')
            by_type = dict(cursor.fetchall())

            # Get entries by source
            cursor.execute('SELECT source, COUNT(*) FROM ioc_cache GROUP BY source')
            by_source = dict(cursor.fetchall())

            # Get top cached IOCs
            cursor.execute('''
                SELECT ioc_type, ioc_value, hit_count FROM ioc_cache
                ORDER BY hit_count DESC LIMIT 10
            ''')
            top_hits = [{'type': r[0], 'value': r[1], 'hits': r[2]} for r in cursor.fetchall()]

            conn.close()

            if row:
                total_hits, total_misses, api_calls_saved, last_cleanup = row
                hit_rate = (total_hits / (total_hits + total_misses) * 100) if (total_hits + total_misses) > 0 else 0

                return {
                    'totalEntries': total_entries,
                    'totalHits': total_hits,
                    'totalMisses': total_misses,
                    'hitRate': round(hit_rate, 2),
                    'apiCallsSaved': api_calls_saved,
                    'lastCleanup': last_cleanup,
                    'cacheDurationHours': CACHE_DURATION_HOURS,
                    'byType': by_type,
                    'bySource': by_source,
                    'topHits': top_hits
                }

            return {'error': 'No stats available'}

        except Exception as e:
            return {'error': str(e)}


def clear_cache(ioc_type: str = None, source: str = None) -> int:
    """Clear cache entries, optionally filtered by type or source"""
    with _db_lock:
        try:
            conn = sqlite3.connect(CACHE_DB_FILE)
            cursor = conn.cursor()

            if ioc_type and source:
                cursor.execute('DELETE FROM ioc_cache WHERE ioc_type = ? AND source = ?', (ioc_type, source))
            elif ioc_type:
                cursor.execute('DELETE FROM ioc_cache WHERE ioc_type = ?', (ioc_type,))
            elif source:
                cursor.execute('DELETE FROM ioc_cache WHERE source = ?', (source,))
            else:
                cursor.execute('DELETE FROM ioc_cache')

            deleted = cursor.rowcount
            conn.commit()
            conn.close()

            return deleted
        except Exception as e:
            print(f"[ThreatIntel Cache] Clear error: {e}")
            return 0


def search_cache(query: str, limit: int = 50) -> List[Dict]:
    """Search cache for IOCs matching query"""
    with _db_lock:
        try:
            conn = sqlite3.connect(CACHE_DB_FILE)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT ioc_type, ioc_value, source, result, hit_count, created_at, expires_at
                FROM ioc_cache
                WHERE ioc_value LIKE ?
                ORDER BY hit_count DESC
                LIMIT ?
            ''', (f'%{query}%', limit))

            results = []
            for row in cursor.fetchall():
                ioc_type, ioc_value, source, result_json, hit_count, created_at, expires_at = row
                results.append({
                    'type': ioc_type,
                    'value': ioc_value,
                    'source': source,
                    'result': json.loads(result_json),
                    'hitCount': hit_count,
                    'createdAt': created_at,
                    'expiresAt': expires_at
                })

            conn.close()
            return results

        except Exception as e:
            print(f"[ThreatIntel Cache] Search error: {e}")
            return []


# Initialize cache database on module load
init_cache_db()


# =============================================================================
# IOC Storage Functions (for SIEM/Sentinel Export)
# =============================================================================

def store_ip_ioc(ip: str, investigation_result: Dict):
    """Store IP investigation result in the IOC table"""
    with _db_lock:
        try:
            conn = sqlite3.connect(CACHE_DB_FILE)
            cursor = conn.cursor()

            # Extract data from investigation result
            summary = investigation_result.get('summary', {})
            sources = investigation_result.get('sources', {})

            # Determine if malicious
            is_malicious = summary.get('isMalicious', False)
            risk_score = summary.get('riskScore', 0)

            # Extract from various sources
            abuse_score = 0
            total_reports = 0
            is_tor = False
            is_proxy = False
            is_vpn = False
            is_hosting = False
            country = None
            country_code = None
            city = None
            isp = None
            org = None
            asn = None
            tags = []
            malware_families = []
            threat_types = []

            # AbuseIPDB
            if 'abuseipdb' in sources:
                abuse_data = sources['abuseipdb']
                abuse_score = abuse_data.get('abuseConfidenceScore', 0)
                total_reports = abuse_data.get('totalReports', 0)
                is_tor = abuse_data.get('isTor', False)
                country_code = abuse_data.get('countryCode')

            # IPQualityScore
            if 'ipqualityscore' in sources:
                ipqs = sources['ipqualityscore']
                is_proxy = ipqs.get('proxy', False)
                is_vpn = ipqs.get('vpn', False)
                is_tor = is_tor or ipqs.get('tor', False)
                is_hosting = ipqs.get('is_crawler', False) or ipqs.get('host', False)
                country_code = country_code or ipqs.get('country_code')
                city = ipqs.get('city')
                isp = ipqs.get('ISP')
                org = ipqs.get('organization')
                asn = ipqs.get('ASN')

            # GreyNoise
            if 'greynoise' in sources:
                gn = sources['greynoise']
                if gn.get('classification'):
                    tags.append(f"greynoise:{gn['classification']}")

            # Shodan
            if 'shodan' in sources:
                shodan = sources['shodan']
                if shodan.get('tags'):
                    tags.extend(shodan['tags'])
                country = shodan.get('country_name')
                city = city or shodan.get('city')
                isp = isp or shodan.get('isp')
                org = org or shodan.get('org')
                asn = asn or shodan.get('asn')

            # ThreatFox
            if 'threatfox' in sources:
                tf = sources['threatfox']
                if tf.get('malware'):
                    malware_families.append(tf['malware'])
                if tf.get('threat_type'):
                    threat_types.append(tf['threat_type'])
                if tf.get('tags'):
                    tags.extend(tf['tags'])

            # AlienVault OTX
            if 'alienvault_otx' in sources:
                otx = sources['alienvault_otx']
                if otx.get('pulses'):
                    for pulse in otx['pulses'][:5]:
                        if pulse.get('tags'):
                            tags.extend(pulse['tags'][:3])

            cursor.execute('''
                INSERT OR REPLACE INTO ioc_ips
                (ip, is_malicious, risk_score, abuse_score, total_reports,
                 is_tor, is_proxy, is_vpn, is_hosting, country, country_code,
                 city, isp, org, asn, tags, malware_families, threat_types,
                 last_updated, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                ip,
                is_malicious,
                risk_score,
                abuse_score,
                total_reports,
                is_tor,
                is_proxy,
                is_vpn,
                is_hosting,
                country,
                country_code,
                city,
                isp,
                org,
                asn,
                json.dumps(list(set(tags))) if tags else None,
                json.dumps(list(set(malware_families))) if malware_families else None,
                json.dumps(list(set(threat_types))) if threat_types else None,
                datetime.now().isoformat(),
                json.dumps(investigation_result)
            ))

            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[ThreatIntel] Error storing IP IOC: {e}")


def store_url_ioc(url: str, investigation_result: Dict):
    """Store URL investigation result in the IOC table"""
    with _db_lock:
        try:
            conn = sqlite3.connect(CACHE_DB_FILE)
            cursor = conn.cursor()

            summary = investigation_result.get('summary', {})
            sources = investigation_result.get('sources', {})

            is_malicious = summary.get('isMalicious', False)
            risk_score = summary.get('riskScore', 0)

            # Extract domain from URL
            try:
                from urllib.parse import urlparse
                domain = urlparse(url).netloc
            except:
                domain = None

            vt_malicious = 0
            vt_suspicious = 0
            vt_harmless = 0
            urlhaus_status = None
            threat_type = None
            malware_family = None
            tags = []
            categories = []

            # VirusTotal
            if 'virustotal' in sources:
                vt = sources['virustotal']
                vt_malicious = vt.get('malicious', 0)
                vt_suspicious = vt.get('suspicious', 0)
                vt_harmless = vt.get('harmless', 0)
                if vt.get('categories'):
                    categories = list(vt['categories'].values())

            # URLhaus
            if 'urlhaus' in sources:
                uh = sources['urlhaus']
                urlhaus_status = uh.get('status')
                threat_type = uh.get('threat')
                if uh.get('tags'):
                    tags.extend(uh['tags'])

            # ThreatFox
            if 'threatfox' in sources:
                tf = sources['threatfox']
                malware_family = tf.get('malware')
                threat_type = threat_type or tf.get('threat_type')
                if tf.get('tags'):
                    tags.extend(tf['tags'])

            cursor.execute('''
                INSERT OR REPLACE INTO ioc_urls
                (url, domain, is_malicious, risk_score, vt_malicious,
                 vt_suspicious, vt_harmless, urlhaus_status, threat_type,
                 malware_family, tags, categories, last_updated, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                url,
                domain,
                is_malicious,
                risk_score,
                vt_malicious,
                vt_suspicious,
                vt_harmless,
                urlhaus_status,
                threat_type,
                malware_family,
                json.dumps(list(set(tags))) if tags else None,
                json.dumps(categories) if categories else None,
                datetime.now().isoformat(),
                json.dumps(investigation_result)
            ))

            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[ThreatIntel] Error storing URL IOC: {e}")


def store_hash_ioc(hash_value: str, investigation_result: Dict):
    """Store hash investigation result in the IOC table"""
    with _db_lock:
        try:
            conn = sqlite3.connect(CACHE_DB_FILE)
            cursor = conn.cursor()

            summary = investigation_result.get('summary', {})
            sources = investigation_result.get('sources', {})

            is_malicious = summary.get('isMalicious', False)
            risk_score = summary.get('riskScore', 0)

            # Determine hash type
            hash_len = len(hash_value)
            if hash_len == 32:
                hash_type = 'md5'
            elif hash_len == 40:
                hash_type = 'sha1'
            elif hash_len == 64:
                hash_type = 'sha256'
            else:
                hash_type = 'unknown'

            vt_malicious = 0
            vt_suspicious = 0
            vt_harmless = 0
            file_name = None
            file_type = None
            file_size = None
            malware_family = None
            threat_type = None
            tags = []
            av_detections = []

            # VirusTotal
            if 'virustotal' in sources:
                vt = sources['virustotal']
                vt_malicious = vt.get('malicious', 0)
                vt_suspicious = vt.get('suspicious', 0)
                vt_harmless = vt.get('harmless', 0)
                file_name = vt.get('meaningful_name') or vt.get('names', [None])[0] if vt.get('names') else None
                file_type = vt.get('type_description')
                file_size = vt.get('size')
                if vt.get('tags'):
                    tags.extend(vt['tags'])
                if vt.get('popular_threat_classification'):
                    ptc = vt['popular_threat_classification']
                    if ptc.get('suggested_threat_label'):
                        malware_family = ptc['suggested_threat_label']

            # ThreatFox
            if 'threatfox' in sources:
                tf = sources['threatfox']
                malware_family = malware_family or tf.get('malware')
                threat_type = tf.get('threat_type')
                if tf.get('tags'):
                    tags.extend(tf['tags'])

            # MalwareBazaar
            if 'malwarebazaar' in sources:
                mb = sources['malwarebazaar']
                file_name = file_name or mb.get('file_name')
                file_type = file_type or mb.get('file_type')
                file_size = file_size or mb.get('file_size')
                if mb.get('signature'):
                    malware_family = malware_family or mb['signature']
                if mb.get('tags'):
                    tags.extend(mb['tags'])

            cursor.execute('''
                INSERT OR REPLACE INTO ioc_hashes
                (hash_value, hash_type, is_malicious, risk_score, vt_malicious,
                 vt_suspicious, vt_harmless, file_name, file_type, file_size,
                 malware_family, threat_type, tags, av_detections, last_updated, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                hash_value.lower(),
                hash_type,
                is_malicious,
                risk_score,
                vt_malicious,
                vt_suspicious,
                vt_harmless,
                file_name,
                file_type,
                file_size,
                malware_family,
                threat_type,
                json.dumps(list(set(tags))) if tags else None,
                json.dumps(av_detections) if av_detections else None,
                datetime.now().isoformat(),
                json.dumps(investigation_result)
            ))

            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[ThreatIntel] Error storing hash IOC: {e}")


# =============================================================================
# IOC Export Functions (for SIEM/Sentinel)
# =============================================================================

def export_iocs(ioc_type: str = None, malicious_only: bool = False,
                min_risk_score: int = 0, format: str = 'json',
                limit: int = 1000) -> Dict:
    """
    Export IOCs for SIEM/Sentinel import

    Args:
        ioc_type: 'ip', 'url', 'hash', or None for all
        malicious_only: Only export IOCs marked as malicious
        min_risk_score: Minimum risk score to include
        format: 'json', 'csv', or 'sentinel' (Azure Sentinel format)
        limit: Maximum number of records to export

    Returns:
        Dict with export data and metadata
    """
    with _db_lock:
        try:
            conn = sqlite3.connect(CACHE_DB_FILE)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            results = {
                'exportedAt': datetime.now().isoformat(),
                'format': format,
                'filters': {
                    'iocType': ioc_type,
                    'maliciousOnly': malicious_only,
                    'minRiskScore': min_risk_score
                },
                'ips': [],
                'urls': [],
                'hashes': [],
                'counts': {'ips': 0, 'urls': 0, 'hashes': 0, 'total': 0}
            }

            # Build WHERE clause
            def build_where(malicious_col='is_malicious', risk_col='risk_score'):
                conditions = []
                params = []
                if malicious_only:
                    conditions.append(f'{malicious_col} = 1')
                if min_risk_score > 0:
                    conditions.append(f'{risk_col} >= ?')
                    params.append(min_risk_score)
                where = ' WHERE ' + ' AND '.join(conditions) if conditions else ''
                return where, params

            # Export IPs
            if ioc_type is None or ioc_type == 'ip':
                where, params = build_where()
                cursor.execute(f'''
                    SELECT ip, is_malicious, risk_score, abuse_score, total_reports,
                           is_tor, is_proxy, is_vpn, is_hosting, country, country_code,
                           city, isp, org, asn, tags, malware_families, threat_types,
                           first_seen, last_seen, last_updated
                    FROM ioc_ips {where}
                    ORDER BY risk_score DESC, last_updated DESC
                    LIMIT ?
                ''', params + [limit])

                for row in cursor.fetchall():
                    ip_data = dict(row)
                    # Parse JSON fields
                    for field in ['tags', 'malware_families', 'threat_types']:
                        if ip_data.get(field):
                            try:
                                ip_data[field] = json.loads(ip_data[field])
                            except:
                                pass
                    results['ips'].append(ip_data)
                results['counts']['ips'] = len(results['ips'])

            # Export URLs
            if ioc_type is None or ioc_type == 'url':
                where, params = build_where()
                cursor.execute(f'''
                    SELECT url, domain, is_malicious, risk_score, vt_malicious,
                           vt_suspicious, vt_harmless, urlhaus_status, threat_type,
                           malware_family, tags, categories, first_seen, last_seen,
                           last_updated
                    FROM ioc_urls {where}
                    ORDER BY risk_score DESC, last_updated DESC
                    LIMIT ?
                ''', params + [limit])

                for row in cursor.fetchall():
                    url_data = dict(row)
                    for field in ['tags', 'categories']:
                        if url_data.get(field):
                            try:
                                url_data[field] = json.loads(url_data[field])
                            except:
                                pass
                    results['urls'].append(url_data)
                results['counts']['urls'] = len(results['urls'])

            # Export Hashes
            if ioc_type is None or ioc_type == 'hash':
                where, params = build_where()
                cursor.execute(f'''
                    SELECT hash_value, hash_type, is_malicious, risk_score, vt_malicious,
                           vt_suspicious, vt_harmless, file_name, file_type, file_size,
                           malware_family, threat_type, tags, first_seen, last_seen,
                           last_updated
                    FROM ioc_hashes {where}
                    ORDER BY risk_score DESC, last_updated DESC
                    LIMIT ?
                ''', params + [limit])

                for row in cursor.fetchall():
                    hash_data = dict(row)
                    if hash_data.get('tags'):
                        try:
                            hash_data['tags'] = json.loads(hash_data['tags'])
                        except:
                            pass
                    results['hashes'].append(hash_data)
                results['counts']['hashes'] = len(results['hashes'])

            results['counts']['total'] = (results['counts']['ips'] +
                                          results['counts']['urls'] +
                                          results['counts']['hashes'])

            conn.close()

            # Convert to requested format
            if format == 'sentinel':
                return convert_to_sentinel_format(results)
            elif format == 'csv':
                return convert_to_csv_format(results)
            else:
                return results

        except Exception as e:
            return {'error': str(e)}


def convert_to_sentinel_format(data: Dict) -> Dict:
    """Convert IOC export to Azure Sentinel TI format"""
    indicators = []

    # IPs
    for ip in data.get('ips', []):
        indicator = {
            'type': 'indicator',
            'spec_version': '2.1',
            'pattern_type': 'stix',
            'pattern': f"[ipv4-addr:value = '{ip['ip']}']",
            'valid_from': ip.get('first_seen') or ip.get('last_updated'),
            'created': ip.get('last_updated'),
            'modified': ip.get('last_updated'),
            'confidence': min(ip.get('risk_score', 0), 100),
            'labels': [],
            'external_references': []
        }
        if ip.get('is_malicious'):
            indicator['labels'].append('malicious-activity')
        if ip.get('is_tor'):
            indicator['labels'].append('tor-exit-node')
        if ip.get('malware_families'):
            for mf in ip['malware_families']:
                indicator['labels'].append(f'malware:{mf}')
        indicators.append(indicator)

    # URLs
    for url in data.get('urls', []):
        indicator = {
            'type': 'indicator',
            'spec_version': '2.1',
            'pattern_type': 'stix',
            'pattern': f"[url:value = '{url['url']}']",
            'valid_from': url.get('first_seen') or url.get('last_updated'),
            'created': url.get('last_updated'),
            'modified': url.get('last_updated'),
            'confidence': min(url.get('risk_score', 0), 100),
            'labels': [],
            'external_references': []
        }
        if url.get('is_malicious'):
            indicator['labels'].append('malicious-activity')
        if url.get('malware_family'):
            indicator['labels'].append(f'malware:{url["malware_family"]}')
        if url.get('threat_type'):
            indicator['labels'].append(url['threat_type'])
        indicators.append(indicator)

    # Hashes
    for h in data.get('hashes', []):
        hash_type_map = {'md5': 'MD5', 'sha1': 'SHA-1', 'sha256': 'SHA-256'}
        stix_hash_type = hash_type_map.get(h.get('hash_type'), 'SHA-256')
        indicator = {
            'type': 'indicator',
            'spec_version': '2.1',
            'pattern_type': 'stix',
            'pattern': f"[file:hashes.'{stix_hash_type}' = '{h['hash_value']}']",
            'valid_from': h.get('first_seen') or h.get('last_updated'),
            'created': h.get('last_updated'),
            'modified': h.get('last_updated'),
            'confidence': min(h.get('risk_score', 0), 100),
            'labels': [],
            'external_references': []
        }
        if h.get('is_malicious'):
            indicator['labels'].append('malicious-activity')
        if h.get('malware_family'):
            indicator['labels'].append(f'malware:{h["malware_family"]}')
        if h.get('file_name'):
            indicator['name'] = h['file_name']
        indicators.append(indicator)

    return {
        'type': 'bundle',
        'id': f'bundle--shieldtier-{datetime.now().strftime("%Y%m%d%H%M%S")}',
        'objects': indicators,
        'exportedAt': data.get('exportedAt'),
        'counts': data.get('counts')
    }


def convert_to_csv_format(data: Dict) -> Dict:
    """Convert IOC export to CSV format"""
    csv_data = {
        'exportedAt': data.get('exportedAt'),
        'counts': data.get('counts'),
        'ips_csv': '',
        'urls_csv': '',
        'hashes_csv': ''
    }

    # IPs CSV
    if data.get('ips'):
        headers = ['ip', 'is_malicious', 'risk_score', 'abuse_score', 'is_tor', 'is_proxy', 'is_vpn', 'country_code', 'isp', 'last_updated']
        lines = [','.join(headers)]
        for ip in data['ips']:
            row = [str(ip.get(h, '')) for h in headers]
            lines.append(','.join(row))
        csv_data['ips_csv'] = '\n'.join(lines)

    # URLs CSV
    if data.get('urls'):
        headers = ['url', 'domain', 'is_malicious', 'risk_score', 'vt_malicious', 'threat_type', 'malware_family', 'last_updated']
        lines = [','.join(headers)]
        for url in data['urls']:
            row = [str(url.get(h, '')).replace(',', ';') for h in headers]
            lines.append(','.join(row))
        csv_data['urls_csv'] = '\n'.join(lines)

    # Hashes CSV
    if data.get('hashes'):
        headers = ['hash_value', 'hash_type', 'is_malicious', 'risk_score', 'vt_malicious', 'file_name', 'malware_family', 'last_updated']
        lines = [','.join(headers)]
        for h in data['hashes']:
            row = [str(h.get(hdr, '')).replace(',', ';') for hdr in headers]
            lines.append(','.join(row))
        csv_data['hashes_csv'] = '\n'.join(lines)

    return csv_data


def get_ioc_stats() -> Dict:
    """Get statistics about stored IOCs"""
    with _db_lock:
        try:
            conn = sqlite3.connect(CACHE_DB_FILE)
            cursor = conn.cursor()

            stats = {
                'ips': {'total': 0, 'malicious': 0},
                'urls': {'total': 0, 'malicious': 0},
                'hashes': {'total': 0, 'malicious': 0}
            }

            # IP stats
            cursor.execute('SELECT COUNT(*) FROM ioc_ips')
            stats['ips']['total'] = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM ioc_ips WHERE is_malicious = 1')
            stats['ips']['malicious'] = cursor.fetchone()[0]

            # URL stats
            cursor.execute('SELECT COUNT(*) FROM ioc_urls')
            stats['urls']['total'] = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM ioc_urls WHERE is_malicious = 1')
            stats['urls']['malicious'] = cursor.fetchone()[0]

            # Hash stats
            cursor.execute('SELECT COUNT(*) FROM ioc_hashes')
            stats['hashes']['total'] = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM ioc_hashes WHERE is_malicious = 1')
            stats['hashes']['malicious'] = cursor.fetchone()[0]

            stats['totalIOCs'] = stats['ips']['total'] + stats['urls']['total'] + stats['hashes']['total']
            stats['totalMalicious'] = stats['ips']['malicious'] + stats['urls']['malicious'] + stats['hashes']['malicious']

            conn.close()
            return stats

        except Exception as e:
            return {'error': str(e)}


def load_config() -> Dict:
    """Load API keys from configuration file"""
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            # Remove comment fields
            return {k: v for k, v in config.items() if not k.startswith('_')}
    except FileNotFoundError:
        print(f"[ThreatIntel] Config file not found: {CONFIG_FILE}")
        return {}
    except json.JSONDecodeError as e:
        print(f"[ThreatIntel] Invalid JSON in config: {e}")
        return {}


def get_api_key(service: str) -> Optional[str]:
    """Get API key for a service if enabled"""
    config = load_config()
    service_config = config.get(service, {})
    if service_config.get('enabled', False):
        return service_config.get('api_key', '')
    return None


def is_service_enabled(service: str) -> bool:
    """Check if a service is enabled"""
    config = load_config()
    service_config = config.get(service, {})
    return service_config.get('enabled', False)


def check_rate_limit(service: str, max_requests: int, window_seconds: int) -> bool:
    """Check if we're within rate limits for a service"""
    now = datetime.now()
    if service not in _rate_limits:
        _rate_limits[service] = []

    # Clean old entries
    _rate_limits[service] = [
        t for t in _rate_limits[service]
        if now - t < timedelta(seconds=window_seconds)
    ]

    if len(_rate_limits[service]) >= max_requests:
        return False

    _rate_limits[service].append(now)
    return True


def get_cached(key: str) -> Optional[Dict]:
    """Get cached response from database if not expired"""
    return get_cached_db(key)


def set_cached(key: str, value: Dict):
    """Cache a response in the database"""
    # Parse key to extract type and value (format: "source:type:value" or "source:value")
    parts = key.split(':', 2)
    if len(parts) >= 2:
        source = parts[0]
        if len(parts) == 3:
            ioc_type = parts[1]
            ioc_value = parts[2]
        else:
            ioc_type = 'unknown'
            ioc_value = parts[1]
        set_cached_db(key, ioc_type, ioc_value, source, value)


def make_request(url: str, headers: Dict = None, data: bytes = None,
                 method: str = 'GET', timeout: int = 10) -> Optional[Dict]:
    """Make HTTP request with error handling"""
    try:
        req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        print(f"[ThreatIntel] HTTP error {e.code}: {url}")
        return None
    except urllib.error.URLError as e:
        print(f"[ThreatIntel] URL error: {e.reason}")
        return None
    except json.JSONDecodeError:
        return None
    except Exception as e:
        print(f"[ThreatIntel] Request error: {e}")
        return None


# =============================================================================
# AbuseIPDB
# =============================================================================

def check_abuseipdb(ip: str) -> Dict:
    """Check IP reputation on AbuseIPDB"""
    cache_key = f"abuseipdb:ip:{ip}"
    cached = get_cached(cache_key)
    if cached:
        return cached

    api_key = get_api_key('abuseipdb')
    if not api_key:
        return {'error': 'API key not configured', 'source': 'abuseipdb'}

    if not check_rate_limit('abuseipdb', 1000, 86400):  # 1000/day
        return {'error': 'Rate limit exceeded', 'source': 'abuseipdb'}

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose=true"
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }

    response = make_request(url, headers)
    if response and 'data' in response:
        result = {
            'source': 'abuseipdb',
            'ip': ip,
            'abuseScore': response['data'].get('abuseConfidenceScore', 0),
            'totalReports': response['data'].get('totalReports', 0),
            'lastReported': response['data'].get('lastReportedAt'),
            'isp': response['data'].get('isp'),
            'domain': response['data'].get('domain'),
            'countryCode': response['data'].get('countryCode'),
            'isWhitelisted': response['data'].get('isWhitelisted', False),
            'isTor': response['data'].get('isTor', False),
            'usageType': response['data'].get('usageType'),
            'categories': [],
            'recentReports': []
        }

        # Extract categories
        for report in response['data'].get('reports', [])[:5]:
            result['recentReports'].append({
                'reportedAt': report.get('reportedAt'),
                'comment': report.get('comment', '')[:200],
                'categories': report.get('categories', [])
            })
            for cat in report.get('categories', []):
                if cat not in result['categories']:
                    result['categories'].append(cat)

        set_cached(cache_key, result)
        return result

    return {'error': 'No data returned', 'source': 'abuseipdb'}


# =============================================================================
# VirusTotal
# =============================================================================

def check_virustotal_ip(ip: str) -> Dict:
    """Check IP on VirusTotal"""
    cache_key = f"virustotal:ip:{ip}"
    cached = get_cached(cache_key)
    if cached:
        return cached

    api_key = get_api_key('virustotal')
    if not api_key:
        return {'error': 'API key not configured', 'source': 'virustotal'}

    if not check_rate_limit('virustotal', 4, 60):  # 4/minute
        return {'error': 'Rate limit exceeded', 'source': 'virustotal'}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {'x-apikey': api_key}

    response = make_request(url, headers)
    if response and 'data' in response:
        attrs = response['data'].get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        result = {
            'source': 'virustotal',
            'ip': ip,
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0),
            'asOwner': attrs.get('as_owner'),
            'asn': attrs.get('asn'),
            'country': attrs.get('country'),
            'reputation': attrs.get('reputation', 0),
            'lastAnalysisDate': attrs.get('last_analysis_date'),
        }
        set_cached(cache_key, result)
        return result

    return {'error': 'No data returned', 'source': 'virustotal'}


def check_virustotal_url(url_to_check: str) -> Dict:
    """Check URL on VirusTotal"""
    url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip('=')
    cache_key = f"virustotal:url:{url_id}"
    cached = get_cached(cache_key)
    if cached:
        return cached

    api_key = get_api_key('virustotal')
    if not api_key:
        return {'error': 'API key not configured', 'source': 'virustotal'}

    if not check_rate_limit('virustotal', 4, 60):
        return {'error': 'Rate limit exceeded', 'source': 'virustotal'}

    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {'x-apikey': api_key}

    response = make_request(url, headers)
    if response and 'data' in response:
        attrs = response['data'].get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        result = {
            'source': 'virustotal',
            'url': url_to_check,
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0),
            'finalUrl': attrs.get('last_final_url'),
            'title': attrs.get('title'),
            'reputation': attrs.get('reputation', 0),
            'lastAnalysisDate': attrs.get('last_analysis_date'),
            'categories': attrs.get('categories', {}),
        }
        set_cached(cache_key, result)
        return result

    return {'error': 'No data returned', 'source': 'virustotal'}


def check_virustotal_hash(file_hash: str) -> Dict:
    """Check file hash on VirusTotal"""
    cache_key = f"virustotal:hash:{file_hash}"
    cached = get_cached(cache_key)
    if cached:
        return cached

    api_key = get_api_key('virustotal')
    if not api_key:
        return {'error': 'API key not configured', 'source': 'virustotal'}

    if not check_rate_limit('virustotal', 4, 60):
        return {'error': 'Rate limit exceeded', 'source': 'virustotal'}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {'x-apikey': api_key}

    response = make_request(url, headers)
    if response and 'data' in response:
        attrs = response['data'].get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        result = {
            'source': 'virustotal',
            'hash': file_hash,
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0),
            'fileName': attrs.get('meaningful_name'),
            'fileType': attrs.get('type_description'),
            'fileSize': attrs.get('size'),
            'reputation': attrs.get('reputation', 0),
            'lastAnalysisDate': attrs.get('last_analysis_date'),
            'tags': attrs.get('tags', []),
        }
        set_cached(cache_key, result)
        return result

    return {'error': 'No data returned', 'source': 'virustotal'}


# =============================================================================
# URLhaus (abuse.ch) - No API key required
# =============================================================================

def check_urlhaus(url_to_check: str) -> Dict:
    """Check URL on URLhaus"""
    # Use base64 encoded URL to avoid ':' in cache key
    url_encoded = base64.urlsafe_b64encode(url_to_check.encode()).decode()
    cache_key = f"urlhaus:url:{url_encoded}"
    cached = get_cached(cache_key)
    if cached:
        return cached

    if not is_service_enabled('urlhaus'):
        return {'error': 'Service disabled', 'source': 'urlhaus'}

    api_key = get_api_key('urlhaus')
    if not api_key:
        return {'error': 'Auth-Key not configured (get free key at https://auth.abuse.ch/)', 'source': 'urlhaus'}

    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    data = urllib.parse.urlencode({'url': url_to_check}).encode()
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Auth-Key': api_key
    }

    response = make_request(api_url, headers=headers, method='POST', data=data)
    if response:
        if response.get('query_status') == 'ok':
            result = {
                'source': 'urlhaus',
                'url': url_to_check,
                'threat': response.get('threat'),
                'urlStatus': response.get('url_status'),
                'dateAdded': response.get('date_added'),
                'tags': response.get('tags', []),
                'host': response.get('host'),
                'blacklists': response.get('blacklists', {}),
                'payloads': []
            }
            for payload in response.get('payloads', [])[:5]:
                result['payloads'].append({
                    'filename': payload.get('filename'),
                    'fileType': payload.get('file_type'),
                    'sha256': payload.get('sha256_hash'),
                    'signature': payload.get('signature')
                })
            set_cached(cache_key, result)
            return result
        elif response.get('query_status') == 'no_results':
            result = {'source': 'urlhaus', 'url': url_to_check, 'status': 'clean', 'found': False}
            set_cached(cache_key, result)
            return result

    return {'error': 'No data returned', 'source': 'urlhaus'}


def check_urlhaus_hash(file_hash: str) -> Dict:
    """Check file hash on URLhaus"""
    cache_key = f"urlhaus:hash:{file_hash}"
    cached = get_cached(cache_key)
    if cached:
        return cached

    if not is_service_enabled('urlhaus'):
        return {'error': 'Service disabled', 'source': 'urlhaus'}

    api_key = get_api_key('urlhaus')
    if not api_key:
        return {'error': 'Auth-Key not configured', 'source': 'urlhaus'}

    # Determine hash type
    if len(file_hash) == 64:
        hash_type = 'sha256_hash'
    elif len(file_hash) == 32:
        hash_type = 'md5_hash'
    else:
        return {'error': 'Invalid hash format', 'source': 'urlhaus'}

    api_url = "https://urlhaus-api.abuse.ch/v1/payload/"
    data = urllib.parse.urlencode({hash_type: file_hash}).encode()
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Auth-Key': api_key
    }

    response = make_request(api_url, headers=headers, method='POST', data=data)
    if response:
        if response.get('query_status') == 'ok':
            result = {
                'source': 'urlhaus',
                'hash': file_hash,
                'fileType': response.get('file_type'),
                'fileSize': response.get('file_size'),
                'signature': response.get('signature'),
                'firstSeen': response.get('firstseen'),
                'lastSeen': response.get('lastseen'),
                'urlCount': response.get('url_count', 0),
                'urls': []
            }
            for url_info in response.get('urls', [])[:5]:
                result['urls'].append({
                    'url': url_info.get('url'),
                    'status': url_info.get('url_status'),
                    'dateAdded': url_info.get('date_added')
                })
            set_cached(cache_key, result)
            return result
        elif response.get('query_status') == 'no_results':
            result = {'source': 'urlhaus', 'hash': file_hash, 'status': 'clean', 'found': False}
            set_cached(cache_key, result)
            return result

    return {'error': 'No data returned', 'source': 'urlhaus'}


# =============================================================================
# MalwareBazaar (abuse.ch) - No API key required
# =============================================================================

def check_malwarebazaar_hash(file_hash: str) -> Dict:
    """Check file hash on MalwareBazaar"""
    cache_key = f"malwarebazaar:hash:{file_hash}"
    cached = get_cached(cache_key)
    if cached:
        return cached

    # MalwareBazaar requires Auth-Key (same as URLhaus/ThreatFox from abuse.ch)
    api_key = get_api_key('urlhaus')  # Uses same auth.abuse.ch key
    if not api_key:
        api_key = get_api_key('threatfox')
    if not api_key:
        return {'error': 'Auth-Key not configured (get from https://auth.abuse.ch/)', 'source': 'malwarebazaar'}

    api_url = "https://mb-api.abuse.ch/api/v1/"

    # Determine hash type
    if len(file_hash) == 64:
        hash_param = 'sha256_hash'
    elif len(file_hash) == 40:
        hash_param = 'sha1_hash'
    elif len(file_hash) == 32:
        hash_param = 'md5_hash'
    else:
        return {'error': 'Invalid hash format (use MD5, SHA1, or SHA256)', 'source': 'malwarebazaar'}

    data = urllib.parse.urlencode({
        'query': 'get_info',
        'hash': file_hash
    }).encode()

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Auth-Key': api_key,
        'User-Agent': 'ShieldTier-ThreatIntel/1.0'
    }

    response = make_request(api_url, headers=headers, method='POST', data=data)
    if response:
        if response.get('query_status') == 'ok':
            sample = response.get('data', [{}])[0] if response.get('data') else {}
            result = {
                'source': 'malwarebazaar',
                'found': True,
                'hash': file_hash,
                'sha256': sample.get('sha256_hash'),
                'sha1': sample.get('sha1_hash'),
                'md5': sample.get('md5_hash'),
                'fileName': sample.get('file_name'),
                'fileType': sample.get('file_type'),
                'fileTypeMime': sample.get('file_type_mime'),
                'fileSize': sample.get('file_size'),
                'signature': sample.get('signature'),
                'firstSeen': sample.get('first_seen'),
                'lastSeen': sample.get('last_seen'),
                'reporter': sample.get('reporter'),
                'tags': sample.get('tags', []),
                'malwareFamily': sample.get('signature'),
                'deliveryMethod': sample.get('delivery_method'),
                'intelligence': sample.get('intelligence', {}),
                'originCountry': sample.get('origin_country'),
                'imphash': sample.get('imphash'),
                'tlsh': sample.get('tlsh'),
                'ssdeep': sample.get('ssdeep'),
                'vendorIntel': {}
            }

            # Extract vendor intelligence (AV detections)
            vendor_intel = sample.get('vendor_intel', {})
            if vendor_intel:
                result['vendorIntel'] = {
                    vendor: info.get('verdict', info.get('detection', 'Unknown'))
                    for vendor, info in vendor_intel.items()
                    if isinstance(info, dict)
                }
                result['detectionCount'] = len([v for v in result['vendorIntel'].values()
                                                if v and v.lower() not in ('clean', 'unknown', 'n/a')])

            # Extract YARA matches
            yara_rules = sample.get('yara_rules', [])
            if yara_rules:
                result['yaraMatches'] = [
                    {'rule': rule.get('rule_name'), 'author': rule.get('author')}
                    for rule in yara_rules[:10]
                ]

            set_cached(cache_key, result)
            return result

        elif response.get('query_status') == 'hash_not_found':
            result = {
                'source': 'malwarebazaar',
                'found': False,
                'hash': file_hash,
                'status': 'clean',
                'message': 'Hash not found in MalwareBazaar database'
            }
            set_cached(cache_key, result)
            return result

        elif response.get('query_status') == 'illegal_hash':
            return {'error': 'Invalid hash format', 'source': 'malwarebazaar'}

    return {'error': 'No data returned', 'source': 'malwarebazaar'}


# =============================================================================
# ThreatFox (abuse.ch) - No API key required
# =============================================================================

def check_threatfox_ioc(ioc: str, ioc_type: str = 'ip:port') -> Dict:
    """Check IOC on ThreatFox"""
    # Replace : in ioc_type for safe cache key parsing
    safe_type = ioc_type.replace(':', '_')
    cache_key = f"threatfox:{safe_type}:{ioc}"
    cached = get_cached(cache_key)
    if cached:
        return cached

    if not is_service_enabled('threatfox'):
        return {'error': 'Service disabled', 'source': 'threatfox'}

    api_key = get_api_key('threatfox')
    if not api_key:
        return {'error': 'Auth-Key not configured (get free key at https://auth.abuse.ch/)', 'source': 'threatfox'}

    api_url = "https://threatfox-api.abuse.ch/api/v1/"
    data = json.dumps({'query': 'search_ioc', 'search_term': ioc}).encode()
    headers = {
        'Content-Type': 'application/json',
        'Auth-Key': api_key
    }

    response = make_request(api_url, headers=headers, method='POST', data=data)
    if response:
        if response.get('query_status') == 'ok':
            result = {
                'source': 'threatfox',
                'ioc': ioc,
                'found': True,
                'data': []
            }
            for entry in response.get('data', [])[:5]:
                result['data'].append({
                    'iocType': entry.get('ioc_type'),
                    'threatType': entry.get('threat_type'),
                    'malware': entry.get('malware'),
                    'malwarePrintable': entry.get('malware_printable'),
                    'confidence': entry.get('confidence_level'),
                    'firstSeen': entry.get('first_seen'),
                    'lastSeen': entry.get('last_seen'),
                    'reporter': entry.get('reporter'),
                    'tags': entry.get('tags', [])
                })
            set_cached(cache_key, result)
            return result
        elif response.get('query_status') == 'no_result':
            result = {'source': 'threatfox', 'ioc': ioc, 'found': False, 'status': 'clean'}
            set_cached(cache_key, result)
            return result

    return {'error': 'No data returned', 'source': 'threatfox'}


# =============================================================================
# IPQualityScore
# =============================================================================

def check_ipqualityscore(ip: str) -> Dict:
    """Check IP on IPQualityScore"""
    cache_key = f"ipqualityscore:ip:{ip}"
    cached = get_cached(cache_key)
    if cached:
        return cached

    api_key = get_api_key('ipqualityscore')
    if not api_key:
        return {'error': 'API key not configured', 'source': 'ipqualityscore'}

    if not check_rate_limit('ipqualityscore', 5000, 2592000):  # 5000/month
        return {'error': 'Rate limit exceeded', 'source': 'ipqualityscore'}

    url = f"https://ipqualityscore.com/api/json/ip/{api_key}/{ip}?strictness=1&allow_public_access_points=true"

    response = make_request(url)
    if response and response.get('success'):
        result = {
            'source': 'ipqualityscore',
            'ip': ip,
            'fraudScore': response.get('fraud_score', 0),
            'isProxy': response.get('proxy', False),
            'isVpn': response.get('vpn', False),
            'isTor': response.get('tor', False),
            'isBot': response.get('bot_status', False),
            'recentAbuse': response.get('recent_abuse', False),
            'isCrawler': response.get('is_crawler', False),
            'connectionType': response.get('connection_type'),
            'abuseVelocity': response.get('abuse_velocity'),
            'isp': response.get('ISP'),
            'organization': response.get('organization'),
            'country': response.get('country_code'),
            'city': response.get('city'),
        }
        set_cached(cache_key, result)
        return result

    return {'error': response.get('message', 'No data returned'), 'source': 'ipqualityscore'}


# =============================================================================
# AlienVault OTX
# =============================================================================

def check_alienvault_ip(ip: str) -> Dict:
    """Check IP on AlienVault OTX"""
    cache_key = f"alienvault:ip:{ip}"
    cached = get_cached(cache_key)
    if cached:
        return cached

    api_key = get_api_key('alienvault_otx')
    if not api_key:
        return {'error': 'API key not configured', 'source': 'alienvault_otx'}

    if not check_rate_limit('alienvault_otx', 10000, 3600):  # 10000/hour
        return {'error': 'Rate limit exceeded', 'source': 'alienvault_otx'}

    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {'X-OTX-API-KEY': api_key}

    response = make_request(url, headers)
    if response:
        result = {
            'source': 'alienvault_otx',
            'ip': ip,
            'reputation': response.get('reputation', 0),
            'pulseCount': response.get('pulse_info', {}).get('count', 0),
            'asn': response.get('asn'),
            'country': response.get('country_name'),
            'city': response.get('city'),
            'validation': response.get('validation', []),
            'pulses': []
        }
        for pulse in response.get('pulse_info', {}).get('pulses', [])[:5]:
            result['pulses'].append({
                'name': pulse.get('name'),
                'description': pulse.get('description', '')[:200],
                'created': pulse.get('created'),
                'tags': pulse.get('tags', [])
            })
        set_cached(cache_key, result)
        return result

    return {'error': 'No data returned', 'source': 'alienvault_otx'}


def check_alienvault_url(url_to_check: str) -> Dict:
    """Check URL on AlienVault OTX"""
    # Extract domain from URL
    try:
        parsed = urllib.parse.urlparse(url_to_check)
        domain = parsed.netloc or parsed.path.split('/')[0]
    except:
        return {'error': 'Invalid URL', 'source': 'alienvault_otx'}

    cache_key = f"alienvault:domain:{domain}"
    cached = get_cached(cache_key)
    if cached:
        return cached

    api_key = get_api_key('alienvault_otx')
    if not api_key:
        return {'error': 'API key not configured', 'source': 'alienvault_otx'}

    if not check_rate_limit('alienvault_otx', 10000, 3600):
        return {'error': 'Rate limit exceeded', 'source': 'alienvault_otx'}

    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    headers = {'X-OTX-API-KEY': api_key}

    response = make_request(url, headers)
    if response:
        result = {
            'source': 'alienvault_otx',
            'domain': domain,
            'url': url_to_check,
            'pulseCount': response.get('pulse_info', {}).get('count', 0),
            'validation': response.get('validation', []),
            'whois': response.get('whois'),
            'pulses': []
        }
        for pulse in response.get('pulse_info', {}).get('pulses', [])[:5]:
            result['pulses'].append({
                'name': pulse.get('name'),
                'description': pulse.get('description', '')[:200],
                'created': pulse.get('created'),
                'tags': pulse.get('tags', [])
            })
        set_cached(cache_key, result)
        return result

    return {'error': 'No data returned', 'source': 'alienvault_otx'}


def check_alienvault_hash(file_hash: str) -> Dict:
    """Check file hash on AlienVault OTX"""
    cache_key = f"alienvault:hash:{file_hash}"
    cached = get_cached(cache_key)
    if cached:
        return cached

    api_key = get_api_key('alienvault_otx')
    if not api_key:
        return {'error': 'API key not configured', 'source': 'alienvault_otx'}

    if not check_rate_limit('alienvault_otx', 10000, 3600):
        return {'error': 'Rate limit exceeded', 'source': 'alienvault_otx'}

    url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
    headers = {'X-OTX-API-KEY': api_key}

    response = make_request(url, headers)
    if response:
        result = {
            'source': 'alienvault_otx',
            'hash': file_hash,
            'pulseCount': response.get('pulse_info', {}).get('count', 0),
            'fileType': response.get('type_description'),
            'fileSize': response.get('size'),
            'pulses': []
        }
        for pulse in response.get('pulse_info', {}).get('pulses', [])[:5]:
            result['pulses'].append({
                'name': pulse.get('name'),
                'description': pulse.get('description', '')[:200],
                'created': pulse.get('created'),
                'tags': pulse.get('tags', [])
            })
        set_cached(cache_key, result)
        return result

    return {'error': 'No data returned', 'source': 'alienvault_otx'}


# =============================================================================
# GreyNoise
# =============================================================================

def check_greynoise(ip: str) -> Dict:
    """Check IP on GreyNoise"""
    cache_key = f"greynoise:ip:{ip}"
    cached = get_cached(cache_key)
    if cached:
        return cached

    api_key = get_api_key('greynoise')

    # GreyNoise has a free community API endpoint
    if api_key:
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {'key': api_key}
    else:
        # Try community endpoint without key
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {}

    if not check_rate_limit('greynoise', 100, 86400):  # Limited free tier
        return {'error': 'Rate limit exceeded', 'source': 'greynoise'}

    response = make_request(url, headers)
    if response:
        result = {
            'source': 'greynoise',
            'ip': ip,
            'noise': response.get('noise', False),
            'riot': response.get('riot', False),  # Rule It Out (benign)
            'classification': response.get('classification'),
            'name': response.get('name'),
            'lastSeen': response.get('last_seen'),
            'link': response.get('link'),
            'message': response.get('message'),
        }
        set_cached(cache_key, result)
        return result

    return {'error': 'No data returned', 'source': 'greynoise'}


# =============================================================================
# Shodan
# =============================================================================

def check_shodan(ip: str) -> Dict:
    """Check IP on Shodan"""
    cache_key = f"shodan:ip:{ip}"
    cached = get_cached(cache_key)
    if cached:
        return cached

    api_key = get_api_key('shodan')
    if not api_key:
        return {'error': 'API key not configured', 'source': 'shodan'}

    if not check_rate_limit('shodan', 100, 86400):  # Limited free tier
        return {'error': 'Rate limit exceeded', 'source': 'shodan'}

    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"

    response = make_request(url)
    if response:
        result = {
            'source': 'shodan',
            'ip': ip,
            'hostnames': response.get('hostnames', []),
            'country': response.get('country_name'),
            'city': response.get('city'),
            'org': response.get('org'),
            'isp': response.get('isp'),
            'asn': response.get('asn'),
            'ports': response.get('ports', []),
            'vulns': response.get('vulns', []),
            'tags': response.get('tags', []),
            'lastUpdate': response.get('last_update'),
            'services': []
        }
        for data in response.get('data', [])[:10]:
            result['services'].append({
                'port': data.get('port'),
                'transport': data.get('transport'),
                'product': data.get('product'),
                'version': data.get('version'),
                'cpe': data.get('cpe', [])
            })
        set_cached(cache_key, result)
        return result

    return {'error': 'No data returned', 'source': 'shodan'}


# =============================================================================
# URLScan.io
# =============================================================================

def check_urlscanio(url_to_check: str) -> Dict:
    """Check URL/domain on URLScan.io search API"""
    from urllib.parse import urlparse as _urlparse
    parsed = _urlparse(url_to_check)
    domain = parsed.hostname or url_to_check

    cache_key = f"urlscanio:domain:{domain}"
    cached = get_cached(cache_key)
    if cached:
        return cached

    if not check_rate_limit('urlscanio', 2, 60):  # 2/min
        return {'error': 'Rate limit exceeded', 'source': 'urlscanio'}

    api_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5"
    headers = {'Accept': 'application/json'}

    # Optional API key for higher limits
    api_key = get_api_key('urlscanio')
    if api_key:
        headers['API-Key'] = api_key

    response = make_request(api_url, headers=headers, timeout=15)
    if response and 'results' in response:
        total_scans = response.get('total', 0)
        scan_results = response.get('results', [])

        malicious_count = 0
        verdicts = []
        page_info = {}

        for scan in scan_results[:5]:
            verdict = scan.get('verdicts', {}).get('overall', {})
            if verdict.get('malicious'):
                malicious_count += 1
            if verdict.get('categories'):
                verdicts.extend(verdict['categories'])

            # Get page info from most recent scan
            if not page_info and scan.get('page'):
                page_info = {
                    'server': scan['page'].get('server', ''),
                    'ip': scan['page'].get('ip', ''),
                    'country': scan['page'].get('country', ''),
                    'title': scan['page'].get('title', '')[:100],
                    'statusCode': scan['page'].get('status', 0)
                }

        result = {
            'source': 'urlscanio',
            'domain': domain,
            'totalScans': total_scans,
            'maliciousScans': malicious_count,
            'isMalicious': malicious_count > 0,
            'verdicts': list(set(verdicts))[:10],
            'pageInfo': page_info
        }
        set_cached(cache_key, result)
        return result

    return {'error': 'No data returned', 'source': 'urlscanio'}


# =============================================================================
# BGPView (IP ASN/Prefix lookup)
# =============================================================================

def check_bgpview(ip: str) -> Dict:
    """Check IP on BGPView for ASN, prefix, and hosting/CDN detection"""
    cache_key = f"bgpview:ip:{ip}"
    cached = get_cached(cache_key)
    if cached:
        return cached

    if not check_rate_limit('bgpview', 30, 60):  # 30/min
        return {'error': 'Rate limit exceeded', 'source': 'bgpview'}

    api_url = f"https://api.bgpview.io/ip/{ip}"
    headers = {'Accept': 'application/json'}

    response = make_request(api_url, headers=headers, timeout=10)
    if response and response.get('status') == 'ok' and response.get('data'):
        data = response['data']
        prefixes = data.get('rir_allocation', {})
        ptr = data.get('ptr_record')

        # Get primary ASN info from prefixes
        asn_info = {}
        prefix = ''
        if data.get('prefixes') and len(data['prefixes']) > 0:
            first_prefix = data['prefixes'][0]
            prefix = first_prefix.get('prefix', '')
            asn_data = first_prefix.get('asn', {})
            asn_info = {
                'asn': asn_data.get('asn', 0),
                'name': asn_data.get('name', ''),
                'description': asn_data.get('description', ''),
                'country': asn_data.get('country_code', '')
            }

        # Detect hosting/CDN from ASN description keywords
        hosting_keywords = ['hosting', 'server', 'vps', 'cloud', 'data center', 'datacenter',
                           'hetzner', 'ovh', 'digitalocean', 'linode', 'vultr', 'contabo',
                           'hostinger', 'godaddy', 'bluehost', 'ionos', 'scaleway', 'choopa',
                           'amazon', 'aws', 'azure', 'google cloud', 'gcp', 'oracle cloud',
                           'alibaba cloud', 'tencent cloud', 'rackspace']
        cdn_keywords = ['cloudflare', 'akamai', 'fastly', 'cdn', 'content delivery',
                       'incapsula', 'imperva', 'stackpath', 'limelight', 'edgecast',
                       'bunnycdn', 'keycdn', 'cloudfront']

        asn_desc = (asn_info.get('description', '') + ' ' + asn_info.get('name', '')).lower()
        is_hosting = any(kw in asn_desc for kw in hosting_keywords)
        is_cdn = any(kw in asn_desc for kw in cdn_keywords)

        result = {
            'source': 'bgpview',
            'ip': ip,
            'prefix': prefix,
            'asn': asn_info,
            'rir': prefixes.get('rir_name', ''),
            'ptr': ptr,
            'isHosting': is_hosting,
            'isCdn': is_cdn
        }
        set_cached(cache_key, result)
        return result

    return {'error': 'No data returned', 'source': 'bgpview'}


# =============================================================================
# VirusTotal Imphash Cluster Search
# =============================================================================

def check_virustotal_imphash(imphash: str) -> Dict:
    """Search VirusTotal for related samples by import hash"""
    if not imphash:
        return {'error': 'No imphash provided', 'source': 'virustotal_imphash'}

    cache_key = f"vt:imphash:{imphash}"
    cached = get_cached(cache_key)
    if cached:
        return cached

    api_key = get_api_key('virustotal')
    if not api_key:
        return {'error': 'API key not configured', 'source': 'virustotal_imphash'}

    if not check_rate_limit('virustotal', 4, 60):  # 4/min
        return {'error': 'Rate limit exceeded', 'source': 'virustotal_imphash'}

    url = f"https://www.virustotal.com/api/v3/search?query=imphash:{imphash}&limit=10"
    headers = {'x-apikey': api_key}

    response = make_request(url, headers=headers, timeout=15)
    if response and 'data' in response:
        samples = response.get('data', [])
        total_related = len(samples)
        malicious_related = 0
        related_samples = []

        for sample in samples[:10]:
            attrs = sample.get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            mal_count = stats.get('malicious', 0)
            if mal_count > 3:
                malicious_related += 1
            related_samples.append({
                'sha256': sample.get('id', ''),
                'name': attrs.get('meaningful_name', attrs.get('type_description', 'Unknown')),
                'malicious': mal_count,
                'total': sum(stats.values()) if stats else 0,
                'type': attrs.get('type_description', '')
            })

        cluster_risk = 'high' if malicious_related >= 3 else 'medium' if malicious_related >= 1 else 'low'

        result = {
            'source': 'virustotal_imphash',
            'imphash': imphash,
            'totalRelated': total_related,
            'maliciousRelated': malicious_related,
            'relatedSamples': related_samples,
            'clusterRisk': cluster_risk
        }
        set_cached(cache_key, result)
        return result

    return {'error': 'No data returned', 'source': 'virustotal_imphash'}


# =============================================================================
# Malpedia Malware Family Lookup
# =============================================================================

def check_malpedia_family(family_name: str) -> Dict:
    """Look up malware family details on Malpedia"""
    if not family_name:
        return {'error': 'No family name provided', 'source': 'malpedia'}

    cache_key = f"malpedia:family:{family_name.lower()}"
    cached = get_cached(cache_key)
    if cached:
        return cached

    api_key = get_api_key('malpedia')
    if not api_key:
        return {'error': 'API key not configured', 'source': 'malpedia'}

    if not check_rate_limit('malpedia', 10, 60):  # 10/min
        return {'error': 'Rate limit exceeded', 'source': 'malpedia'}

    # Normalize family name (Malpedia uses underscores)
    normalized = family_name.lower().replace(' ', '_').replace('-', '_')
    url = f"https://malpedia.caad.fkie.fraunhofer.de/api/get/family/{normalized}"
    headers = {'Authorization': f'apitoken {api_key}'}

    response = make_request(url, headers=headers, timeout=15)
    if response and not isinstance(response, list):
        result = {
            'source': 'malpedia',
            'family': family_name,
            'description': response.get('description', '')[:500],
            'altNames': response.get('alt_names', [])[:10],
            'urls': response.get('urls', [])[:5],
            'attribution': [],
            'mitreTechniques': []
        }

        # Extract actor attribution
        for actor in response.get('attribution', [])[:5]:
            if isinstance(actor, str):
                result['attribution'].append(actor)
            elif isinstance(actor, dict):
                result['attribution'].append(actor.get('actor', actor.get('name', 'Unknown')))

        # Extract MITRE techniques
        for technique in response.get('techniques', [])[:10]:
            if isinstance(technique, str):
                result['mitreTechniques'].append(technique)
            elif isinstance(technique, dict):
                result['mitreTechniques'].append(technique.get('id', ''))

        set_cached(cache_key, result)
        return result

    return {'error': 'No data returned', 'source': 'malpedia'}


# =============================================================================
# MISP Threat Intelligence Platform
# =============================================================================

def _misp_request(endpoint: str, data: Dict = None, method: str = 'POST') -> Optional[Dict]:
    """Make a request to the local MISP instance."""
    config = load_config()
    misp_config = config.get('misp', {})
    api_key = misp_config.get('api_key', '')
    base_url = misp_config.get('base_url', '').rstrip('/')
    verify_ssl = misp_config.get('verify_ssl', False)

    if not api_key or not base_url:
        return None

    url = f"{base_url}{endpoint}"
    headers = {
        'Authorization': api_key,
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }

    try:
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, headers=headers, method=method)

        import ssl
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        print(f"[MISP] Request error ({endpoint}): {e}")
        return None


def check_misp_ip(ip: str) -> Dict:
    """Check IP address against local MISP instance."""
    cache_key = f"misp:ip:{ip}"
    cached = get_cached(cache_key)
    if cached:
        return cached

    if not is_service_enabled('misp'):
        return {'error': 'MISP not enabled', 'source': 'misp'}

    if not check_rate_limit('misp', 1000, 3600):
        return {'error': 'Rate limit exceeded', 'source': 'misp'}

    # Search for IP in both ip-src and ip-dst attribute types
    response = _misp_request('/attributes/restSearch', {
        'type': ['ip-src', 'ip-dst', 'ip-dst|port', 'ip-src|port'],
        'value': ip,
        'limit': 50,
        'returnFormat': 'json',
    })

    if not response or 'response' not in response:
        return {'error': 'No data returned', 'source': 'misp'}

    attributes = response.get('response', {}).get('Attribute', [])

    # Collect unique event IDs and details
    event_ids = set()
    events_detail = []
    for attr in attributes:
        eid = attr.get('event_id')
        if eid and eid not in event_ids:
            event_ids.add(eid)
            events_detail.append({
                'eventId': eid,
                'category': attr.get('category', ''),
                'type': attr.get('type', ''),
                'comment': (attr.get('comment') or '')[:200],
                'timestamp': attr.get('timestamp', ''),
            })

    result = {
        'source': 'misp',
        'ip': ip,
        'found': len(event_ids) > 0,
        'attributeCount': len(attributes),
        'eventCount': len(event_ids),
        'events': events_detail[:10],
    }

    set_cached(cache_key, result)
    return result


def check_misp_url(url_to_check: str) -> Dict:
    """Check URL/domain against local MISP instance."""
    from urllib.parse import urlparse as _urlparse

    cache_key = f"misp:url:{hashlib.md5(url_to_check.encode()).hexdigest()}"
    cached = get_cached(cache_key)
    if cached:
        return cached

    if not is_service_enabled('misp'):
        return {'error': 'MISP not enabled', 'source': 'misp'}

    if not check_rate_limit('misp', 1000, 3600):
        return {'error': 'Rate limit exceeded', 'source': 'misp'}

    # Extract domain for additional search
    try:
        domain = _urlparse(url_to_check).netloc.lower()
        if ':' in domain:
            domain = domain.split(':')[0]
    except Exception:
        domain = None

    # Search URL and domain
    search_types = ['url', 'link']
    search_value = url_to_check

    response = _misp_request('/attributes/restSearch', {
        'type': search_types,
        'value': f"%{search_value}%",
        'limit': 50,
        'returnFormat': 'json',
    })

    attributes = []
    if response and 'response' in response:
        attributes = response.get('response', {}).get('Attribute', [])

    # Also search by domain if available
    if domain:
        domain_resp = _misp_request('/attributes/restSearch', {
            'type': ['domain', 'hostname', 'domain|ip'],
            'value': domain,
            'limit': 50,
            'returnFormat': 'json',
        })
        if domain_resp and 'response' in domain_resp:
            attributes += domain_resp.get('response', {}).get('Attribute', [])

    # Deduplicate by attribute ID
    seen_ids = set()
    unique_attrs = []
    for attr in attributes:
        aid = attr.get('id')
        if aid not in seen_ids:
            seen_ids.add(aid)
            unique_attrs.append(attr)

    event_ids = set()
    events_detail = []
    for attr in unique_attrs:
        eid = attr.get('event_id')
        if eid and eid not in event_ids:
            event_ids.add(eid)
            events_detail.append({
                'eventId': eid,
                'category': attr.get('category', ''),
                'type': attr.get('type', ''),
                'matchedValue': (attr.get('value') or '')[:120],
                'comment': (attr.get('comment') or '')[:200],
                'timestamp': attr.get('timestamp', ''),
            })

    result = {
        'source': 'misp',
        'url': url_to_check,
        'domain': domain,
        'found': len(event_ids) > 0,
        'attributeCount': len(unique_attrs),
        'eventCount': len(event_ids),
        'events': events_detail[:10],
    }

    set_cached(cache_key, result)
    return result


def check_misp_hash(file_hash: str) -> Dict:
    """Check file hash against local MISP instance."""
    cache_key = f"misp:hash:{file_hash}"
    cached = get_cached(cache_key)
    if cached:
        return cached

    if not is_service_enabled('misp'):
        return {'error': 'MISP not enabled', 'source': 'misp'}

    if not check_rate_limit('misp', 1000, 3600):
        return {'error': 'Rate limit exceeded', 'source': 'misp'}

    # Determine hash type
    hash_len = len(file_hash)
    if hash_len == 32:
        hash_types = ['md5', 'filename|md5']
    elif hash_len == 40:
        hash_types = ['sha1', 'filename|sha1']
    elif hash_len == 64:
        hash_types = ['sha256', 'filename|sha256']
    else:
        hash_types = ['md5', 'sha1', 'sha256']

    response = _misp_request('/attributes/restSearch', {
        'type': hash_types,
        'value': file_hash,
        'limit': 50,
        'returnFormat': 'json',
    })

    if not response or 'response' not in response:
        return {'error': 'No data returned', 'source': 'misp'}

    attributes = response.get('response', {}).get('Attribute', [])

    event_ids = set()
    events_detail = []
    malware_names = set()
    for attr in attributes:
        eid = attr.get('event_id')
        if eid and eid not in event_ids:
            event_ids.add(eid)
            comment = attr.get('comment') or ''
            if comment:
                malware_names.add(comment[:100])
            events_detail.append({
                'eventId': eid,
                'category': attr.get('category', ''),
                'type': attr.get('type', ''),
                'comment': comment[:200],
                'timestamp': attr.get('timestamp', ''),
            })

    result = {
        'source': 'misp',
        'hash': file_hash,
        'hashType': 'md5' if hash_len == 32 else 'sha1' if hash_len == 40 else 'sha256' if hash_len == 64 else 'unknown',
        'found': len(event_ids) > 0,
        'attributeCount': len(attributes),
        'eventCount': len(event_ids),
        'events': events_detail[:10],
        'malwareNames': list(malware_names)[:5],
    }

    set_cached(cache_key, result)
    return result


# =============================================================================
# Aggregated Investigation Functions
# =============================================================================

def investigate_ip(ip: str) -> Dict:
    """Investigate an IP address across all enabled services"""
    results = {
        'ip': ip,
        'investigatedAt': datetime.now().isoformat(),
        'sources': {},
        'summary': {
            'isMalicious': False,
            'totalSources': 0,
            'maliciousSources': 0,
            'riskScore': 0,
            'findings': []
        }
    }

    # Check each service
    services = [
        ('abuseipdb', check_abuseipdb),
        ('virustotal', check_virustotal_ip),
        ('ipqualityscore', check_ipqualityscore),
        ('alienvault_otx', check_alienvault_ip),
        ('greynoise', check_greynoise),
        ('shodan', check_shodan),
        ('bgpview', check_bgpview),
        ('threatfox', lambda ip: check_threatfox_ioc(ip, 'ip:port')),
        ('misp', check_misp_ip),
    ]

    for service_name, check_func in services:
        if is_service_enabled(service_name) or service_name in ['urlhaus', 'threatfox', 'bgpview']:
            try:
                result = check_func(ip)
                if 'error' not in result:
                    results['sources'][service_name] = result
                    results['summary']['totalSources'] += 1

                    # Analyze results
                    if service_name == 'abuseipdb' and result.get('abuseScore', 0) > 50:
                        results['summary']['maliciousSources'] += 1
                        results['summary']['findings'].append(f"AbuseIPDB: Score {result.get('abuseScore')}%")
                    elif service_name == 'virustotal' and result.get('malicious', 0) > 0:
                        results['summary']['maliciousSources'] += 1
                        results['summary']['findings'].append(f"VirusTotal: {result.get('malicious')} detections")
                    elif service_name == 'ipqualityscore' and result.get('fraudScore', 0) > 75:
                        results['summary']['maliciousSources'] += 1
                        results['summary']['findings'].append(f"IPQualityScore: Fraud score {result.get('fraudScore')}")
                    elif service_name == 'alienvault_otx' and result.get('pulseCount', 0) > 0:
                        pulse_count = result.get('pulseCount', 0)
                        results['summary']['findings'].append(f"AlienVault: {pulse_count} threat pulses")
                        if pulse_count >= 3:
                            results['summary']['maliciousSources'] += 1
                        results['summary']['riskScore'] = max(
                            results['summary']['riskScore'],
                            min(80, 20 + (pulse_count * 15))
                        )
                    elif service_name == 'greynoise' and result.get('noise'):
                        results['summary']['findings'].append(f"GreyNoise: Known scanner ({result.get('classification')})")
                    elif service_name == 'threatfox' and result.get('found'):
                        results['summary']['maliciousSources'] += 1
                        results['summary']['findings'].append("ThreatFox: Known malicious IOC")
                    elif service_name == 'misp' and result.get('found'):
                        results['summary']['maliciousSources'] += 1
                        results['summary']['findings'].append(f"MISP: Found in {result.get('eventCount')} threat intel events")
            except Exception as e:
                results['sources'][service_name] = {'error': str(e)}

    # Calculate overall risk score using consensus-based approach
    if results['summary']['totalSources'] > 0:
        sources = results['sources']

        # Count clean vs suspicious indicators
        clean_indicators = 0
        threat_indicators = 0
        threat_score = 0

        # AbuseIPDB - most reliable for actual abuse reports
        if 'abuseipdb' in sources:
            abuse_data = sources['abuseipdb']
            abuse_score = abuse_data.get('abuseScore', 0)
            total_reports = abuse_data.get('totalReports', 0)
            if abuse_score > 50 or total_reports > 10:
                threat_indicators += 2  # Strong indicator
                threat_score += abuse_score
            elif abuse_score == 0 and total_reports == 0:
                clean_indicators += 2  # Strong clean signal

        # VirusTotal - very reliable
        if 'virustotal' in sources:
            vt_data = sources['virustotal']
            vt_malicious = vt_data.get('malicious', 0)
            vt_harmless = vt_data.get('harmless', 0)
            if vt_malicious > 0:
                threat_indicators += 2
                threat_score += min(80, vt_malicious * 10)
            elif vt_harmless > 50 and vt_malicious == 0:
                clean_indicators += 2

        # ThreatFox - known malware IOCs
        if 'threatfox' in sources:
            if sources['threatfox'].get('found'):
                threat_indicators += 3  # Very strong indicator
                threat_score += 80
            else:
                clean_indicators += 1

        # AlienVault - threat pulses
        if 'alienvault_otx' in sources:
            pulse_count = sources['alienvault_otx'].get('pulseCount', 0)
            if pulse_count > 5:
                threat_indicators += 1
                threat_score += min(40, pulse_count * 5)
            elif pulse_count == 0:
                clean_indicators += 1

        # IPQualityScore - only trust if corroborated by other sources
        # Hosting providers often get flagged as proxy/VPN incorrectly
        if 'ipqualityscore' in sources:
            ipqs = sources['ipqualityscore']
            fraud_score = ipqs.get('fraudScore', 0)
            is_hosting = 'hosting' in str(ipqs.get('isp', '')).lower() or \
                        'hosting' in str(ipqs.get('organization', '')).lower() or \
                        ipqs.get('connectionType', '') in ['Data Center', 'Corporate', 'Premium required.']

            # Only count as threat if: high fraud score AND corroborated by other source
            # OR very high fraud score with recent abuse flag
            if fraud_score > 85 and ipqs.get('recentAbuse') and threat_indicators > 0:
                threat_indicators += 1
                threat_score += fraud_score // 2
            elif fraud_score > 75 and not is_hosting and threat_indicators > 0:
                threat_indicators += 1
                threat_score += fraud_score // 3
            elif fraud_score < 30:
                clean_indicators += 1

        # GreyNoise - scanner detection (informational, not necessarily malicious)
        if 'greynoise' in sources:
            gn = sources['greynoise']
            if gn.get('noise') and gn.get('classification') == 'malicious':
                threat_indicators += 1
                threat_score += 30

        # MISP - local threat intelligence repository
        if 'misp' in sources:
            misp_data = sources['misp']
            event_count = misp_data.get('eventCount', 0)
            if event_count >= 5:
                threat_indicators += 2  # Strong signal — multiple MISP events
                threat_score += min(50, event_count * 5)
            elif event_count > 0:
                threat_indicators += 1
                threat_score += min(30, event_count * 8)
            elif not misp_data.get('found'):
                clean_indicators += 1

        # Consensus-based final score calculation
        if threat_indicators > 0 and clean_indicators == 0:
            # All sources agree it's bad
            results['summary']['isMalicious'] = True
            results['summary']['riskScore'] = min(100, threat_score // max(1, threat_indicators))
        elif threat_indicators >= 2 and threat_indicators > clean_indicators:
            # Multiple sources flag it, outweighs clean signals
            results['summary']['isMalicious'] = True
            results['summary']['riskScore'] = min(90, threat_score // threat_indicators)
        elif threat_indicators == 1 and clean_indicators >= 2:
            # Only 1 source flags it, multiple say clean - likely false positive
            results['summary']['isMalicious'] = False
            results['summary']['riskScore'] = min(30, threat_score // 4)
            results['summary']['findings'].append("Note: Single-source detection with multiple clean signals - possible false positive")
        elif threat_indicators == 1:
            # Single flag, no strong clean signals
            results['summary']['isMalicious'] = False
            results['summary']['riskScore'] = min(50, threat_score // 2)
        else:
            # Clean across all sources
            results['summary']['isMalicious'] = False
            results['summary']['riskScore'] = 0

    # Generate AI-style verdict summary
    results['summary']['verdict'] = _generate_ip_verdict(ip, results)

    # Store in IOC table for SIEM export
    store_ip_ioc(ip, results)

    return results


def _generate_ip_verdict(ip: str, results: Dict) -> str:
    """Generate a human-readable verdict summary for an IP address"""
    summary = results.get('summary', {})
    sources = results.get('sources', {})

    risk_score = summary.get('riskScore', 0)
    is_malicious = summary.get('isMalicious', False)
    findings = summary.get('findings', [])

    # Gather context from sources
    org = None
    isp = None
    country = None
    asn = None
    is_vpn = False
    is_proxy = False
    is_tor = False
    is_datacenter = False
    is_scanner = False
    abuse_score = 0
    vt_detections = 0

    # Extract data from AbuseIPDB
    if 'abuseipdb' in sources:
        abuseipdb = sources['abuseipdb']
        isp = abuseipdb.get('isp')
        country = abuseipdb.get('country')
        abuse_score = abuseipdb.get('abuseScore', 0)
        is_tor = abuseipdb.get('isTor', False)

    # Extract data from IPQualityScore
    if 'ipqualityscore' in sources:
        ipqs = sources['ipqualityscore']
        org = org or ipqs.get('organization')
        isp = isp or ipqs.get('isp')
        country = country or ipqs.get('country')
        is_vpn = ipqs.get('vpn', False)
        is_proxy = ipqs.get('proxy', False)
        is_tor = is_tor or ipqs.get('tor', False)

    # Extract data from Shodan
    if 'shodan' in sources:
        shodan = sources['shodan']
        org = org or shodan.get('org')
        isp = isp or shodan.get('isp')
        asn = shodan.get('asn')

    # Extract from VirusTotal
    if 'virustotal' in sources:
        vt = sources['virustotal']
        vt_detections = vt.get('malicious', 0)
        org = org or vt.get('owner')
        asn = asn or vt.get('asn')

    # Extract from GreyNoise
    if 'greynoise' in sources:
        gn = sources['greynoise']
        is_scanner = gn.get('noise', False)
        org = org or gn.get('name')

    # Build verdict
    parts = []

    # Start with risk assessment
    if risk_score >= 80:
        parts.append(f"HIGH RISK ({risk_score}/100)")
    elif risk_score >= 50:
        parts.append(f"MODERATE RISK ({risk_score}/100)")
    elif risk_score >= 20:
        parts.append(f"LOW RISK ({risk_score}/100)")
    else:
        parts.append(f"CLEAN ({risk_score}/100)")

    # Add identity info
    identity_parts = []
    if org:
        identity_parts.append(org)
    elif isp:
        identity_parts.append(isp)
    if country:
        identity_parts.append(country)

    if identity_parts:
        parts.append(f"This IP belongs to {', '.join(identity_parts)}.")

    # Add threat context
    threats = []
    if is_malicious:
        if vt_detections > 0:
            threats.append(f"flagged by {vt_detections} security vendors")
        if abuse_score > 50:
            threats.append(f"abuse confidence {abuse_score}%")

    if is_tor:
        threats.append("Tor exit node")
    if is_vpn:
        threats.append("VPN/anonymizer")
    if is_proxy:
        threats.append("known proxy")
    if is_scanner:
        threats.append("internet scanner")

    if threats:
        parts.append(f"Identified as: {', '.join(threats)}.")
    elif not is_malicious:
        # Positive verdict for clean IPs
        if org and any(safe in org.lower() for safe in ['google', 'cloudflare', 'amazon', 'microsoft', 'akamai']):
            parts.append("Belongs to a major trusted cloud/CDN provider.")
        elif risk_score == 0:
            parts.append("No malicious activity detected across all sources.")

    # Add recommendation
    if risk_score >= 70:
        parts.append("RECOMMENDATION: Block this IP immediately.")
    elif risk_score >= 40:
        parts.append("RECOMMENDATION: Monitor traffic from this IP closely.")
    elif is_vpn or is_proxy or is_tor:
        parts.append("RECOMMENDATION: Consider blocking anonymized traffic based on your security policy.")

    return " ".join(parts)


# =============================================================================
# DNS Intelligence Functions
# =============================================================================

def lookup_dns_records(domain: str) -> Dict:
    """Comprehensive DNS lookup for a domain"""
    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        return {'error': 'dnspython not installed'}

    results = {
        'domain': domain,
        'records': {},
        'emailSecurity': {},
        'blocklists': [],
        'timestamp': datetime.now().isoformat()
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    # Standard DNS records
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            records = []
            for rdata in answers:
                if record_type == 'MX':
                    records.append({
                        'priority': rdata.preference,
                        'host': str(rdata.exchange).rstrip('.')
                    })
                elif record_type == 'SOA':
                    records.append({
                        'mname': str(rdata.mname).rstrip('.'),
                        'rname': str(rdata.rname).rstrip('.'),
                        'serial': rdata.serial,
                        'refresh': rdata.refresh,
                        'retry': rdata.retry,
                        'expire': rdata.expire,
                        'minimum': rdata.minimum
                    })
                else:
                    records.append(str(rdata).strip('"'))
            results['records'][record_type] = records
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            results['records']['error'] = 'Domain does not exist (NXDOMAIN)'
            break
        except dns.exception.Timeout:
            pass
        except Exception as e:
            pass

    # Extract email security records from TXT
    txt_records = results['records'].get('TXT', [])
    for txt in txt_records:
        txt_lower = txt.lower()
        if txt_lower.startswith('v=spf1'):
            results['emailSecurity']['spf'] = {
                'record': txt,
                'valid': True,
                'details': _parse_spf(txt)
            }
        elif '_dmarc' in domain.lower() or txt_lower.startswith('v=dmarc1'):
            results['emailSecurity']['dmarc'] = {
                'record': txt,
                'valid': True,
                'details': _parse_dmarc(txt)
            }

    # Lookup DMARC specifically
    try:
        dmarc_answers = resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for rdata in dmarc_answers:
            txt = str(rdata).strip('"')
            if txt.lower().startswith('v=dmarc1'):
                results['emailSecurity']['dmarc'] = {
                    'record': txt,
                    'valid': True,
                    'details': _parse_dmarc(txt)
                }
                break
    except:
        results['emailSecurity']['dmarc'] = {'record': None, 'valid': False, 'details': 'No DMARC record found'}

    # Try common DKIM selectors
    dkim_selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail', 'dkim', 's1', 's2']
    dkim_found = []
    for selector in dkim_selectors:
        try:
            dkim_answers = resolver.resolve(f'{selector}._domainkey.{domain}', 'TXT')
            for rdata in dkim_answers:
                txt = str(rdata).strip('"')
                if 'v=dkim1' in txt.lower() or 'p=' in txt:
                    dkim_found.append({
                        'selector': selector,
                        'record': txt[:100] + '...' if len(txt) > 100 else txt,
                        'valid': True
                    })
                    break
        except:
            pass

    if dkim_found:
        results['emailSecurity']['dkim'] = dkim_found
    else:
        results['emailSecurity']['dkim'] = {'found': False, 'selectorsChecked': dkim_selectors}

    # Check DNSBL blocklists
    results['blocklists'] = check_domain_blocklists(domain)

    return results


def _parse_spf(spf_record: str) -> Dict:
    """Parse SPF record details"""
    details = {
        'mechanisms': [],
        'includes': [],
        'all': 'neutral'
    }

    parts = spf_record.split()
    for part in parts:
        part_lower = part.lower()
        if part_lower.startswith('include:'):
            details['includes'].append(part[8:])
        elif part_lower.startswith('a:') or part_lower.startswith('mx:') or part_lower.startswith('ip4:') or part_lower.startswith('ip6:'):
            details['mechanisms'].append(part)
        elif part_lower in ['+all', '-all', '~all', '?all']:
            all_map = {'+all': 'pass', '-all': 'fail', '~all': 'softfail', '?all': 'neutral'}
            details['all'] = all_map.get(part_lower, 'unknown')

    return details


def _parse_dmarc(dmarc_record: str) -> Dict:
    """Parse DMARC record details"""
    details = {
        'policy': 'none',
        'subdomain_policy': None,
        'percent': 100,
        'rua': None,
        'ruf': None,
        'adkim': 'relaxed',
        'aspf': 'relaxed'
    }

    parts = dmarc_record.split(';')
    for part in parts:
        part = part.strip()
        if '=' in part:
            key, value = part.split('=', 1)
            key = key.strip().lower()
            value = value.strip()

            if key == 'p':
                details['policy'] = value
            elif key == 'sp':
                details['subdomain_policy'] = value
            elif key == 'pct':
                try:
                    details['percent'] = int(value)
                except:
                    pass
            elif key == 'rua':
                details['rua'] = value
            elif key == 'ruf':
                details['ruf'] = value
            elif key == 'adkim':
                details['adkim'] = 'strict' if value.lower() == 's' else 'relaxed'
            elif key == 'aspf':
                details['aspf'] = 'strict' if value.lower() == 's' else 'relaxed'

    return details


def check_domain_blocklists(domain: str) -> List[Dict]:
    """Check domain against DNS-based blocklists"""
    try:
        import dns.resolver
    except ImportError:
        return []

    blocklists = [
        {'name': 'Spamhaus DBL', 'zone': 'dbl.spamhaus.org', 'type': 'spam'},
        {'name': 'SURBL', 'zone': 'multi.surbl.org', 'type': 'spam'},
        {'name': 'URIBL', 'zone': 'multi.uribl.com', 'type': 'spam'},
        {'name': 'Spamhaus ZEN', 'zone': 'zen.spamhaus.org', 'type': 'spam'},
    ]

    results = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    for bl in blocklists:
        try:
            query = f"{domain}.{bl['zone']}"
            answers = resolver.resolve(query, 'A')
            # If we get an answer, domain is listed
            for rdata in answers:
                results.append({
                    'blocklist': bl['name'],
                    'listed': True,
                    'type': bl['type'],
                    'response': str(rdata)
                })
                break
        except dns.resolver.NXDOMAIN:
            # Not listed - this is good
            results.append({
                'blocklist': bl['name'],
                'listed': False,
                'type': bl['type']
            })
        except:
            # Timeout or error - skip
            pass

    return results


def lookup_whois(domain: str) -> Dict:
    """Lookup WHOIS information for a domain"""
    try:
        import whois
    except ImportError:
        return {'error': 'python-whois not installed'}

    try:
        w = whois.whois(domain)

        # Handle date serialization
        def serialize_date(d):
            if d is None:
                return None
            if isinstance(d, list):
                return serialize_date(d[0]) if d else None
            if hasattr(d, 'isoformat'):
                return d.isoformat()
            return str(d)

        # Handle list fields
        def get_first(val):
            if isinstance(val, list):
                return val[0] if val else None
            return val

        result = {
            'registrar': get_first(w.registrar),
            'creationDate': serialize_date(w.creation_date),
            'expirationDate': serialize_date(w.expiration_date),
            'updatedDate': serialize_date(w.updated_date),
            'nameServers': w.name_servers if isinstance(w.name_servers, list) else [w.name_servers] if w.name_servers else [],
            'status': w.status if isinstance(w.status, list) else [w.status] if w.status else [],
            'dnssec': w.dnssec if hasattr(w, 'dnssec') else None,
            'org': get_first(w.org) if hasattr(w, 'org') else None,
            'country': get_first(w.country) if hasattr(w, 'country') else None,
        }

        # Calculate domain age
        if result['creationDate']:
            try:
                from datetime import datetime
                if isinstance(result['creationDate'], str):
                    created = datetime.fromisoformat(result['creationDate'].replace('Z', '+00:00'))
                else:
                    created = result['creationDate']
                age_days = (datetime.now(created.tzinfo) if created.tzinfo else datetime.now() - created).days
                result['domainAge'] = {
                    'days': age_days,
                    'years': round(age_days / 365, 1)
                }
            except:
                pass

        return result
    except Exception as e:
        return {'error': str(e)}


def _unwrap_url_for_investigation(url: str) -> dict:
    """
    Detect and unwrap security-gateway wrapped URLs (Defender Safe Links,
    Proofpoint, Google redirect, Barracuda, Mimecast, Cisco).
    Returns {'original': ..., 'unwrapped': ..., 'is_wrapped': bool,
             'wrapper': service_name | None}.
    """
    from urllib.parse import urlparse, parse_qs, unquote

    result = {'original': url, 'unwrapped': url, 'is_wrapped': False, 'wrapper': None}
    if not url:
        return result

    # Ensure URL has a scheme
    if not re.match(r'https?://', url, re.I):
        url = 'https://' + url

    def _ensure_scheme(u):
        if u and not re.match(r'https?://', u, re.I):
            return 'https://' + u
        return u

    try:
        parsed = urlparse(url)
        host = (parsed.netloc or '').lower()
        qp = parse_qs(parsed.query)
    except Exception:
        return result

    # Microsoft Defender Safe Links
    if 'safelinks.protection.outlook.com' in host:
        raw = qp.get('url', [None])[0]
        if raw:
            inner = _ensure_scheme(unquote(raw))
            child = _unwrap_url_for_investigation(inner)
            return {'original': url, 'unwrapped': child['unwrapped'],
                    'is_wrapped': True, 'wrapper': 'Microsoft Defender Safe Links'}

    # Proofpoint URL Defense v2
    if 'urldefense.proofpoint.com' in host:
        raw = qp.get('u', [None])[0]
        if raw:
            inner = _ensure_scheme(unquote(raw.replace('-', '%').replace('_', '/')))
            child = _unwrap_url_for_investigation(inner)
            return {'original': url, 'unwrapped': child['unwrapped'],
                    'is_wrapped': True, 'wrapper': 'Proofpoint URL Defense'}

    # Proofpoint URL Defense v3
    if 'urldefense.com' in host:
        import re as _re
        m = _re.search(r'__(.+?)(?:__|;)', parsed.path)
        if m:
            inner = _ensure_scheme(unquote(m.group(1)))
            child = _unwrap_url_for_investigation(inner)
            return {'original': url, 'unwrapped': child['unwrapped'],
                    'is_wrapped': True, 'wrapper': 'Proofpoint URL Defense v3'}

    # Google redirect
    if 'google.com' in host and '/url' in parsed.path:
        raw = qp.get('q', [None])[0] or qp.get('url', [None])[0]
        if raw:
            inner = _ensure_scheme(unquote(raw))
            child = _unwrap_url_for_investigation(inner)
            return {'original': url, 'unwrapped': child['unwrapped'],
                    'is_wrapped': True, 'wrapper': 'Google Redirect'}

    # Barracuda ESS
    if 'linkprotect.cudasvc.com' in host:
        raw = qp.get('a', [None])[0]
        if raw:
            inner = _ensure_scheme(unquote(raw))
            child = _unwrap_url_for_investigation(inner)
            return {'original': url, 'unwrapped': child['unwrapped'],
                    'is_wrapped': True, 'wrapper': 'Barracuda ESS'}

    # Mimecast
    if re.match(r'protect-[a-z]+\.mimecast\.com', host):
        raw = qp.get('d', [None])[0] or qp.get('domain', [None])[0]
        if raw:
            inner = _ensure_scheme(unquote(raw))
            child = _unwrap_url_for_investigation(inner)
            return {'original': url, 'unwrapped': child['unwrapped'],
                    'is_wrapped': True, 'wrapper': 'Mimecast'}

    # Cisco Secure Email
    if 'secure-web.cisco.com' in host:
        parts = parsed.path.strip('/').split('/', 1)
        if len(parts) == 2:
            inner = _ensure_scheme(unquote(parts[1]))
            child = _unwrap_url_for_investigation(inner)
            return {'original': url, 'unwrapped': child['unwrapped'],
                    'is_wrapped': True, 'wrapper': 'Cisco Secure Email'}

    # Generic fallback: check common redirect param names
    for pname in ('url', 'redirect', 'target', 'dest', 'destination', 'goto', 'link'):
        raw = qp.get(pname, [None])[0]
        if raw and re.match(r'https?://', unquote(raw), re.I):
            inner = unquote(raw)
            child = _unwrap_url_for_investigation(inner)
            return {'original': url, 'unwrapped': child['unwrapped'],
                    'is_wrapped': True, 'wrapper': f'URL redirect ({host})'}

    return result


def investigate_url(url: str) -> Dict:
    """Investigate a URL across all enabled services including DNS intelligence.
    Automatically unwraps Defender Safe Links, Proofpoint, and other
    security-gateway wrapped URLs before scanning."""
    from urllib.parse import urlparse

    # ── Unwrap security-gateway URLs before investigation ──
    unwrap_info = _unwrap_url_for_investigation(url)
    target_url = unwrap_info['unwrapped']
    was_wrapped = unwrap_info['is_wrapped']

    # Extract domain from the REAL destination URL
    try:
        parsed = urlparse(target_url)
        domain = parsed.netloc
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
    except:
        domain = None

    results = {
        'url': target_url,
        'domain': domain,
        'investigatedAt': datetime.now().isoformat(),
        'sources': {},
        'dns': {},
        'whois': {},
        'summary': {
            'isMalicious': False,
            'totalSources': 0,
            'maliciousSources': 0,
            'riskScore': 0,
            'findings': []
        }
    }

    # Include unwrap metadata if the URL was wrapped
    if was_wrapped:
        results['urlUnwrap'] = {
            'wasWrapped': True,
            'wrapperService': unwrap_info['wrapper'],
            'wrapperUrl': unwrap_info['original'],
            'actualUrl': target_url,
        }
        results['summary']['findings'].append(
            f"URL was wrapped by {unwrap_info['wrapper']} — "
            f"unwrapped and scanning actual destination: {target_url}"
        )
        print(f"[ThreatIntel] URL unwrapped: {unwrap_info['wrapper']}: "
              f"{url[:60]}... → {target_url}")

    # Threat intelligence services
    services = [
        ('virustotal', check_virustotal_url),
        ('urlhaus', check_urlhaus),
        ('alienvault_otx', check_alienvault_url),
        ('urlscanio', check_urlscanio),
        ('misp', check_misp_url),
    ]

    for service_name, check_func in services:
        if is_service_enabled(service_name) or service_name in ['urlhaus', 'urlscanio']:
            try:
                result = check_func(target_url)
                if 'error' not in result:
                    results['sources'][service_name] = result
                    results['summary']['totalSources'] += 1

                    if service_name == 'virustotal' and result.get('malicious', 0) > 0:
                        results['summary']['maliciousSources'] += 1
                        results['summary']['findings'].append(f"VirusTotal: {result.get('malicious')} detections")
                    elif service_name == 'urlhaus' and result.get('threat'):
                        results['summary']['maliciousSources'] += 1
                        results['summary']['findings'].append(f"URLhaus: {result.get('threat')}")
                    elif service_name == 'urlscanio' and result.get('isMalicious'):
                        results['summary']['maliciousSources'] += 1
                        results['summary']['findings'].append(f"URLScan.io: {result.get('maliciousScans')} malicious scan(s)")
                    elif service_name == 'alienvault_otx' and result.get('pulseCount', 0) > 0:
                        pulse_count = result.get('pulseCount', 0)
                        results['summary']['findings'].append(f"AlienVault: {pulse_count} threat pulses")
                        if pulse_count >= 3:
                            results['summary']['maliciousSources'] += 1
                        results['summary']['riskScore'] = max(
                            results['summary']['riskScore'],
                            min(80, 20 + (pulse_count * 15))
                        )
                    elif service_name == 'misp' and result.get('found'):
                        results['summary']['maliciousSources'] += 1
                        results['summary']['findings'].append(f"MISP: Found in {result.get('eventCount')} threat intel events")
            except Exception as e:
                results['sources'][service_name] = {'error': str(e)}

    # DNS Intelligence (if domain extracted)
    if domain:
        try:
            dns_results = lookup_dns_records(domain)
            if 'error' not in dns_results:
                results['dns'] = dns_results

                # Check for blocklist hits
                blocklists = dns_results.get('blocklists', [])
                listed_count = sum(1 for bl in blocklists if bl.get('listed'))
                if listed_count > 0:
                    results['summary']['findings'].append(f"Domain on {listed_count} blocklist(s)")
                    results['summary']['riskScore'] = max(results['summary']['riskScore'], 30 + (listed_count * 15))

                # Check email security
                email_sec = dns_results.get('emailSecurity', {})
                if email_sec.get('spf', {}).get('valid'):
                    pass  # Good - has SPF
                if not email_sec.get('dmarc', {}).get('valid'):
                    results['summary']['findings'].append("Missing DMARC record")
        except Exception as e:
            results['dns'] = {'error': str(e)}

        # WHOIS lookup
        try:
            whois_results = lookup_whois(domain)
            if 'error' not in whois_results:
                results['whois'] = whois_results

                # Check domain age (new domains are suspicious)
                domain_age = whois_results.get('domainAge', {})
                if domain_age.get('days') and domain_age['days'] < 30:
                    results['summary']['findings'].append(f"Domain only {domain_age['days']} days old")
                    results['summary']['riskScore'] = max(results['summary']['riskScore'], 40)
                elif domain_age.get('days') and domain_age['days'] < 90:
                    results['summary']['findings'].append(f"Domain is {domain_age['days']} days old")
                    results['summary']['riskScore'] = max(results['summary']['riskScore'], 20)
        except Exception as e:
            results['whois'] = {'error': str(e)}

    # AITM Phishing Detection
    try:
        aitm_result = check_aitm_indicators(
            target_url, domain,
            whois_data=results.get('whois'),
            dns_data=results.get('dns')
        )
        if aitm_result.get('detected') or aitm_result.get('confidence', 0) >= 25:
            results['aitmDetection'] = aitm_result
            if aitm_result.get('detected'):
                results['summary']['maliciousSources'] += 1
                platform_str = ', '.join(aitm_result.get('platforms', [])) or 'AITM indicators'
                results['summary']['findings'].append(f"AITM Detection: {platform_str} (confidence: {aitm_result['confidence']}%)")
                results['summary']['riskScore'] = max(results['summary']['riskScore'], 70 + aitm_result['confidence'] // 5)
    except Exception as e:
        print(f"[ThreatIntel] AITM detection error: {e}")

    if results['summary']['maliciousSources'] > 0:
        results['summary']['isMalicious'] = True
        results['summary']['riskScore'] = min(100, 40 + (results['summary']['maliciousSources'] * 25))

    # Generate AI-style verdict summary
    results['summary']['verdict'] = _generate_url_verdict(target_url, results)

    # Store in IOC table for SIEM export
    store_url_ioc(target_url, results)
    # Also store the wrapper URL for cross-reference if it was wrapped
    if was_wrapped:
        store_url_ioc(url, results)

    return results


def _generate_url_verdict(url: str, results: Dict) -> str:
    """Generate a human-readable verdict summary for a URL"""
    from urllib.parse import urlparse

    summary = results.get('summary', {})
    sources = results.get('sources', {})

    risk_score = summary.get('riskScore', 0)
    is_malicious = summary.get('isMalicious', False)
    findings = summary.get('findings', [])

    # Parse URL for context
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
    except:
        domain = url[:50]

    # Gather threat context
    threat_type = None
    malware_name = None
    vt_detections = 0

    if 'urlhaus' in sources:
        urlhaus = sources['urlhaus']
        threat_type = urlhaus.get('threat')
        if urlhaus.get('tags'):
            malware_name = ', '.join(urlhaus['tags'][:3])

    if 'virustotal' in sources:
        vt = sources['virustotal']
        vt_detections = vt.get('malicious', 0)

    # Build verdict
    parts = []

    # Risk assessment
    if risk_score >= 80:
        parts.append(f"DANGEROUS ({risk_score}/100)")
    elif risk_score >= 50:
        parts.append(f"SUSPICIOUS ({risk_score}/100)")
    elif risk_score >= 20:
        parts.append(f"LOW RISK ({risk_score}/100)")
    else:
        parts.append(f"CLEAN ({risk_score}/100)")

    # Domain info
    parts.append(f"URL on domain: {domain[:40]}{'...' if len(domain) > 40 else ''}.")

    # Threat details
    if is_malicious:
        threats = []
        if vt_detections > 0:
            threats.append(f"detected by {vt_detections} security vendors")
        if threat_type:
            threats.append(f"classified as {threat_type}")
        if malware_name:
            threats.append(f"associated with {malware_name}")

        if threats:
            parts.append(f"Identified as: {', '.join(threats)}.")

        # Recommendation
        if threat_type and 'malware' in threat_type.lower():
            parts.append("RECOMMENDATION: Block immediately - known malware distribution.")
        elif threat_type and 'phishing' in threat_type.lower():
            parts.append("RECOMMENDATION: Block immediately - phishing/credential theft.")
        else:
            parts.append("RECOMMENDATION: Block this URL and investigate any access.")
    else:
        parts.append("No malicious activity detected across threat intelligence sources.")

    return " ".join(parts)


def investigate_hash(file_hash: str) -> Dict:
    """Investigate a file hash across all enabled services"""
    results = {
        'hash': file_hash,
        'investigatedAt': datetime.now().isoformat(),
        'sources': {},
        'summary': {
            'isMalicious': False,
            'totalSources': 0,
            'maliciousSources': 0,
            'riskScore': 0,
            'findings': []
        },
        'riskReasons': []
    }

    services = [
        ('virustotal', check_virustotal_hash),
        ('malwarebazaar', check_malwarebazaar_hash),
        ('urlhaus', check_urlhaus_hash),
        ('alienvault_otx', check_alienvault_hash),
        ('misp', check_misp_hash),
    ]

    for service_name, check_func in services:
        # MalwareBazaar and URLhaus don't need API keys
        if is_service_enabled(service_name) or service_name in ['urlhaus', 'malwarebazaar']:
            try:
                result = check_func(file_hash)
                if 'error' not in result:
                    results['sources'][service_name] = result
                    results['summary']['totalSources'] += 1

                    if service_name == 'virustotal' and result.get('malicious', 0) > 0:
                        detections = result.get('malicious', 0)
                        results['summary']['maliciousSources'] += 1
                        results['summary']['findings'].append(f"VirusTotal: {detections} detections")
                        # Add detailed risk reason
                        results['riskReasons'].append({
                            'category': 'Known Malware',
                            'description': f'{detections} antivirus engines detect this file as malicious',
                            'severity': 'critical' if detections >= 10 else 'high' if detections >= 5 else 'medium',
                            'source': 'VirusTotal',
                            'score_contribution': min(40, detections * 4)
                        })

                    elif service_name == 'malwarebazaar' and result.get('found'):
                        results['summary']['maliciousSources'] += 1
                        sig = result.get('signature') or result.get('malwareFamily') or 'Unknown'
                        findings = f"MalwareBazaar: Known malware - {sig}"
                        if result.get('tags'):
                            findings += f" (tags: {', '.join(result.get('tags', [])[:3])})"
                        results['summary']['findings'].append(findings)
                        # Add detailed risk reason
                        results['riskReasons'].append({
                            'category': 'Known Malware',
                            'description': f'File identified as {sig} in MalwareBazaar database',
                            'severity': 'critical',
                            'source': 'MalwareBazaar',
                            'score_contribution': 40,
                            'malwareFamily': sig,
                            'tags': result.get('tags', [])[:5]
                        })
                        # Add YARA matches as additional reasons
                        if result.get('yaraMatches'):
                            for yara in result.get('yaraMatches', [])[:3]:
                                results['riskReasons'].append({
                                    'category': 'YARA Match',
                                    'description': f'Matched YARA rule: {yara.get("rule", "Unknown")}',
                                    'severity': 'high',
                                    'source': 'MalwareBazaar',
                                    'score_contribution': 15
                                })

                    elif service_name == 'urlhaus' and int(result.get('urlCount', 0) or 0) > 0:
                        url_count = int(result.get('urlCount', 0) or 0)
                        results['summary']['maliciousSources'] += 1
                        results['summary']['findings'].append(f"URLhaus: Associated with {url_count} malicious URLs")
                        # Add detailed risk reason
                        results['riskReasons'].append({
                            'category': 'Malware Distribution',
                            'description': f'File associated with {url_count} malicious distribution URLs',
                            'severity': 'high',
                            'source': 'URLhaus',
                            'score_contribution': 30
                        })

                    elif service_name == 'alienvault_otx' and result.get('pulseCount', 0) > 0:
                        pulse_count = result.get('pulseCount', 0)
                        results['summary']['findings'].append(f"AlienVault: {pulse_count} threat pulses")
                        if pulse_count >= 3:
                            results['summary']['maliciousSources'] += 1
                        results['summary']['riskScore'] = max(
                            results['summary']['riskScore'],
                            min(80, 20 + (pulse_count * 15))
                        )
                        # Add detailed risk reason
                        results['riskReasons'].append({
                            'category': 'Threat Intelligence',
                            'description': f'Referenced in {pulse_count} threat intelligence pulses',
                            'severity': 'medium' if pulse_count < 5 else 'high',
                            'source': 'AlienVault OTX',
                            'score_contribution': min(20, pulse_count * 4)
                        })

                    elif service_name == 'misp' and result.get('found'):
                        event_count = result.get('eventCount', 0)
                        results['summary']['maliciousSources'] += 1
                        malware_info = ', '.join(result.get('malwareNames', [])[:3]) or 'Threat intel match'
                        results['summary']['findings'].append(f"MISP: Found in {event_count} events — {malware_info}")
                        results['riskReasons'].append({
                            'category': 'MISP Intelligence',
                            'description': f'Hash found in {event_count} MISP threat intel events',
                            'severity': 'critical' if event_count >= 5 else 'high',
                            'source': 'MISP',
                            'score_contribution': min(40, event_count * 5)
                        })

            except Exception as e:
                results['sources'][service_name] = {'error': str(e)}

    # Malpedia enrichment: extract family name from VT/MalwareBazaar and query
    try:
        family_name = None
        vt_source = results['sources'].get('virustotal', {})
        mb_source = results['sources'].get('malwarebazaar', {})
        if mb_source.get('signature'):
            family_name = mb_source['signature']
        elif mb_source.get('malwareFamily'):
            family_name = mb_source['malwareFamily']
        elif vt_source.get('suggestedThreatLabel'):
            # VT labels like "trojan.agent/generic" — extract family part
            label = vt_source['suggestedThreatLabel']
            parts = label.replace('/', '.').split('.')
            if len(parts) >= 2:
                family_name = parts[1] if parts[1].lower() not in ('generic', 'gen', 'agent') else parts[0]

        if family_name and is_service_enabled('malpedia'):
            malpedia_result = check_malpedia_family(family_name)
            if 'error' not in malpedia_result:
                results['sources']['malpedia'] = malpedia_result
                results['summary']['totalSources'] += 1
                if malpedia_result.get('attribution'):
                    results['summary']['findings'].append(
                        f"Malpedia: Attributed to {', '.join(malpedia_result['attribution'][:2])}"
                    )
                    results['riskReasons'].append({
                        'category': 'APT Attribution',
                        'description': f'Malware family "{family_name}" attributed to: {", ".join(malpedia_result["attribution"][:3])}',
                        'severity': 'critical',
                        'source': 'Malpedia',
                        'score_contribution': 25
                    })
    except Exception as e:
        print(f"[ThreatIntel] Malpedia enrichment error: {e}")

    if results['summary']['maliciousSources'] > 0:
        results['summary']['isMalicious'] = True
        results['summary']['riskScore'] = min(100, 50 + (results['summary']['maliciousSources'] * 20))

    # Generate AI-style verdict summary
    results['summary']['verdict'] = _generate_hash_verdict(file_hash, results)

    # Store in IOC table for SIEM export
    store_hash_ioc(file_hash, results)

    return results


def _generate_hash_verdict(file_hash: str, results: Dict) -> str:
    """Generate a human-readable verdict summary for a file hash"""
    summary = results.get('summary', {})
    sources = results.get('sources', {})

    risk_score = summary.get('riskScore', 0)
    is_malicious = summary.get('isMalicious', False)
    findings = summary.get('findings', [])

    # Gather context
    malware_family = None
    malware_type = None
    file_type = None
    file_name = None
    vt_detections = 0
    tags = []

    if 'virustotal' in sources:
        vt = sources['virustotal']
        vt_detections = vt.get('malicious', 0)
        file_type = vt.get('fileType')
        file_name = vt.get('fileName')

    if 'malwarebazaar' in sources:
        mb = sources['malwarebazaar']
        if mb.get('found'):
            malware_family = mb.get('signature') or mb.get('malwareFamily')
            file_type = file_type or mb.get('fileType')
            file_name = file_name or mb.get('fileName')
            tags = mb.get('tags', [])[:5]

    if 'urlhaus' in sources:
        uh = sources['urlhaus']
        if uh.get('signature'):
            malware_family = malware_family or uh.get('signature')

    # Build verdict
    parts = []

    # Risk assessment
    if risk_score >= 80:
        parts.append(f"MALICIOUS ({risk_score}/100)")
    elif risk_score >= 50:
        parts.append(f"SUSPICIOUS ({risk_score}/100)")
    elif risk_score >= 20:
        parts.append(f"LOW RISK ({risk_score}/100)")
    else:
        parts.append(f"CLEAN ({risk_score}/100)")

    # File info
    if file_name:
        parts.append(f"File: {file_name[:40]}{'...' if len(file_name) > 40 else ''}.")
    if file_type:
        parts.append(f"Type: {file_type}.")

    # Threat details
    if is_malicious:
        threats = []
        if vt_detections > 0:
            threats.append(f"detected by {vt_detections} antivirus engines")
        if malware_family:
            threats.append(f"identified as {malware_family}")
        if tags:
            threats.append(f"tags: {', '.join(tags)}")

        if threats:
            parts.append(f"Identified as: {', '.join(threats)}.")

        # Recommendations based on malware type
        if malware_family:
            family_lower = malware_family.lower()
            if any(x in family_lower for x in ['ransom', 'crypt', 'locker']):
                parts.append("RECOMMENDATION: RANSOMWARE - Isolate affected systems immediately.")
            elif any(x in family_lower for x in ['trojan', 'rat', 'backdoor']):
                parts.append("RECOMMENDATION: TROJAN/RAT - Check for persistence and lateral movement.")
            elif any(x in family_lower for x in ['miner', 'coin']):
                parts.append("RECOMMENDATION: CRYPTOMINER - Check system resources and network traffic.")
            elif any(x in family_lower for x in ['steal', 'password', 'credential']):
                parts.append("RECOMMENDATION: STEALER - Reset credentials for affected users.")
            else:
                parts.append("RECOMMENDATION: Quarantine file and investigate execution history.")
        else:
            parts.append("RECOMMENDATION: Quarantine and analyze with sandbox.")
    else:
        parts.append("No malicious signatures detected across threat intelligence databases.")
        if vt_detections == 0 and 'virustotal' in sources:
            parts.append("File appears safe but exercise caution with unknown executables.")

    return " ".join(parts)


def investigate_all_iocs(ips: List[str] = None, urls: List[str] = None,
                         hashes: List[str] = None, max_per_type: int = 10) -> Dict:
    """
    Investigate multiple IOCs at once.
    Limits each type to avoid API rate limits.
    """
    results = {
        'investigatedAt': datetime.now().isoformat(),
        'ips': [],
        'urls': [],
        'hashes': [],
        'summary': {
            'totalIOCs': 0,
            'maliciousIOCs': 0,
            'overallRiskScore': 0,
        }
    }

    # Investigate IPs
    if ips:
        for ip in ips[:max_per_type]:
            ip_result = investigate_ip(ip)
            results['ips'].append(ip_result)
            results['summary']['totalIOCs'] += 1
            if ip_result['summary']['isMalicious']:
                results['summary']['maliciousIOCs'] += 1
                results['summary']['overallRiskScore'] = max(
                    results['summary']['overallRiskScore'],
                    ip_result['summary']['riskScore']
                )

    # Investigate URLs
    if urls:
        for url in urls[:max_per_type]:
            url_result = investigate_url(url)
            results['urls'].append(url_result)
            results['summary']['totalIOCs'] += 1
            if url_result['summary']['isMalicious']:
                results['summary']['maliciousIOCs'] += 1
                results['summary']['overallRiskScore'] = max(
                    results['summary']['overallRiskScore'],
                    url_result['summary']['riskScore']
                )

    # Investigate hashes
    if hashes:
        for file_hash in hashes[:max_per_type]:
            hash_result = investigate_hash(file_hash)
            results['hashes'].append(hash_result)
            results['summary']['totalIOCs'] += 1
            if hash_result['summary']['isMalicious']:
                results['summary']['maliciousIOCs'] += 1
                results['summary']['overallRiskScore'] = max(
                    results['summary']['overallRiskScore'],
                    hash_result['summary']['riskScore']
                )

    return results


def get_configured_services() -> Dict:
    """Return status of all configured services"""
    config = load_config()
    status = {}

    # Services that work without API key (community/free endpoints)
    free_services = ['greynoise']  # GreyNoise has free community endpoint

    for service, settings in config.items():
        if isinstance(settings, dict):
            has_key = bool(settings.get('api_key'))
            is_free = service in free_services
            status[service] = {
                'enabled': settings.get('enabled', False),
                'configured': has_key or is_free,
                'needsKey': not is_free,
                'description': settings.get('description', ''),
                'rateLimit': settings.get('rate_limit', '')
            }

    return status


# CLI for testing
if __name__ == '__main__':
    import sys

    print("=== Threat Intelligence Module ===\n")
    print("Configured services:")
    for service, status in get_configured_services().items():
        state = "✓" if status['configured'] and status['enabled'] else "✗"
        print(f"  {state} {service}: {'configured' if status['configured'] else 'needs API key'}")

    if len(sys.argv) > 2:
        ioc_type = sys.argv[1]
        ioc_value = sys.argv[2]

        print(f"\nInvestigating {ioc_type}: {ioc_value}\n")

        if ioc_type == 'ip':
            result = investigate_ip(ioc_value)
        elif ioc_type == 'url':
            result = investigate_url(ioc_value)
        elif ioc_type == 'hash':
            result = investigate_hash(ioc_value)
        else:
            print(f"Unknown type: {ioc_type}")
            sys.exit(1)

        print(json.dumps(result, indent=2))
    else:
        print("\nUsage: python threat_intel.py <ip|url|hash> <value>")
        print("Example: python threat_intel.py ip 8.8.8.8")
