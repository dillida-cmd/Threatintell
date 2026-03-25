#!/usr/bin/env python3
"""
AI Risk Validator Module
Analyzes threat intelligence results and validates risk scores using pattern recognition,
consensus analysis, and contextual understanding.
"""

import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

# Known legitimate services that often get flagged incorrectly
KNOWN_HOSTING_PROVIDERS = [
    'hostinger', 'aws', 'amazon', 'azure', 'microsoft', 'google', 'cloudflare',
    'digitalocean', 'linode', 'vultr', 'ovh', 'hetzner', 'godaddy', 'namecheap',
    'bluehost', 'hostgator', 'dreamhost', 'ionos', 'contabo', 'scaleway'
]

KNOWN_CDN_PROVIDERS = [
    'cloudflare', 'akamai', 'fastly', 'cloudfront', 'jsdelivr', 'unpkg',
    'cdnjs', 'maxcdn', 'stackpath', 'keycdn', 'bunny', 'imperva', 'incapsula'
]

KNOWN_LEGITIMATE_SERVICES = [
    'google', 'microsoft', 'apple', 'amazon', 'facebook', 'meta', 'twitter',
    'github', 'gitlab', 'bitbucket', 'linkedin', 'dropbox', 'slack', 'zoom',
    'salesforce', 'adobe', 'oracle', 'ibm', 'cisco', 'vmware', 'docker'
]

# Suspicious TLDs often used in phishing/malware
SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.work', '.click', '.link', '.gq', '.ml', '.cf', '.tk', '.ga',
    '.buzz', '.rest', '.surf', '.monster', '.quest', '.sbs', '.cfd'
]

# High-risk imports in PE files
HIGH_RISK_IMPORTS = {
    'critical': [
        'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
        'NtUnmapViewOfSection', 'ZwUnmapViewOfSection', 'RtlCreateUserThread'
    ],
    'high': [
        'VirtualProtect', 'VirtualAlloc', 'LoadLibraryA', 'LoadLibraryW',
        'GetProcAddress', 'CreateProcess', 'ShellExecute', 'WinExec',
        'URLDownloadToFile', 'InternetOpen', 'InternetConnect'
    ],
    'medium': [
        'RegSetValue', 'RegCreateKey', 'CreateService', 'OpenProcess',
        'ReadProcessMemory', 'SetWindowsHookEx', 'CreateFile'
    ]
}

# MITRE ATT&CK technique patterns
MITRE_PATTERNS = {
    'T1055': {'name': 'Process Injection', 'severity': 'critical', 'indicators': ['CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx', 'NtUnmapViewOfSection']},
    'T1547': {'name': 'Boot/Logon Autostart', 'severity': 'high', 'indicators': ['RegSetValue', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run']},
    'T1071': {'name': 'Application Layer Protocol', 'severity': 'medium', 'indicators': ['InternetConnect', 'HttpOpenRequest', 'InternetReadFile']},
    'T1027': {'name': 'Obfuscated Files', 'severity': 'medium', 'indicators': ['high_entropy', 'packed', 'encrypted']},
    'T1059': {'name': 'Command Scripting', 'severity': 'high', 'indicators': ['cmd.exe', 'powershell', 'wscript', 'cscript']},
    'T1083': {'name': 'File Discovery', 'severity': 'low', 'indicators': ['FindFirstFile', 'FindNextFile', 'GetFileAttributes']},
    'T1082': {'name': 'System Discovery', 'severity': 'low', 'indicators': ['GetComputerName', 'GetUserName', 'GetSystemInfo']},
    'T1140': {'name': 'Deobfuscate/Decode', 'severity': 'medium', 'indicators': ['CryptDecrypt', 'CryptStringToBinary', 'base64']},
}


class AIRiskValidator:
    """AI-powered risk score validator using pattern analysis and consensus"""

    # Source names to strip from user-facing text
    _SOURCE_PREFIXES = [
        'VirusTotal: ', 'AbuseIPDB: ', 'URLhaus: ', 'Shodan: ', 'AlienVault: ',
        'GreyNoise: ', 'URLScan.io: ', 'MalwareBazaar: ', 'IPQualityScore: ',
        'ThreatFox: ', 'BGPView: ', 'Malpedia: ', 'MISP: ', 'DNSBL: ', 'WHOIS: ',
        'IPQualityScore ', 'High IPQualityScore ',
    ]

    def __init__(self):
        self.validation_history = []

    def _sanitize_analysis(self, analysis: Dict) -> Dict:
        """Remove source names from all user-facing text in the analysis"""
        # Strip source prefixes from factor strings
        for category in ['positive', 'negative', 'neutral']:
            if category in analysis.get('factors', {}):
                sanitized = []
                for text in analysis['factors'][category]:
                    for prefix in self._SOURCE_PREFIXES:
                        if text.startswith(prefix):
                            text = text[len(prefix):]
                            # Capitalize first letter after stripping
                            if text:
                                text = text[0].upper() + text[1:]
                            break
                    sanitized.append(text)
                analysis['factors'][category] = sanitized

        # Strip from false positive indicators
        if 'falsePositiveIndicators' in analysis:
            sanitized = []
            for text in analysis['falsePositiveIndicators']:
                for prefix in self._SOURCE_PREFIXES:
                    if text.startswith(prefix):
                        text = text[len(prefix):]
                        if text:
                            text = text[0].upper() + text[1:]
                        break
                sanitized.append(text)
            analysis['falsePositiveIndicators'] = sanitized

        # Remove source field from threat indicators
        if 'threatIndicators' in analysis:
            for indicator in analysis['threatIndicators']:
                if 'source' in indicator:
                    del indicator['source']

        return analysis

    def validate_ip_risk(self, results: Dict) -> Dict:
        """Validate and potentially adjust IP threat intelligence risk score"""
        sources = results.get('sources', {})
        original_score = results.get('summary', {}).get('riskScore', 0)
        original_malicious = results.get('summary', {}).get('isMalicious', False)

        analysis = {
            'originalScore': original_score,
            'originalMalicious': original_malicious,
            'validatedScore': original_score,
            'validatedMalicious': original_malicious,
            'confidence': 0,
            'reasoning': [],
            'factors': {
                'positive': [],  # Indicators of legitimacy
                'negative': [],  # Indicators of maliciousness
                'neutral': []    # Informational
            },
            'recommendation': '',
            'falsePositiveIndicators': [],
            'threatIndicators': []
        }

        # Analyze each source
        clean_sources = 0
        threat_sources = 0
        total_sources = len(sources)

        # Check AbuseIPDB
        if 'abuseipdb' in sources:
            abuse = sources['abuseipdb']
            abuse_score = abuse.get('abuseScore', 0)
            total_reports = abuse.get('totalReports', 0)

            if abuse_score == 0 and total_reports == 0:
                clean_sources += 2
                analysis['factors']['positive'].append('AbuseIPDB: No abuse reports (strong clean signal)')
            elif abuse_score > 80:
                threat_sources += 2
                analysis['factors']['negative'].append(f'AbuseIPDB: High abuse score ({abuse_score}%) with {total_reports} reports')
                analysis['threatIndicators'].append({'source': 'AbuseIPDB', 'type': 'abuse_reports', 'severity': 'high'})
            elif abuse_score > 50:
                threat_sources += 1
                analysis['factors']['negative'].append(f'AbuseIPDB: Moderate abuse score ({abuse_score}%)')

        # Check VirusTotal
        if 'virustotal' in sources:
            vt = sources['virustotal']
            malicious = vt.get('malicious', 0)
            harmless = vt.get('harmless', 0)
            reputation = vt.get('reputation', 0)

            if malicious == 0 and harmless > 50:
                clean_sources += 2
                analysis['factors']['positive'].append(f'VirusTotal: Clean ({harmless} vendors say harmless)')
            elif malicious > 5:
                threat_sources += 2
                analysis['factors']['negative'].append(f'VirusTotal: {malicious} security vendors flag as malicious')
                analysis['threatIndicators'].append({'source': 'VirusTotal', 'type': 'vendor_detections', 'severity': 'high'})
            elif malicious > 0:
                threat_sources += 1
                analysis['factors']['negative'].append(f'VirusTotal: {malicious} vendor detection(s)')

        # Check IPQualityScore
        if 'ipqualityscore' in sources:
            ipqs = sources['ipqualityscore']
            fraud_score = ipqs.get('fraudScore', 0)
            isp = str(ipqs.get('isp', '')).lower()
            org = str(ipqs.get('organization', '')).lower()

            # Check if it's a known hosting provider
            is_hosting = any(hp in isp or hp in org for hp in KNOWN_HOSTING_PROVIDERS)
            is_cdn = any(cdn in isp or cdn in org for cdn in KNOWN_CDN_PROVIDERS)

            if is_hosting or is_cdn:
                analysis['falsePositiveIndicators'].append(f'Known hosting/CDN provider: {ipqs.get("isp", "Unknown")}')
                analysis['factors']['neutral'].append(f'IPQualityScore flags hosting/CDN IPs as proxy (common false positive)')

                if fraud_score > 75 and not any(t['source'] != 'IPQualityScore' for t in analysis['threatIndicators']):
                    # High IPQS score but no corroboration - likely false positive
                    analysis['factors']['positive'].append('High IPQualityScore not corroborated by other sources')
            elif fraud_score > 85:
                threat_sources += 1
                analysis['factors']['negative'].append(f'IPQualityScore: Very high fraud score ({fraud_score})')
            elif fraud_score < 30:
                clean_sources += 1
                analysis['factors']['positive'].append('IPQualityScore: Low fraud score')

        # Check ThreatFox
        if 'threatfox' in sources:
            tf = sources['threatfox']
            if tf.get('found'):
                threat_sources += 3
                analysis['factors']['negative'].append('ThreatFox: Known malicious IOC in malware database')
                analysis['threatIndicators'].append({'source': 'ThreatFox', 'type': 'known_ioc', 'severity': 'critical'})
            else:
                clean_sources += 1
                analysis['factors']['positive'].append('ThreatFox: Not found in malware IOC database')

        # Check AlienVault
        if 'alienvault_otx' in sources:
            otx = sources['alienvault_otx']
            pulses = otx.get('pulseCount', 0)
            if pulses > 10:
                threat_sources += 1
                analysis['factors']['negative'].append(f'AlienVault: Found in {pulses} threat intelligence reports')
            elif pulses == 0:
                clean_sources += 1
                analysis['factors']['positive'].append('AlienVault: No threat intelligence reports')

        # Check GreyNoise
        if 'greynoise' in sources:
            gn = sources['greynoise']
            if gn.get('noise') and gn.get('classification') == 'malicious':
                threat_sources += 1
                analysis['factors']['negative'].append('GreyNoise: Known malicious scanner')
            elif gn.get('noise') and gn.get('classification') == 'benign':
                analysis['factors']['neutral'].append('GreyNoise: Known benign scanner')

        # Check BGPView for hosting/CDN detection (more accurate than static list)
        if 'bgpview' in sources:
            bgp = sources['bgpview']
            asn_info = bgp.get('asn', {})
            if bgp.get('isHosting') or bgp.get('isCdn'):
                provider_name = asn_info.get('description') or asn_info.get('name') or 'Unknown'
                analysis['falsePositiveIndicators'].append(f'BGPView: IP belongs to hosting/CDN provider ({provider_name})')
                analysis['factors']['neutral'].append(f'BGPView: AS{asn_info.get("asn", "?")} — {provider_name} (hosting/CDN)')
            elif asn_info.get('name'):
                analysis['factors']['neutral'].append(f'BGPView: AS{asn_info.get("asn", "?")} — {asn_info["name"]}')

        # Calculate validated score using consensus
        analysis = self._calculate_consensus_score(analysis, clean_sources, threat_sources, total_sources)
        analysis = self._cross_correlate_findings(analysis, results, 'ip')

        return self._sanitize_analysis(analysis)

    def validate_url_risk(self, results: Dict) -> Dict:
        """Validate and potentially adjust URL threat intelligence risk score"""
        sources = results.get('sources', {})
        dns = results.get('dns', {})
        whois = results.get('whois', {})
        original_score = results.get('summary', {}).get('riskScore', 0)
        domain = results.get('domain', '')

        analysis = {
            'originalScore': original_score,
            'originalMalicious': results.get('summary', {}).get('isMalicious', False),
            'validatedScore': original_score,
            'validatedMalicious': False,
            'confidence': 0,
            'reasoning': [],
            'factors': {'positive': [], 'negative': [], 'neutral': []},
            'recommendation': '',
            'falsePositiveIndicators': [],
            'threatIndicators': []
        }

        clean_sources = 0
        threat_sources = 0

        # Check domain characteristics
        if domain:
            # Check for suspicious TLD
            for tld in SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    analysis['factors']['negative'].append(f'Suspicious TLD: {tld}')
                    threat_sources += 1
                    break

            # Check if it's a known legitimate service
            for service in KNOWN_LEGITIMATE_SERVICES:
                if service in domain.lower():
                    analysis['factors']['positive'].append(f'Known legitimate service: {service}')
                    clean_sources += 2
                    analysis['falsePositiveIndicators'].append(f'Domain associated with {service}')
                    break

        # Check WHOIS for domain age
        if whois and not whois.get('error'):
            domain_age = whois.get('domainAge', {})
            if domain_age.get('days'):
                days = domain_age['days']
                if days < 30:
                    threat_sources += 1
                    analysis['factors']['negative'].append(f'Very new domain ({days} days old)')
                    analysis['threatIndicators'].append({'source': 'WHOIS', 'type': 'new_domain', 'severity': 'medium'})
                elif days > 365 * 5:
                    clean_sources += 1
                    analysis['factors']['positive'].append(f'Established domain ({domain_age.get("years")} years old)')

        # Check DNS blocklists
        if dns and dns.get('blocklists'):
            listed_count = sum(1 for bl in dns['blocklists'] if bl.get('listed'))
            if listed_count > 0:
                threat_sources += listed_count
                analysis['factors']['negative'].append(f'Listed on {listed_count} DNS blocklist(s)')
                analysis['threatIndicators'].append({'source': 'DNSBL', 'type': 'blocklist', 'severity': 'high'})
            else:
                clean_sources += 1
                analysis['factors']['positive'].append('Not on any DNS blocklists')

        # Check email security (informational)
        if dns and dns.get('emailSecurity'):
            email_sec = dns['emailSecurity']
            if email_sec.get('dmarc', {}).get('valid') and email_sec.get('spf', {}).get('valid'):
                analysis['factors']['positive'].append('Proper email security (SPF + DMARC)')
            elif not email_sec.get('dmarc', {}).get('valid'):
                analysis['factors']['neutral'].append('Missing DMARC record')

        # Check VirusTotal
        if 'virustotal' in sources:
            vt = sources['virustotal']
            malicious = vt.get('malicious', 0)
            harmless = vt.get('harmless', 0)
            total_scanned = malicious + harmless + vt.get('suspicious', 0) + vt.get('undetected', 0)

            if malicious > 5:
                threat_sources += 2
                analysis['factors']['negative'].append(f'VirusTotal: {malicious} security vendors flag as malicious')
                analysis['threatIndicators'].append({'source': 'VirusTotal', 'type': 'vendor_detections', 'severity': 'high'})
            elif malicious > 0 and malicious <= 3:
                # Very low detection count - likely false positive
                if harmless > 50:
                    clean_sources += 1
                    analysis['factors']['neutral'].append(f'VirusTotal: Only {malicious} detection(s) vs {harmless} clean - likely false positive')
                    analysis['falsePositiveIndicators'].append(f'Single/low vendor detection ({malicious}/{total_scanned}) often indicates false positive')
                else:
                    analysis['factors']['neutral'].append(f'VirusTotal: {malicious} detection(s) - inconclusive')
            elif malicious > 3 and malicious <= 5:
                # Low but notable detection count
                threat_sources += 1
                analysis['factors']['negative'].append(f'VirusTotal: {malicious} vendor detections')
            elif malicious == 0:
                clean_sources += 2
                analysis['factors']['positive'].append('VirusTotal: No security vendor detections')

        # Check URLhaus
        if 'urlhaus' in sources:
            uh = sources['urlhaus']
            if uh.get('found') or uh.get('threat'):
                threat_sources += 3
                analysis['factors']['negative'].append(f'URLhaus: Known malware distribution ({uh.get("threat", "malware")})')
                analysis['threatIndicators'].append({'source': 'URLhaus', 'type': 'known_malware', 'severity': 'critical'})
            else:
                clean_sources += 1
                analysis['factors']['positive'].append('URLhaus: Not in malware URL database')

        # Check AlienVault
        if 'alienvault_otx' in sources:
            otx = sources['alienvault_otx']
            # Check for whitelisted indicators
            validation = otx.get('validation', [])
            for v in validation:
                if v.get('source') in ['whitelist', 'majestic', 'alexa', 'akamai']:
                    clean_sources += 1
                    analysis['factors']['positive'].append(f'AlienVault: {v.get("message", "Whitelisted")}')
                    analysis['falsePositiveIndicators'].append(v.get('message'))

            pulse_count = otx.get('pulseCount', 0)
            if pulse_count >= 3:
                threat_sources += 2
                analysis['factors']['negative'].append(f'AlienVault: {pulse_count} threat reports')
                analysis['threatIndicators'].append({'source': 'AlienVault OTX', 'type': 'threat_pulses', 'severity': 'high'})
            elif pulse_count > 0:
                threat_sources += 1
                analysis['factors']['negative'].append(f'AlienVault: {pulse_count} threat report(s)')

        # Check MISP
        if 'misp' in sources:
            misp = sources['misp']
            if misp.get('found'):
                event_count = misp.get('eventCount', 0)
                threat_sources += 2
                analysis['factors']['negative'].append(f'MISP: Found in {event_count} threat intel event(s)')
                analysis['threatIndicators'].append({'source': 'MISP', 'type': 'threat_intel', 'severity': 'high'})
            else:
                clean_sources += 1
                analysis['factors']['positive'].append('MISP: Not in threat intelligence database')

        # Check URLScan.io
        if 'urlscanio' in sources:
            usio = sources['urlscanio']
            if usio.get('isMalicious'):
                threat_sources += 2
                analysis['factors']['negative'].append(f'URLScan.io: {usio.get("maliciousScans", 0)} malicious verdict(s)')
                analysis['threatIndicators'].append({'source': 'URLScan.io', 'type': 'malicious_scan', 'severity': 'high'})
            elif usio.get('totalScans', 0) > 0 and not usio.get('isMalicious'):
                clean_sources += 1
                analysis['factors']['positive'].append(f'URLScan.io: {usio.get("totalScans")} scans, no malicious verdicts')

        # AITM Detection
        aitm = results.get('aitmDetection', {})
        if aitm.get('detected'):
            severity = aitm.get('severity', 'high')
            confidence = aitm.get('confidence', 0)
            if severity == 'critical':
                threat_sources += 4
            elif severity == 'high':
                threat_sources += 3
            else:
                threat_sources += 2
            platforms = ', '.join(aitm.get('platforms', [])) or 'AITM indicators'
            analysis['factors']['negative'].append(f'AITM Detection: {platforms} (confidence: {confidence}%)')
            analysis['threatIndicators'].append({'source': 'AITM Detection', 'type': 'phishing_kit', 'severity': severity})
            for mitre_id in aitm.get('mitre', []):
                analysis.setdefault('mitreAttacks', []).append({'id': mitre_id, 'name': 'Adversary-in-the-Middle', 'severity': severity})
        elif aitm.get('confidence', 0) >= 25:
            threat_sources += 1
            analysis['factors']['negative'].append(f'AITM Warning: Partial indicators detected (confidence: {aitm["confidence"]}%)')

        analysis = self._calculate_consensus_score(analysis, clean_sources, threat_sources, len(sources) + 2)
        analysis = self._cross_correlate_findings(analysis, results, 'url')

        return self._sanitize_analysis(analysis)

    def validate_hash_risk(self, results: Dict) -> Dict:
        """Validate and potentially adjust hash/file threat intelligence risk score"""
        sources = results.get('sources', {})
        original_score = results.get('summary', {}).get('riskScore', 0)

        analysis = {
            'originalScore': original_score,
            'originalMalicious': results.get('summary', {}).get('isMalicious', False),
            'validatedScore': original_score,
            'validatedMalicious': False,
            'confidence': 0,
            'reasoning': [],
            'factors': {'positive': [], 'negative': [], 'neutral': []},
            'recommendation': '',
            'falsePositiveIndicators': [],
            'threatIndicators': [],
            'malwareFamily': None,
            'mitreAttacks': []
        }

        clean_sources = 0
        threat_sources = 0

        # Check VirusTotal
        if 'virustotal' in sources:
            vt = sources['virustotal']
            detections = vt.get('malicious', 0) + vt.get('suspicious', 0)
            total = vt.get('total', 70)

            if detections == 0:
                clean_sources += 3
                analysis['factors']['positive'].append('VirusTotal: No detections from any vendor')
            elif detections < 3:
                clean_sources += 1
                analysis['factors']['neutral'].append(f'VirusTotal: Only {detections} detection(s) - possible false positive')
                analysis['falsePositiveIndicators'].append('Low detection count may indicate false positive')
            elif detections < 10:
                threat_sources += 1
                analysis['factors']['negative'].append(f'VirusTotal: {detections} vendor detections')
            else:
                threat_sources += 3
                analysis['factors']['negative'].append(f'VirusTotal: {detections} vendor detections (high confidence malware)')
                analysis['threatIndicators'].append({'source': 'VirusTotal', 'type': 'multi_vendor', 'severity': 'critical'})

            # Extract malware family if available
            if vt.get('popularThreatName'):
                analysis['malwareFamily'] = vt['popularThreatName']

        # Check MalwareBazaar
        if 'malwarebazaar' in sources:
            mb = sources['malwarebazaar']
            if mb.get('found'):
                threat_sources += 3
                analysis['factors']['negative'].append(f'MalwareBazaar: Known malware sample')
                if mb.get('signature'):
                    analysis['malwareFamily'] = mb['signature']
                    analysis['factors']['negative'].append(f'Malware family: {mb["signature"]}')
                analysis['threatIndicators'].append({'source': 'MalwareBazaar', 'type': 'known_malware', 'severity': 'critical'})
            else:
                clean_sources += 1
                analysis['factors']['positive'].append('MalwareBazaar: Not in malware database')

        # Check ThreatFox
        if 'threatfox' in sources:
            tf = sources['threatfox']
            if tf.get('found'):
                threat_sources += 2
                analysis['factors']['negative'].append('ThreatFox: Known malicious IOC')
                analysis['threatIndicators'].append({'source': 'ThreatFox', 'type': 'known_ioc', 'severity': 'high'})
            else:
                clean_sources += 1
                analysis['factors']['positive'].append('ThreatFox: Not in IOC database')

        # Check Malpedia enrichment
        if 'malpedia' in sources:
            mp = sources['malpedia']
            if mp.get('attribution'):
                threat_sources += 2
                actors = ', '.join(mp['attribution'][:3])
                analysis['factors']['negative'].append(f'Malpedia: Attributed to threat actor(s): {actors}')
                analysis['threatIndicators'].append({'source': 'Malpedia', 'type': 'apt_attribution', 'severity': 'critical'})
            if mp.get('mitreTechniques'):
                for tech in mp['mitreTechniques'][:5]:
                    analysis['mitreAttacks'].append({'id': tech, 'name': 'Malpedia technique', 'severity': 'high'})

        analysis = self._calculate_consensus_score(analysis, clean_sources, threat_sources, len(sources))
        analysis = self._cross_correlate_findings(analysis, results, 'hash')

        return self._sanitize_analysis(analysis)

    def validate_sandbox_risk(self, results: Dict) -> Dict:
        """Validate and potentially adjust sandbox analysis risk score"""
        original_score = results.get('riskScore', 0)
        behaviors = results.get('behaviors', [])
        network = results.get('network', {})
        processes = results.get('processTree', [])
        pe_analysis = results.get('peAnalysis', {})
        threat_map = results.get('threatMap', {})

        analysis = {
            'originalScore': original_score,
            'originalRiskLevel': results.get('riskLevel', 'Unknown'),
            'validatedScore': original_score,
            'validatedRiskLevel': 'Unknown',
            'confidence': 0,
            'reasoning': [],
            'factors': {'positive': [], 'negative': [], 'neutral': []},
            'recommendation': '',
            'behaviorAnalysis': [],
            'mitreAttacks': [],
            'iocs': {
                'ips': [],
                'domains': [],
                'files': [],
                'registry': []
            }
        }

        threat_score = 0
        clean_score = 0

        # Analyze PE imports
        if pe_analysis and pe_analysis.get('imports'):
            imports = pe_analysis['imports']
            import_list = []
            for imp in imports:
                if isinstance(imp, dict):
                    import_list.extend(imp.get('functions', []))
                elif isinstance(imp, str):
                    import_list.append(imp)

            # Check for high-risk imports
            for imp_name in import_list:
                if any(crit in imp_name for crit in HIGH_RISK_IMPORTS['critical']):
                    threat_score += 25
                    technique = self._get_mitre_technique(imp_name)
                    analysis['factors']['negative'].append(f'Critical API: {imp_name}')
                    if technique:
                        analysis['mitreAttacks'].append(technique)
                elif any(high in imp_name for high in HIGH_RISK_IMPORTS['high']):
                    threat_score += 10
                    analysis['factors']['negative'].append(f'Suspicious API: {imp_name}')
                elif any(med in imp_name for med in HIGH_RISK_IMPORTS['medium']):
                    threat_score += 5

        # Analyze PE sections
        if pe_analysis and pe_analysis.get('sections'):
            for section in pe_analysis['sections']:
                entropy = section.get('entropy', 0)
                flags = section.get('flags', '')

                if entropy > 7.5:
                    threat_score += 15
                    analysis['factors']['negative'].append(f'High entropy section: {section.get("name")} ({entropy:.2f})')
                    analysis['mitreAttacks'].append({'id': 'T1027', 'name': 'Obfuscated Files', 'severity': 'medium'})

                if 'WRITE' in flags and 'EXECUTE' in flags:
                    threat_score += 20
                    analysis['factors']['negative'].append(f'RWX section: {section.get("name")} (self-modifying code)')

        # Analyze network activity
        if network:
            connections = network.get('connections', [])
            dns_queries = network.get('dnsQueries', [])

            if connections:
                analysis['factors']['negative'].append(f'Network connections detected: {len(connections)}')
                threat_score += len(connections) * 5
                for conn in connections[:5]:
                    analysis['iocs']['ips'].append(conn.get('ip', conn.get('host', 'unknown')))

            if dns_queries:
                analysis['factors']['neutral'].append(f'DNS queries: {len(dns_queries)}')
                for query in dns_queries[:5]:
                    domain = query.get('domain', query) if isinstance(query, dict) else query
                    analysis['iocs']['domains'].append(domain)

        # Analyze process tree
        if processes:
            suspicious_processes = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'regsvr32.exe']
            for proc in processes:
                proc_name = proc.get('name', '').lower()
                if any(sp in proc_name for sp in suspicious_processes):
                    threat_score += 15
                    analysis['factors']['negative'].append(f'Suspicious child process: {proc_name}')
                    analysis['mitreAttacks'].append({'id': 'T1059', 'name': 'Command Scripting', 'severity': 'high'})

        # Analyze behaviors
        if behaviors:
            for behavior in behaviors:
                if isinstance(behavior, dict):
                    desc = behavior.get('description', '').lower()
                elif isinstance(behavior, str):
                    desc = behavior.lower()
                else:
                    continue

                if 'registry' in desc and ('run' in desc or 'startup' in desc):
                    threat_score += 20
                    analysis['factors']['negative'].append('Persistence via registry detected')
                    analysis['mitreAttacks'].append({'id': 'T1547', 'name': 'Boot/Logon Autostart', 'severity': 'high'})
                elif 'inject' in desc or 'hollow' in desc:
                    threat_score += 30
                    analysis['factors']['negative'].append('Process injection behavior detected')
                elif 'download' in desc:
                    threat_score += 10
                    analysis['factors']['negative'].append('Downloads additional content')

        # Analyze threat map if available
        if threat_map:
            for category, items in threat_map.items():
                if items and isinstance(items, list) and len(items) > 0:
                    for item in items:
                        severity = item.get('severity', 'medium')
                        if severity == 'critical':
                            threat_score += 25
                        elif severity == 'high':
                            threat_score += 15
                        elif severity == 'medium':
                            threat_score += 8

        # Imphash cluster analysis
        imphash_cluster = results.get('imphashCluster', {})
        if imphash_cluster and not imphash_cluster.get('error'):
            malicious_related = imphash_cluster.get('maliciousRelated', 0)
            total_related = imphash_cluster.get('totalRelated', 0)
            if malicious_related >= 3:
                threat_score += 20
                analysis['factors']['negative'].append(f'Imphash cluster: {malicious_related}/{total_related} related samples are malicious')
                analysis['mitreAttacks'].append({'id': 'T1027.002', 'name': 'Software Packing (shared imphash)', 'severity': 'high'})
            elif malicious_related >= 1:
                threat_score += 10
                analysis['factors']['negative'].append(f'Imphash cluster: {malicious_related} related malicious sample(s) found')
            elif total_related > 0:
                analysis['factors']['neutral'].append(f'Imphash cluster: {total_related} related samples, none flagged malicious')

        # YARA matches
        yara_matches = results.get('yaraMatches', [])
        if yara_matches:
            for match in yara_matches[:5]:
                rule_name = match.get('rule', 'Unknown')
                threat_score += 15
                analysis['factors']['negative'].append(f'YARA match: {rule_name}')

        # Check for clean indicators
        if not behaviors and not network.get('connections') and threat_score < 20:
            clean_score += 30
            analysis['factors']['positive'].append('No suspicious runtime behavior detected')

        if not processes or len(processes) <= 1:
            clean_score += 10
            analysis['factors']['positive'].append('No suspicious child processes')

        # Calculate final score
        final_score = max(0, min(100, threat_score - clean_score))

        # Adjust if original score differs significantly
        if abs(final_score - original_score) > 30:
            analysis['reasoning'].append(f'Score adjusted from {original_score} to {final_score} based on behavioral analysis')

        analysis['validatedScore'] = final_score

        # Determine risk level
        if final_score >= 80:
            analysis['validatedRiskLevel'] = 'Critical'
            analysis['recommendation'] = 'BLOCK IMMEDIATELY: High-confidence malware with dangerous capabilities'
        elif final_score >= 60:
            analysis['validatedRiskLevel'] = 'High'
            analysis['recommendation'] = 'QUARANTINE: Likely malicious, requires investigation'
        elif final_score >= 40:
            analysis['validatedRiskLevel'] = 'Medium'
            analysis['recommendation'] = 'INVESTIGATE: Suspicious indicators present'
        elif final_score >= 20:
            analysis['validatedRiskLevel'] = 'Low'
            analysis['recommendation'] = 'MONITOR: Minor suspicious indicators'
        else:
            analysis['validatedRiskLevel'] = 'Clean'
            analysis['recommendation'] = 'ALLOW: No significant threats detected'

        analysis['confidence'] = self._calculate_confidence(threat_score, clean_score, len(behaviors) + len(processes))

        return self._sanitize_analysis(analysis)

    def validate_file_analysis(self, results: Dict, file_type: str) -> Dict:
        """Validate risk for static file analysis (email, PDF, Office)"""
        original_score = results.get('riskScore', 0)

        analysis = {
            'originalScore': original_score,
            'validatedScore': original_score,
            'confidence': 0,
            'reasoning': [],
            'factors': {'positive': [], 'negative': [], 'neutral': []},
            'recommendation': '',
            'extractedThreats': []
        }

        threat_score = 0
        clean_score = 0

        if file_type == 'email':
            # Email-specific validation
            auth = results.get('authentication', {})
            links = results.get('links', [])
            attachments = results.get('attachments', [])

            # Check authentication
            if auth.get('spf') == 'pass' and auth.get('dkim') == 'pass' and auth.get('dmarc') == 'pass':
                clean_score += 20
                analysis['factors']['positive'].append('All email authentication passed (SPF/DKIM/DMARC)')
            else:
                if auth.get('spf') == 'fail':
                    threat_score += 15
                    analysis['factors']['negative'].append('SPF authentication failed')
                if auth.get('dmarc') == 'fail':
                    threat_score += 20
                    analysis['factors']['negative'].append('DMARC authentication failed')

            # Check for suspicious links
            for link in links:
                url = link.get('url', link) if isinstance(link, dict) else link
                if any(tld in url for tld in SUSPICIOUS_TLDS):
                    threat_score += 10
                    analysis['factors']['negative'].append(f'Suspicious TLD in link: {url[:50]}')

            # Check attachments
            dangerous_extensions = ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar']
            for att in attachments:
                name = att.get('filename', att) if isinstance(att, dict) else att
                if any(name.lower().endswith(ext) for ext in dangerous_extensions):
                    threat_score += 30
                    analysis['factors']['negative'].append(f'Dangerous attachment: {name}')
                    analysis['extractedThreats'].append({'type': 'attachment', 'name': name})

        elif file_type == 'pdf':
            # PDF-specific validation
            js_code = results.get('javascript', [])
            embedded = results.get('embeddedFiles', [])
            urls = results.get('urls', [])

            if js_code:
                threat_score += 25
                analysis['factors']['negative'].append(f'JavaScript detected in PDF ({len(js_code)} scripts)')

            if embedded:
                threat_score += 20
                analysis['factors']['negative'].append(f'Embedded files in PDF ({len(embedded)} files)')

            if not js_code and not embedded:
                clean_score += 20
                analysis['factors']['positive'].append('No JavaScript or embedded files')

        elif file_type == 'office':
            # Office document validation
            macros = results.get('macros', {})
            vba_code = results.get('vbaCode', [])

            if macros.get('hasMacros') or vba_code:
                threat_score += 20
                analysis['factors']['negative'].append('Document contains macros')

                # Check for suspicious macro patterns
                macro_code = ' '.join(vba_code) if vba_code else ''
                suspicious_patterns = ['Shell', 'CreateObject', 'WScript', 'PowerShell', 'Environ', 'URLDownloadToFile']
                for pattern in suspicious_patterns:
                    if pattern.lower() in macro_code.lower():
                        threat_score += 15
                        analysis['factors']['negative'].append(f'Suspicious macro pattern: {pattern}')
            else:
                clean_score += 20
                analysis['factors']['positive'].append('No macros detected')

        # Calculate final score
        final_score = max(0, min(100, original_score + threat_score - clean_score))
        analysis['validatedScore'] = final_score
        analysis['confidence'] = self._calculate_confidence(threat_score, clean_score, 5)

        # Generate recommendation
        if final_score >= 70:
            analysis['recommendation'] = 'HIGH RISK: Do not open this file'
        elif final_score >= 40:
            analysis['recommendation'] = 'CAUTION: Review carefully before opening'
        else:
            analysis['recommendation'] = 'LOW RISK: File appears safe'

        return self._sanitize_analysis(analysis)

    def _cross_correlate_findings(self, analysis: Dict, results: Dict, ioc_type: str) -> Dict:
        """Cross-correlate findings across sources for confidence enrichment"""
        sources = results.get('sources', {})
        confidence_boost = 0

        if ioc_type == 'hash':
            # Hash: malware family agreement across VT + MalwareBazaar
            vt_family = None
            mb_family = None
            vt_src = sources.get('virustotal', {})
            mb_src = sources.get('malwarebazaar', {})

            if vt_src.get('popularThreatName'):
                vt_family = vt_src['popularThreatName'].lower()
            elif vt_src.get('suggestedThreatLabel'):
                vt_family = vt_src['suggestedThreatLabel'].lower()

            if mb_src.get('signature'):
                mb_family = mb_src['signature'].lower()

            if vt_family and mb_family:
                # Check if family names partially match
                if vt_family in mb_family or mb_family in vt_family or any(
                    part in vt_family for part in mb_family.split('.') if len(part) > 3
                ):
                    confidence_boost += 15
                    analysis['reasoning'].append(f'Cross-correlation: VT and MalwareBazaar agree on malware family')

        elif ioc_type == 'ip':
            # IP: temporal analysis — stale AbuseIPDB reports reduce threat weight
            abuse_src = sources.get('abuseipdb', {})
            last_reported = abuse_src.get('lastReported')
            if last_reported and abuse_src.get('abuseScore', 0) > 0:
                try:
                    from datetime import datetime as _dt
                    last_dt = _dt.fromisoformat(last_reported.replace('Z', '+00:00').replace('+00:00', ''))
                    days_since = (_dt.now() - last_dt).days
                    if days_since > 180:
                        confidence_boost -= 10
                        analysis['factors']['positive'].append(f'AbuseIPDB: Last report was {days_since} days ago (stale)')
                        analysis['falsePositiveIndicators'].append(f'Last abuse report is {days_since} days old')
                except (ValueError, TypeError):
                    pass

        elif ioc_type == 'url':
            # URL: AITM + new domain + suspicious TLD = compound critical
            aitm = results.get('aitmDetection', {})
            whois = results.get('whois', {})
            domain = results.get('domain', '')

            has_aitm = aitm.get('detected', False)
            is_new_domain = (whois.get('domainAge', {}).get('days', 999) < 30) if whois and not whois.get('error') else False
            has_suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)

            compound_count = sum([has_aitm, is_new_domain, has_suspicious_tld])
            if compound_count >= 3:
                confidence_boost += 20
                analysis['reasoning'].append('Cross-correlation: AITM + new domain + suspicious TLD — critical compound signal')
            elif compound_count == 2:
                confidence_boost += 10
                analysis['reasoning'].append('Cross-correlation: Multiple suspicious URL indicators detected')

        # Universal: 3+ independent sources flagging malicious
        malicious_source_count = sum(1 for ti in analysis.get('threatIndicators', [])
                                     if ti.get('severity') in ('high', 'critical'))
        if malicious_source_count >= 3:
            confidence_boost += 10
            analysis['reasoning'].append(f'Cross-correlation: {malicious_source_count} independent sources flag as malicious')

        # Apply confidence boost
        if confidence_boost != 0:
            current_confidence = analysis.get('confidence', 50)
            analysis['confidence'] = max(0, min(100, current_confidence + confidence_boost))
            current_score = analysis.get('validatedScore', 0)
            if confidence_boost > 0 and analysis.get('validatedMalicious'):
                analysis['validatedScore'] = min(100, current_score + confidence_boost // 2)
            elif confidence_boost < 0:
                analysis['validatedScore'] = max(0, current_score + confidence_boost)

        return analysis

    def _calculate_consensus_score(self, analysis: Dict, clean_sources: int, threat_sources: int, total: int) -> Dict:
        """Calculate risk score based on source consensus"""
        # Check for false positive indicators
        has_fp_indicators = len(analysis.get('falsePositiveIndicators', [])) > 0
        fp_boost = len(analysis.get('falsePositiveIndicators', [])) * 10  # Each FP indicator reduces score

        if threat_sources == 0 and clean_sources > 0:
            # All sources clean
            analysis['validatedScore'] = 0
            analysis['validatedMalicious'] = False
            analysis['confidence'] = min(95, 60 + (clean_sources * 5))
            analysis['recommendation'] = 'SAFE: No threats detected across all sources'
            analysis['reasoning'].append('All consulted sources report clean')

        elif threat_sources == 0 and clean_sources == 0 and has_fp_indicators:
            # No strong signals but false positive indicators present
            analysis['validatedScore'] = max(0, min(20, analysis['originalScore'] // 4))
            analysis['validatedMalicious'] = False
            analysis['confidence'] = 65
            analysis['recommendation'] = 'LIKELY SAFE: Low detection count suggests false positive'
            analysis['reasoning'].append('Very low detection count with false positive indicators')

        elif threat_sources > 0 and clean_sources == 0 and not has_fp_indicators:
            # All sources flag as threat, no FP indicators
            analysis['validatedScore'] = min(100, 40 + (threat_sources * 15))
            analysis['validatedMalicious'] = True
            analysis['confidence'] = min(95, 60 + (threat_sources * 10))
            analysis['recommendation'] = 'BLOCK: Multiple sources confirm threat'
            analysis['reasoning'].append('Multiple sources confirm malicious activity')

        elif threat_sources >= clean_sources and threat_sources >= 2 and not has_fp_indicators:
            # More threat signals than clean
            analysis['validatedScore'] = min(90, 30 + (threat_sources * 12))
            analysis['validatedMalicious'] = True
            analysis['confidence'] = 50 + (threat_sources * 5)
            analysis['recommendation'] = 'INVESTIGATE: Majority of sources flag as suspicious'
            analysis['reasoning'].append('Threat indicators outweigh clean signals')

        elif threat_sources == 1 and clean_sources >= 2:
            # Single threat source vs multiple clean - likely false positive
            analysis['validatedScore'] = max(0, min(20, analysis['originalScore'] // 4) - fp_boost)
            analysis['validatedMalicious'] = False
            analysis['confidence'] = 75
            analysis['recommendation'] = 'LIKELY SAFE: Single detection contradicted by multiple clean sources'
            analysis['reasoning'].append('Single-source detection with multiple clean signals suggests false positive')

        elif threat_sources == 1 and has_fp_indicators:
            # Single flag with false positive indicators
            analysis['validatedScore'] = max(0, min(25, analysis['originalScore'] // 3) - fp_boost)
            analysis['validatedMalicious'] = False
            analysis['confidence'] = 70
            analysis['recommendation'] = 'LIKELY SAFE: Single detection with false positive indicators'
            analysis['reasoning'].append('Single detection with characteristics of false positive')

        elif threat_sources == 1:
            # Single flag, no strong clean signals, no FP indicators
            analysis['validatedScore'] = min(40, 20 + (analysis['originalScore'] // 4))
            analysis['validatedMalicious'] = False
            analysis['confidence'] = 50
            analysis['recommendation'] = 'REVIEW: Single suspicious indicator requires investigation'
            analysis['reasoning'].append('Isolated detection requires manual review')

        elif has_fp_indicators and clean_sources > threat_sources:
            # More clean than threats with FP indicators
            analysis['validatedScore'] = max(0, min(15, analysis['originalScore'] // 5))
            analysis['validatedMalicious'] = False
            analysis['confidence'] = 70
            analysis['recommendation'] = 'LIKELY SAFE: Clean signals outweigh threats with false positive indicators'
            analysis['reasoning'].append('Multiple clean sources with false positive indicators detected')

        else:
            # Default to original with slight reduction if FP indicators
            if has_fp_indicators:
                analysis['validatedScore'] = max(0, analysis['originalScore'] - fp_boost)
                analysis['confidence'] = 50
                analysis['reasoning'].append('False positive indicators detected but inconclusive assessment')
            else:
                analysis['confidence'] = 40
                analysis['reasoning'].append('Insufficient data for confident assessment')

        return analysis

    def _calculate_confidence(self, threat_score: int, clean_score: int, data_points: int) -> int:
        """Calculate confidence level based on available data"""
        base_confidence = min(50, data_points * 5)

        if threat_score > 50 and clean_score < 10:
            return min(95, base_confidence + 40)
        elif clean_score > 30 and threat_score < 10:
            return min(95, base_confidence + 35)
        elif abs(threat_score - clean_score) > 30:
            return min(85, base_confidence + 25)
        else:
            return min(70, base_confidence + 15)

    def _get_mitre_technique(self, indicator: str) -> Optional[Dict]:
        """Get MITRE ATT&CK technique for an indicator"""
        for tech_id, tech_info in MITRE_PATTERNS.items():
            if any(ind.lower() in indicator.lower() for ind in tech_info['indicators']):
                return {
                    'id': tech_id,
                    'name': tech_info['name'],
                    'severity': tech_info['severity']
                }
        return None


# Singleton instance
_validator = None

def get_validator() -> AIRiskValidator:
    """Get singleton AI validator instance"""
    global _validator
    if _validator is None:
        _validator = AIRiskValidator()
    return _validator


def validate_ip(results: Dict) -> Dict:
    """Convenience function to validate IP risk"""
    return get_validator().validate_ip_risk(results)


def validate_url(results: Dict) -> Dict:
    """Convenience function to validate URL risk"""
    return get_validator().validate_url_risk(results)


def validate_hash(results: Dict) -> Dict:
    """Convenience function to validate hash risk"""
    return get_validator().validate_hash_risk(results)


def validate_sandbox(results: Dict) -> Dict:
    """Convenience function to validate sandbox risk"""
    return get_validator().validate_sandbox_risk(results)


def validate_file(results: Dict, file_type: str) -> Dict:
    """Convenience function to validate file analysis risk"""
    return get_validator().validate_file_analysis(results, file_type)
