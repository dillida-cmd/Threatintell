#!/usr/bin/env python3
"""IP Lookup Website Server"""

from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
import urllib.request
import urllib.error
import os

PORT = 3000

# Get free API key from https://www.abuseipdb.com/account/api
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')

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

def check_abuse_ipdb(ip):
    """Check IP against AbuseIPDB for threat intelligence"""
    if not ABUSEIPDB_API_KEY:
        return None

    try:
        url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose=true'
        req = urllib.request.Request(url, headers={
            'Key': ABUSEIPDB_API_KEY,
            'Accept': 'application/json'
        })
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            return data.get('data')
    except Exception as e:
        print(f"AbuseIPDB error: {e}")
        return None


class IPLookupHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=os.path.join(os.path.dirname(__file__), 'public'), **kwargs)

    def do_GET(self):
        if self.path == '/api/my-ip':
            self.handle_my_ip()
        elif self.path.startswith('/api/lookup'):
            self.handle_lookup()
        else:
            super().do_GET()

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


def main():
    server = HTTPServer(('0.0.0.0', PORT), IPLookupHandler)
    print(f"IP Lookup server running at http://localhost:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.shutdown()


if __name__ == '__main__':
    main()
