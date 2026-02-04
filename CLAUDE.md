# ShieldTier - Threat Intelligence Platform

## Project Overview
- **Name:** ShieldTier (Powered by MTI)
- **Domain:** www.shieldtier.com
- **Repository:** https://github.com/dillida-cmd/Threatintell

## Tech Stack
- **Backend:** Python 3 (server.py)
- **Frontend:** React + TypeScript + Vite + Tailwind
- **Database:** SQLite (analysis_results.db)
- **Reverse Proxy:** Nginx with Cloudflare Origin Certificate

## Key Features
- IP/URL/Hash threat intelligence lookups
- Email, PDF, Office file analysis
- Sandbox analysis (bubblewrap)
- Screenshot capture (Chromium)
- Encrypted PDF export with defanging
- 15-day data retention

## File Limits
- **Upload:** 15MB max
- **Sandbox:** 50MB max

## API Keys Configuration
- **File:** `api_keys.json`
- **Services:**
  - VirusTotal
  - AbuseIPDB
  - GreyNoise
  - Shodan
  - AlienVault OTX
  - IPQualityScore
  - URLhaus (abuse.ch)
  - ThreatFox (abuse.ch)

## Deployment

### Quick Install on New Server
```bash
curl -sSL "https://raw.githubusercontent.com/dillida-cmd/Threatintell/master/install.sh?$(date +%s)" | sudo bash -s www.shieldtier.com
```

### Copy API Keys to New Server
```bash
scp /home/kali/Desktop/Claude/ip-lookup/api_keys.json user@SERVER_IP:/opt/shieldtier/app/
sudo chown shieldtier:shieldtier /opt/shieldtier/app/api_keys.json
sudo chmod 600 /opt/shieldtier/app/api_keys.json
```

### Cloudflare Setup
1. Create Origin Certificate: SSL/TLS → Origin Server → Create
2. Save to `/etc/nginx/ssl/cloudflare-origin.pem` and `.key`
3. DNS: A record → Server IP → Proxied (orange cloud)
4. SSL mode: Full (strict)

### Update Server
```bash
cd /opt/shieldtier/app && sudo -u shieldtier git pull && sudo systemctl restart shieldtier
```

### Rebuild Frontend
```bash
cd /opt/shieldtier/app/frontend
sudo -u shieldtier npm run build
sudo systemctl restart shieldtier
```

## Server Paths
- **App:** `/opt/shieldtier/app`
- **Data:** `/opt/shieldtier/data`
- **Logs:** `/var/log/shieldtier/`
- **SSL:** `/etc/nginx/ssl/`
- **Nginx:** `/etc/nginx/sites-available/shieldtier`

## Service Commands
```bash
sudo systemctl status shieldtier
sudo systemctl restart shieldtier
sudo journalctl -u shieldtier -f
```

## Security
- UFW firewall allows only Cloudflare IPs on 80/443
- All URLs/IPs/emails defanged in PDF exports
- PDF reports encrypted with user's secret key

## Testing
```bash
# Run all tests
python3 /tmp/run_tests.py

# Quick status check
curl -s http://localhost:3000/api/status
```
