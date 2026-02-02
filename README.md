# IP Lookup

A web application to lookup IP address details including geolocation, network info, and threat intelligence.

## Features

- **Auto-detect visitor's IP** - Automatically shows your public IP
- **Manual IP lookup** - Enter any IP address to analyze
- **Geolocation** - Country, city, region, coordinates, timezone
- **Network info** - ISP, organization, ASN, hostname
- **Threat Intelligence** - Abuse score (0-100), attack categories, recent reports
- **Interactive map** - Shows IP location on OpenStreetMap
- **Modern UI** - Dark theme, responsive design

## Screenshots

The threat score provides a visual gauge from 0-100:
- **0-24**: Low risk (green)
- **25-49**: Medium risk (yellow)
- **50-74**: High risk (orange)
- **75-100**: Critical risk (red)

## Setup

### Requirements
- Python 3.x (no external dependencies)

### Run the server

```bash
python3 server.py
```

Open http://localhost:3000 in your browser.

### Enable Threat Intelligence (Optional)

Get a free API key from [AbuseIPDB](https://www.abuseipdb.com/account/api) and run:

```bash
ABUSEIPDB_API_KEY="your-api-key" python3 server.py
```

Free tier: 1,000 lookups/day

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/my-ip` | Returns visitor's IP address |
| `GET /api/lookup/:ip` | Returns full details for an IP |

## Data Sources

- **Geolocation**: [ip-api.com](http://ip-api.com)
- **Threat Intelligence**: [AbuseIPDB](https://www.abuseipdb.com)

## License

MIT
