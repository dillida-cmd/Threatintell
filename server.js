const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// Get client's real IP address
function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket.remoteAddress?.replace('::ffff:', '') || '127.0.0.1';
}

// API endpoint to get visitor's IP
app.get('/api/my-ip', (req, res) => {
  const ip = getClientIP(req);
  res.json({ ip });
});

// API endpoint to lookup IP details
app.get('/api/lookup/:ip?', async (req, res) => {
  try {
    let ip = req.params.ip || getClientIP(req);

    // Handle localhost/private IPs for testing
    if (ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.') || ip.startsWith('10.')) {
      ip = ''; // ip-api.com returns requester's public IP when empty
    }

    const apiUrl = `http://ip-api.com/json/${ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query`;

    const response = await fetch(apiUrl);
    const data = await response.json();

    if (data.status === 'fail') {
      return res.status(400).json({ error: data.message || 'Invalid IP address' });
    }

    res.json({
      ip: data.query,
      location: {
        continent: data.continent,
        continentCode: data.continentCode,
        country: data.country,
        countryCode: data.countryCode,
        region: data.regionName,
        regionCode: data.region,
        city: data.city,
        district: data.district,
        zipCode: data.zip,
        latitude: data.lat,
        longitude: data.lon,
        timezone: data.timezone,
        utcOffset: data.offset
      },
      network: {
        isp: data.isp,
        organization: data.org,
        asn: data.as,
        asName: data.asname,
        hostname: data.reverse
      },
      security: {
        isMobile: data.mobile,
        isProxy: data.proxy,
        isHosting: data.hosting
      },
      currency: data.currency
    });
  } catch (error) {
    console.error('Lookup error:', error);
    res.status(500).json({ error: 'Failed to fetch IP information' });
  }
});

app.listen(PORT, () => {
  console.log(`IP Lookup server running at http://localhost:${PORT}`);
});
