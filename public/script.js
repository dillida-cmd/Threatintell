document.addEventListener('DOMContentLoaded', () => {
  const ipInput = document.getElementById('ip-input');
  const lookupBtn = document.getElementById('lookup-btn');
  const lookupMyIpBtn = document.getElementById('lookup-my-ip');
  const visitorIpEl = document.getElementById('visitor-ip');
  const resultsEl = document.getElementById('results');
  const errorEl = document.getElementById('error');
  const loadingEl = document.getElementById('loading');

  // Fetch visitor's IP on page load
  fetchVisitorIP();

  // Event listeners
  lookupBtn.addEventListener('click', () => {
    const ip = ipInput.value.trim();
    if (ip) {
      lookupIP(ip);
    }
  });

  ipInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      const ip = ipInput.value.trim();
      if (ip) {
        lookupIP(ip);
      }
    }
  });

  lookupMyIpBtn.addEventListener('click', () => {
    lookupIP();
  });

  async function fetchVisitorIP() {
    try {
      const response = await fetch('/api/my-ip');
      const data = await response.json();
      visitorIpEl.textContent = data.ip;
    } catch (error) {
      visitorIpEl.textContent = 'Unable to detect';
    }
  }

  async function lookupIP(ip = '') {
    showLoading();

    try {
      const url = ip ? `/api/lookup/${encodeURIComponent(ip)}` : '/api/lookup';
      const response = await fetch(url);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Lookup failed');
      }

      displayResults(data);
    } catch (error) {
      showError(error.message);
    }
  }

  function showLoading() {
    resultsEl.classList.add('hidden');
    errorEl.classList.add('hidden');
    loadingEl.classList.remove('hidden');
  }

  function showError(message) {
    loadingEl.classList.add('hidden');
    resultsEl.classList.add('hidden');
    errorEl.classList.remove('hidden');
    errorEl.textContent = message;
  }

  function displayResults(data) {
    loadingEl.classList.add('hidden');
    errorEl.classList.add('hidden');
    resultsEl.classList.remove('hidden');

    // Set IP and flag
    document.getElementById('result-ip').textContent = data.ip;
    document.getElementById('country-flag').textContent = countryCodeToFlag(data.location.countryCode);

    // Location info
    const locationInfo = document.getElementById('location-info');
    locationInfo.innerHTML = `
      ${infoRow('Country', `${data.location.country} (${data.location.countryCode})`)}
      ${infoRow('Region', `${data.location.region} (${data.location.regionCode})`)}
      ${infoRow('City', data.location.city)}
      ${data.location.district ? infoRow('District', data.location.district) : ''}
      ${infoRow('ZIP Code', data.location.zipCode || 'N/A')}
      ${infoRow('Continent', `${data.location.continent} (${data.location.continentCode})`)}
      ${infoRow('Coordinates', `${data.location.latitude}, ${data.location.longitude}`)}
      ${infoRow('Timezone', data.location.timezone)}
      ${infoRow('Currency', data.currency || 'N/A')}
    `;

    // Network info
    const networkInfo = document.getElementById('network-info');
    networkInfo.innerHTML = `
      ${infoRow('ISP', data.network.isp)}
      ${infoRow('Organization', data.network.organization)}
      ${infoRow('AS Number', data.network.asn)}
      ${infoRow('AS Name', data.network.asName)}
      ${infoRow('Hostname', data.network.hostname || 'N/A')}
    `;

    // Security info
    const securityInfo = document.getElementById('security-info');
    securityInfo.innerHTML = `
      ${infoRow('Mobile Network', badge(!data.security.isMobile, data.security.isMobile ? 'Yes' : 'No'))}
      ${infoRow('Proxy/VPN', badge(!data.security.isProxy, data.security.isProxy ? 'Detected' : 'Not Detected'))}
      ${infoRow('Hosting/DC', badge(!data.security.isHosting, data.security.isHosting ? 'Yes' : 'No'))}
    `;

    // Threat Intelligence
    displayThreatInfo(data.threat);

    // Update map
    const mapFrame = document.getElementById('map-frame');
    mapFrame.src = `https://www.openstreetmap.org/export/embed.html?bbox=${data.location.longitude - 0.1},${data.location.latitude - 0.1},${data.location.longitude + 0.1},${data.location.latitude + 0.1}&layer=mapnik&marker=${data.location.latitude},${data.location.longitude}`;
  }

  function infoRow(label, value) {
    return `
      <div class="info-row">
        <span class="info-label">${label}</span>
        <span class="info-value">${value}</span>
      </div>
    `;
  }

  function badge(isSafe, text) {
    const className = isSafe ? 'badge-safe' : 'badge-warning';
    return `<span class="badge ${className}">${text}</span>`;
  }

  function countryCodeToFlag(countryCode) {
    if (!countryCode) return '';
    const codePoints = countryCode
      .toUpperCase()
      .split('')
      .map(char => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
  }

  function displayThreatInfo(threat) {
    const threatSection = document.getElementById('threat-section');
    const scoreCircle = document.getElementById('score-circle');
    const scoreValue = document.getElementById('score-value');
    const riskLevel = document.getElementById('risk-level');
    const threatSummary = document.getElementById('threat-summary');
    const threatInfo = document.getElementById('threat-info');
    const categoriesCard = document.getElementById('categories-card');
    const categoriesInfo = document.getElementById('categories-info');
    const reportsCard = document.getElementById('reports-card');
    const reportsInfo = document.getElementById('reports-info');

    if (!threat.apiConfigured) {
      threatSection.style.display = 'none';
      categoriesCard.style.display = 'none';
      reportsCard.style.display = 'none';
      threatInfo.innerHTML = `
        <div class="api-notice">
          Threat intelligence requires an AbuseIPDB API key.<br>
          <a href="https://www.abuseipdb.com/account/api" target="_blank">Get a free API key</a> and set it as ABUSEIPDB_API_KEY environment variable.
        </div>
      `;
      return;
    }

    threatSection.style.display = 'block';

    // Update score circle
    const score = threat.abuseScore || 0;
    let scoreColor;
    let riskClass;

    if (score >= 75) {
      scoreColor = '#ff5252';
      riskClass = 'risk-critical';
    } else if (score >= 50) {
      scoreColor = '#ff9800';
      riskClass = 'risk-high';
    } else if (score >= 25) {
      scoreColor = '#ffc107';
      riskClass = 'risk-medium';
    } else {
      scoreColor = '#00c853';
      riskClass = 'risk-low';
    }

    scoreCircle.style.setProperty('--score-percent', score);
    scoreCircle.style.setProperty('--score-color', scoreColor);
    scoreValue.textContent = score;
    scoreValue.style.color = scoreColor;

    riskLevel.textContent = `${threat.riskLevel} Risk`;
    riskLevel.className = `risk-level ${riskClass}`;

    // Threat summary stats
    threatSummary.innerHTML = `
      <div class="threat-stat">
        <div class="threat-stat-value">${threat.totalReports || 0}</div>
        <div class="threat-stat-label">Total Reports</div>
      </div>
      <div class="threat-stat">
        <div class="threat-stat-value">${threat.numDistinctUsers || 0}</div>
        <div class="threat-stat-label">Reporters</div>
      </div>
      <div class="threat-stat">
        <div class="threat-stat-value">${threat.lastReported ? formatDate(threat.lastReported) : 'Never'}</div>
        <div class="threat-stat-label">Last Reported</div>
      </div>
    `;

    // Threat info card
    threatInfo.innerHTML = `
      ${infoRow('Abuse Score', threatBadge(score))}
      ${infoRow('Total Reports', threat.totalReports || 0)}
      ${infoRow('Distinct Reporters', threat.numDistinctUsers || 0)}
      ${infoRow('Last Reported', threat.lastReported ? formatDateTime(threat.lastReported) : 'Never')}
      ${infoRow('Whitelisted', badge(threat.isWhitelisted, threat.isWhitelisted ? 'Yes' : 'No'))}
      ${infoRow('Tor Exit Node', badge(!threat.isTor, threat.isTor ? 'Yes' : 'No'))}
      ${infoRow('Usage Type', threat.usageType || 'Unknown')}
      ${threat.domain ? infoRow('Domain', threat.domain) : ''}
    `;

    // Categories card
    if (threat.categories && threat.categories.length > 0) {
      categoriesCard.style.display = 'block';
      categoriesInfo.innerHTML = `
        <div class="category-tags">
          ${threat.categories.map(cat => `<span class="category-tag">${cat}</span>`).join('')}
        </div>
      `;
    } else {
      categoriesCard.style.display = 'block';
      categoriesInfo.innerHTML = `<div class="no-threat">No attack categories reported</div>`;
    }

    // Recent reports card
    if (threat.recentReports && threat.recentReports.length > 0) {
      reportsCard.style.display = 'block';
      reportsInfo.innerHTML = threat.recentReports.slice(0, 5).map(report => `
        <div class="report-item">
          <div class="report-date">${formatDateTime(report.date)}</div>
          ${report.comment ? `<div class="report-comment">${escapeHtml(report.comment)}</div>` : ''}
          ${report.categories.length > 0 ? `
            <div class="report-categories">
              ${report.categories.map(cat => `<span class="category-tag">${cat}</span>`).join('')}
            </div>
          ` : ''}
        </div>
      `).join('');
    } else {
      reportsCard.style.display = 'block';
      reportsInfo.innerHTML = `<div class="no-threat">No recent abuse reports</div>`;
    }
  }

  function threatBadge(score) {
    let className, text;
    if (score >= 75) {
      className = 'badge-danger';
      text = `${score} - Critical`;
    } else if (score >= 50) {
      className = 'badge-warning';
      text = `${score} - High`;
    } else if (score >= 25) {
      className = 'badge-warning';
      text = `${score} - Medium`;
    } else {
      className = 'badge-safe';
      text = `${score} - Low`;
    }
    return `<span class="badge ${className}">${text}</span>`;
  }

  function formatDate(dateStr) {
    if (!dateStr) return 'N/A';
    const date = new Date(dateStr);
    return date.toLocaleDateString();
  }

  function formatDateTime(dateStr) {
    if (!dateStr) return 'N/A';
    const date = new Date(dateStr);
    return date.toLocaleString();
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
});
