document.addEventListener('DOMContentLoaded', () => {
  // IP Lookup elements
  const ipInput = document.getElementById('ip-input');
  const lookupBtn = document.getElementById('lookup-btn');
  const lookupMyIpBtn = document.getElementById('lookup-my-ip');
  const visitorIpEl = document.getElementById('visitor-ip');
  const resultsEl = document.getElementById('results');
  const errorEl = document.getElementById('error');
  const loadingEl = document.getElementById('loading');

  // Navigation tabs
  const navTabs = document.querySelectorAll('.nav-tab');
  const tabContents = document.querySelectorAll('.tab-content');

  // Sandbox elements
  const sandboxResults = document.getElementById('sandbox-results');
  const sandboxError = document.getElementById('sandbox-error');
  const sandboxLoading = document.getElementById('sandbox-loading');
  const clearResultsBtn = document.getElementById('clear-results-btn');
  const entryRefCard = document.getElementById('entry-ref-card');

  // Retrieve elements
  const retrieveEntryRef = document.getElementById('retrieve-entry-ref');
  const retrieveSecretKey = document.getElementById('retrieve-secret-key');
  const retrieveBtn = document.getElementById('retrieve-btn');

  // File inputs and upload zones
  const uploadConfigs = [
    { type: 'email', extensions: ['.eml'], maxSize: 10 * 1024 * 1024 },
    { type: 'pdf', extensions: ['.pdf'], maxSize: 10 * 1024 * 1024 },
    { type: 'office', extensions: ['.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx', '.pptm'], maxSize: 10 * 1024 * 1024 }
  ];

  // Store selected files
  const selectedFiles = {
    email: null,
    pdf: null,
    office: null
  };

  // Minimum secret key length
  const MIN_SECRET_KEY_LENGTH = 8;

  // Initialize
  fetchVisitorIP();
  setupNavigation();
  setupUploadZones();
  setupRetrieve();

  // Tab navigation
  function setupNavigation() {
    navTabs.forEach(tab => {
      tab.addEventListener('click', () => {
        const targetTab = tab.dataset.tab;

        navTabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');

        tabContents.forEach(content => {
          content.classList.remove('active');
          if (content.id === `${targetTab}-section`) {
            content.classList.add('active');
          }
        });
      });
    });
  }

  // Setup upload zones with drag-and-drop
  function setupUploadZones() {
    uploadConfigs.forEach(config => {
      const zone = document.getElementById(`${config.type}-upload-zone`);
      const fileInput = document.getElementById(`${config.type}-file-input`);
      const fileName = document.getElementById(`${config.type}-file-name`);
      const analyzeBtn = document.getElementById(`${config.type}-analyze-btn`);
      const secretKeyInput = document.getElementById(`${config.type}-secret-key`);

      // Click to browse
      zone.addEventListener('click', () => fileInput.click());

      // Drag and drop
      zone.addEventListener('dragover', (e) => {
        e.preventDefault();
        zone.classList.add('drag-over');
      });

      zone.addEventListener('dragleave', () => {
        zone.classList.remove('drag-over');
      });

      zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('drag-over');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
          handleFileSelect(files[0], config.type);
        }
      });

      // File input change
      fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
          handleFileSelect(e.target.files[0], config.type);
        }
      });

      // Secret key validation - enable/disable analyze button
      secretKeyInput.addEventListener('input', () => {
        updateAnalyzeButton(config.type);
      });

      // Analyze button
      analyzeBtn.addEventListener('click', () => {
        const secretKey = secretKeyInput.value;
        if (selectedFiles[config.type] && secretKey.length >= MIN_SECRET_KEY_LENGTH) {
          analyzeFile(config.type, selectedFiles[config.type], secretKey);
        }
      });
    });

    // Clear results button
    clearResultsBtn.addEventListener('click', () => {
      sandboxResults.classList.add('hidden');
      entryRefCard.classList.add('hidden');
      document.getElementById('sandbox-cards').innerHTML = '';
    });

    // Copy entry reference button
    document.getElementById('copy-entry-ref').addEventListener('click', () => {
      const entryRef = document.getElementById('entry-ref-value').textContent;
      navigator.clipboard.writeText(entryRef).then(() => {
        const btn = document.getElementById('copy-entry-ref');
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => {
          btn.textContent = originalText;
        }, 2000);
      });
    });
  }

  // Setup retrieve functionality
  function setupRetrieve() {
    retrieveBtn.addEventListener('click', retrieveResults);

    // Allow Enter key to trigger retrieve
    retrieveEntryRef.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') retrieveResults();
    });
    retrieveSecretKey.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') retrieveResults();
    });
  }

  // Update analyze button state
  function updateAnalyzeButton(type) {
    const secretKeyInput = document.getElementById(`${type}-secret-key`);
    const analyzeBtn = document.getElementById(`${type}-analyze-btn`);
    const hasFile = selectedFiles[type] !== null;
    const hasValidKey = secretKeyInput.value.length >= MIN_SECRET_KEY_LENGTH;
    analyzeBtn.disabled = !(hasFile && hasValidKey);
  }

  function handleFileSelect(file, type) {
    const config = uploadConfigs.find(c => c.type === type);
    const fileName = document.getElementById(`${type}-file-name`);
    const zone = document.getElementById(`${type}-upload-zone`);

    // Validate file extension
    const ext = '.' + file.name.split('.').pop().toLowerCase();
    if (!config.extensions.includes(ext)) {
      showSandboxError(`Invalid file type. Expected: ${config.extensions.join(', ')}`);
      return;
    }

    // Validate file size
    if (file.size > config.maxSize) {
      showSandboxError('File too large. Maximum size is 10MB.');
      return;
    }

    // Store file and update UI
    selectedFiles[type] = file;
    fileName.textContent = file.name;
    zone.classList.add('has-file');

    // Update analyze button
    updateAnalyzeButton(type);
  }

  async function analyzeFile(type, file, secretKey) {
    showSandboxLoading();

    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('secretKey', secretKey);

      const response = await fetch(`/api/analyze/${type}`, {
        method: 'POST',
        body: formData
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Analysis failed');
      }

      displaySandboxResults(data, true);
    } catch (error) {
      showSandboxError(error.message);
    }
  }

  async function retrieveResults() {
    const entryRef = retrieveEntryRef.value.trim().toUpperCase();
    const secretKey = retrieveSecretKey.value;

    if (!entryRef) {
      showSandboxError('Please enter an entry reference (e.g., MSB0001)');
      return;
    }

    if (!secretKey) {
      showSandboxError('Please enter your secret key');
      return;
    }

    showSandboxLoading();

    try {
      const response = await fetch(`/api/results/${entryRef}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ secretKey })
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Failed to retrieve results');
      }

      // The retrieved data has results nested
      const results = {
        ...data.results,
        entryRef: data.entryRef,
        originalFilename: data.originalFilename,
        fileHash: data.fileHash,
        fileSize: data.fileSize,
        createdAt: data.createdAt,
        expiresAt: data.expiresAt,
        accessCount: data.accessCount
      };

      displaySandboxResults(results, false);
    } catch (error) {
      showSandboxError(error.message);
    }
  }

  function showSandboxLoading() {
    sandboxResults.classList.add('hidden');
    sandboxError.classList.add('hidden');
    sandboxLoading.classList.remove('hidden');
  }

  function showSandboxError(message) {
    sandboxLoading.classList.add('hidden');
    sandboxResults.classList.add('hidden');
    sandboxError.classList.remove('hidden');
    sandboxError.textContent = message;
  }

  function displaySandboxResults(data, showEntryCard) {
    sandboxLoading.classList.add('hidden');
    sandboxError.classList.add('hidden');
    sandboxResults.classList.remove('hidden');

    // Update title
    const typeNames = { email: 'Email', pdf: 'PDF', office: 'Office Document' };
    document.getElementById('sandbox-result-title').textContent = `${typeNames[data.type]} Analysis Results`;

    // Show entry reference card if this is a new analysis
    if (showEntryCard && data.entryRef) {
      entryRefCard.classList.remove('hidden');
      document.getElementById('entry-ref-value').textContent = data.entryRef;
      document.getElementById('entry-ref-expires').textContent = formatDateTime(data.expiresAt);
    } else {
      entryRefCard.classList.add('hidden');
    }

    // Update risk score
    updateRiskScore(data.riskScore, data.riskLevel, 'sandbox');

    // Display type-specific results
    const cardsContainer = document.getElementById('sandbox-cards');
    cardsContainer.innerHTML = '';

    // Add metadata card for retrieved results
    if (data.originalFilename || data.fileHash) {
      cardsContainer.innerHTML += createCard('File Information', `
        ${data.originalFilename ? infoRow('Original Filename', escapeHtml(data.originalFilename)) : ''}
        ${data.fileHash ? infoRow('File Hash (SHA-256)', `<code>${data.fileHash.substring(0, 16)}...</code>`) : ''}
        ${data.fileSize ? infoRow('File Size', formatBytes(data.fileSize)) : ''}
        ${data.createdAt ? infoRow('Analyzed', formatDateTime(data.createdAt)) : ''}
        ${data.expiresAt ? infoRow('Expires', formatDateTime(data.expiresAt)) : ''}
        ${data.accessCount ? infoRow('Access Count', data.accessCount) : ''}
      `);
    }

    if (data.type === 'email') {
      displayEmailResults(data, cardsContainer);
    } else if (data.type === 'pdf') {
      displayPdfResults(data, cardsContainer);
    } else if (data.type === 'office') {
      displayOfficeResults(data, cardsContainer);
    }
  }

  function updateRiskScore(score, level, prefix) {
    const scoreCircle = document.getElementById(`${prefix}-score-circle`);
    const scoreValue = document.getElementById(`${prefix}-score-value`);
    const riskLevel = document.getElementById(`${prefix}-risk-level`);

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

    riskLevel.textContent = `${level} Risk`;
    riskLevel.className = `risk-level ${riskClass}`;
  }

  function displayEmailResults(data, container) {
    // Headers card
    container.innerHTML += createCard('Email Headers', `
      ${infoRow('From', escapeHtml(data.headers.from))}
      ${infoRow('To', escapeHtml(data.headers.to))}
      ${infoRow('Subject', escapeHtml(data.headers.subject))}
      ${infoRow('Date', escapeHtml(data.headers.date))}
      ${data.headers.reply_to ? infoRow('Reply-To', escapeHtml(data.headers.reply_to)) : ''}
      ${infoRow('Message-ID', escapeHtml(data.headers.message_id) || 'N/A')}
    `);

    // Sender Domain Info (enriched)
    if (data.senderDomainInfo) {
      const domainInfo = data.senderDomainInfo;
      let domainContent = infoRow('Domain', escapeHtml(domainInfo.domain || data.senderDomain));

      if (domainInfo.whois) {
        const whois = domainInfo.whois;
        if (whois.registrar) domainContent += infoRow('Registrar', escapeHtml(whois.registrar));
        if (whois.creation_date) domainContent += infoRow('Created', formatDateTime(whois.creation_date));
        if (whois.domain_age_days !== null) {
          const ageBadge = whois.domain_age_days < 30
            ? `<span class="badge badge-danger">${whois.domain_age_days} days old (NEW)</span>`
            : `<span class="badge badge-safe">${whois.domain_age_days} days old</span>`;
          domainContent += infoRow('Domain Age', ageBadge);
        }
        if (whois.registrant_country) domainContent += infoRow('Registrant Country', escapeHtml(whois.registrant_country));
      }

      if (domainInfo.is_new_domain) {
        domainContent += `<div class="indicator-item high"><span class="indicator-desc">New domain - potential phishing risk</span></div>`;
      }

      container.innerHTML += createCard('Sender Domain', domainContent);
    }

    // Authentication card
    const authContent = `
      ${infoRow('SPF', authBadge(data.authentication.spf.status))}
      ${infoRow('DKIM', authBadge(data.authentication.dkim.status))}
      ${infoRow('DMARC', authBadge(data.authentication.dmarc.status))}
    `;
    container.innerHTML += createCard('Authentication', authContent);

    // Phishing Indicators card
    if (data.phishingIndicators.length > 0) {
      const indicatorsHtml = data.phishingIndicators.map(ind => `
        <div class="indicator-item ${ind.severity}">
          <span class="indicator-type">${formatIndicatorType(ind.type)}</span>
          <span class="indicator-desc">${escapeHtml(ind.description)}</span>
        </div>
      `).join('');
      container.innerHTML += createCard('Phishing Indicators', indicatorsHtml, 'warning-card');
    } else {
      container.innerHTML += createCard('Phishing Indicators', '<div class="no-threat">No phishing indicators detected</div>');
    }

    // Enriched URLs card
    if (data.enrichedUrls && data.enrichedUrls.length > 0) {
      const urlsHtml = data.enrichedUrls.slice(0, 10).map(enriched => {
        let urlContent = `<div class="enriched-url-item">
          <div class="url-item">${escapeHtml(enriched.url)}</div>`;

        if (enriched.domain) {
          urlContent += `<div class="url-detail"><span class="url-detail-label">Domain:</span> ${escapeHtml(enriched.domain)}</div>`;
        }

        if (enriched.dns && enriched.dns.ips && enriched.dns.ips.length > 0) {
          urlContent += `<div class="url-detail"><span class="url-detail-label">Resolved IPs:</span> ${enriched.dns.ips.join(', ')}</div>`;
        }

        if (enriched.ip_info && enriched.ip_info.length > 0) {
          const ipInfo = enriched.ip_info[0];
          if (ipInfo.country) {
            urlContent += `<div class="url-detail"><span class="url-detail-label">Location:</span> ${ipInfo.city || ''}, ${ipInfo.country}</div>`;
          }
          if (ipInfo.isp) {
            urlContent += `<div class="url-detail"><span class="url-detail-label">ISP:</span> ${escapeHtml(ipInfo.isp)}</div>`;
          }
        }

        if (enriched.threat_info && enriched.threat_info.length > 0) {
          const threat = enriched.threat_info[0];
          if (threat.abuse_score > 0) {
            urlContent += `<div class="url-detail threat-detail"><span class="url-detail-label">Threat Score:</span> <span class="badge badge-${threat.abuse_score > 50 ? 'danger' : 'warning'}">${threat.abuse_score}</span></div>`;
          }
        }

        if (enriched.download && enriched.download.is_download) {
          const dl = enriched.download;
          const riskBadge = dl.is_high_risk ? '<span class="badge badge-danger">HIGH RISK</span>' : '';
          urlContent += `<div class="url-detail download-detail"><span class="url-detail-label">Download Target:</span> ${escapeHtml(dl.target_filename)} ${riskBadge}</div>`;
        }

        urlContent += '</div>';
        return urlContent;
      }).join('');
      container.innerHTML += createCard(`Enriched URLs (${data.urlCount})`, urlsHtml);
    } else if (data.urlCount > 0) {
      const urlsHtml = data.urls.slice(0, 20).map(url => `
        <div class="url-item">${escapeHtml(url)}</div>
      `).join('');
      container.innerHTML += createCard(`URLs Found (${data.urlCount})`, urlsHtml);
    }

    // Attachments card
    if (data.attachmentCount > 0) {
      const attachHtml = data.attachments.map(att => `
        <div class="attachment-item ${att.isSuspicious ? 'suspicious' : ''}">
          <span class="attachment-name">${escapeHtml(att.filename)}</span>
          <span class="attachment-type">${att.contentType}</span>
          <span class="attachment-size">${formatBytes(att.size)}</span>
          ${att.isSuspicious ? '<span class="badge badge-danger">Suspicious</span>' : ''}
        </div>
      `).join('');
      container.innerHTML += createCard(`Attachments (${data.attachmentCount})`, attachHtml);
    }

    // QR Codes card
    if (data.qrCodes && data.qrCodes.length > 0) {
      displayQRCodes(data.qrCodes, container);
    }

    // Routing IPs with threat info
    if (data.routingIps && data.routingIps.length > 0) {
      const routingHtml = data.routingIps.map(routing => {
        let content = `<div class="routing-ip-item">
          <div class="routing-ip">${routing.ip}</div>`;

        if (routing.info) {
          const info = routing.info;
          if (info.country) content += `<span class="routing-detail">${info.city || ''}, ${info.country}</span>`;
          if (info.isp) content += `<span class="routing-detail">${escapeHtml(info.isp)}</span>`;
        }

        if (routing.threat && routing.threat.abuseConfidenceScore > 0) {
          content += `<span class="badge badge-${routing.threat.abuseConfidenceScore > 50 ? 'danger' : 'warning'}">Threat: ${routing.threat.abuseConfidenceScore}</span>`;
        }

        content += '</div>';
        return content;
      }).join('');
      container.innerHTML += createCard('Routing Path IPs', routingHtml);
    }

    // Routing path card (collapsed by default)
    if (data.routingPath.length > 0) {
      const routingHtml = data.routingPath.map((hop, i) => `
        <div class="routing-hop">
          <span class="hop-number">${i + 1}</span>
          <span class="hop-text">${escapeHtml(hop)}</span>
        </div>
      `).join('');
      container.innerHTML += createCard('Routing Path (Raw)', routingHtml);
    }
  }

  function displayPdfResults(data, container) {
    // Metadata card
    container.innerHTML += createCard('PDF Metadata', `
      ${infoRow('Title', data.metadata.title || 'N/A')}
      ${infoRow('Author', data.metadata.author || 'N/A')}
      ${infoRow('Creator', data.metadata.creator || 'N/A')}
      ${infoRow('Producer', data.metadata.producer || 'N/A')}
      ${infoRow('Pages', data.pageCount)}
      ${infoRow('Created', data.metadata.creationDate || 'N/A')}
      ${infoRow('Modified', data.metadata.modDate || 'N/A')}
    `);

    // Security Indicators card
    const indicatorsHtml = `
      ${infoRow('JavaScript', indicatorBadge(data.hasJavaScript, 'JavaScript detected', 'No JavaScript'))}
      ${infoRow('Embedded Files', indicatorBadge(data.hasEmbeddedFiles, 'Embedded files found', 'None'))}
      ${infoRow('External References', indicatorBadge(data.hasExternalRefs, 'External refs found', 'None'))}
      ${infoRow('Interactive Forms', indicatorBadge(data.hasForms, 'Forms present', 'None', true))}
    `;
    container.innerHTML += createCard('Security Indicators', indicatorsHtml);

    // JavaScript details
    if (data.javascript.length > 0) {
      const jsHtml = data.javascript.map(js => `
        <div class="indicator-item high">
          <span class="indicator-desc">${escapeHtml(js)}</span>
        </div>
      `).join('');
      container.innerHTML += createCard('JavaScript Detected', jsHtml, 'warning-card');
    }

    // Process Triggers
    if (data.processTriggers && data.processTriggers.length > 0) {
      const triggersHtml = data.processTriggers.map(trigger => `
        <div class="indicator-item high">
          <span class="indicator-type">${escapeHtml(trigger.type)}</span>
          <span class="indicator-desc">${escapeHtml(trigger.location)}: ${escapeHtml(trigger.pattern)}</span>
        </div>
      `).join('');
      container.innerHTML += createCard('Process Triggers', triggersHtml, 'warning-card');
    }

    // Download URLs
    if (data.downloadUrls && data.downloadUrls.length > 0) {
      const dlHtml = data.downloadUrls.map(dl => `
        <div class="indicator-item ${dl.is_high_risk ? 'high' : 'medium'}">
          <span class="indicator-type">${dl.extension}</span>
          <span class="indicator-desc">${escapeHtml(dl.target_filename)}</span>
          ${dl.is_high_risk ? '<span class="badge badge-danger">HIGH RISK</span>' : ''}
        </div>
      `).join('');
      container.innerHTML += createCard('Download Targets', dlHtml, data.downloadUrls.some(d => d.is_high_risk) ? 'warning-card' : '');
    }

    // External references
    if (data.externalReferences.length > 0) {
      const refsHtml = data.externalReferences.map(ref => `
        <div class="indicator-item high">
          <span class="indicator-desc">${escapeHtml(ref)}</span>
        </div>
      `).join('');
      container.innerHTML += createCard('External References', refsHtml, 'warning-card');
    }

    // Enriched URLs card
    if (data.enrichedUrls && data.enrichedUrls.length > 0) {
      const urlsHtml = data.enrichedUrls.slice(0, 10).map(enriched => {
        let urlContent = `<div class="enriched-url-item">
          <div class="url-item">${escapeHtml(enriched.url)}</div>`;

        if (enriched.domain) {
          urlContent += `<div class="url-detail"><span class="url-detail-label">Domain:</span> ${escapeHtml(enriched.domain)}</div>`;
        }

        if (enriched.dns && enriched.dns.ips && enriched.dns.ips.length > 0) {
          urlContent += `<div class="url-detail"><span class="url-detail-label">Resolved IPs:</span> ${enriched.dns.ips.join(', ')}</div>`;
        }

        if (enriched.ip_info && enriched.ip_info.length > 0) {
          const ipInfo = enriched.ip_info[0];
          if (ipInfo.country) {
            urlContent += `<div class="url-detail"><span class="url-detail-label">Location:</span> ${ipInfo.city || ''}, ${ipInfo.country}</div>`;
          }
        }

        if (enriched.threat_info && enriched.threat_info.length > 0) {
          const threat = enriched.threat_info[0];
          if (threat.abuse_score > 0) {
            urlContent += `<div class="url-detail threat-detail"><span class="url-detail-label">Threat Score:</span> <span class="badge badge-${threat.abuse_score > 50 ? 'danger' : 'warning'}">${threat.abuse_score}</span></div>`;
          }
        }

        urlContent += '</div>';
        return urlContent;
      }).join('');
      container.innerHTML += createCard(`Enriched URLs (${data.urlCount})`, urlsHtml);
    } else if (data.urlCount > 0) {
      const urlsHtml = data.urls.slice(0, 20).map(url => `
        <div class="url-item">${escapeHtml(url)}</div>
      `).join('');
      container.innerHTML += createCard(`URLs Found (${data.urlCount})`, urlsHtml);
    }

    // QR Codes card
    if (data.qrCodes && data.qrCodes.length > 0) {
      displayQRCodes(data.qrCodes, container);
    }
  }

  function displayOfficeResults(data, container) {
    // Document Info card
    container.innerHTML += createCard('Document Info', `
      ${infoRow('Filename', data.filename)}
      ${infoRow('Contains Macros', indicatorBadge(data.hasMacros, 'Yes - Macros detected', 'No macros'))}
    `);

    // Security Indicators card
    const indicatorsHtml = `
      ${infoRow('VBA Macros', indicatorBadge(data.hasMacros, `${data.macros.length} macro(s) found`, 'None'))}
      ${infoRow('Auto-Execution', indicatorBadge(data.autoExecution.length > 0, `${data.autoExecution.length} trigger(s)`, 'None'))}
      ${infoRow('Suspicious Patterns', indicatorBadge(data.suspiciousPatterns.length > 0, `${data.suspiciousPatterns.length} found`, 'None'))}
      ${infoRow('Embedded Objects', indicatorBadge(data.embeddedObjects.length > 0, `${data.embeddedObjects.length} found`, 'None'))}
      ${infoRow('Process Triggers', indicatorBadge(data.processTriggers && data.processTriggers.length > 0, `${(data.processTriggers || []).length} found`, 'None'))}
    `;
    container.innerHTML += createCard('Security Indicators', indicatorsHtml);

    // Auto-execution triggers
    if (data.autoExecution.length > 0) {
      const triggersHtml = data.autoExecution.map(trigger => `
        <div class="indicator-item high">
          <span class="indicator-type">${escapeHtml(trigger.trigger)}</span>
          <span class="indicator-desc">in ${escapeHtml(trigger.location)}</span>
        </div>
      `).join('');
      container.innerHTML += createCard('Auto-Execution Triggers', triggersHtml, 'warning-card');
    }

    // Process Triggers
    if (data.processTriggers && data.processTriggers.length > 0) {
      const procHtml = data.processTriggers.map(trigger => `
        <div class="indicator-item high">
          <span class="indicator-type">${escapeHtml(trigger.type)}</span>
          <span class="indicator-desc">in ${escapeHtml(trigger.location)}</span>
        </div>
      `).join('');
      container.innerHTML += createCard('Process Execution', procHtml, 'warning-card');
    }

    // HTTP Requests
    if (data.httpRequests && data.httpRequests.length > 0) {
      const httpHtml = data.httpRequests.map(req => `
        <div class="indicator-item medium">
          <span class="indicator-type">${escapeHtml(req.pattern)}</span>
          <span class="indicator-desc">in ${escapeHtml(req.location)}</span>
        </div>
      `).join('');
      container.innerHTML += createCard('HTTP Request Patterns', httpHtml, 'warning-card');
    }

    // Download Targets
    if (data.downloadTargets && data.downloadTargets.length > 0) {
      const dlHtml = data.downloadTargets.map(dl => `
        <div class="indicator-item medium">
          <span class="indicator-type">${escapeHtml(dl.pattern)}</span>
          <span class="indicator-desc">in ${escapeHtml(dl.location)}</span>
        </div>
      `).join('');
      container.innerHTML += createCard('Download/Save Operations', dlHtml, 'warning-card');
    }

    // Suspicious patterns
    if (data.suspiciousPatterns.length > 0) {
      const patternsHtml = data.suspiciousPatterns.map(pattern => `
        <div class="indicator-item ${pattern.type === 'IOC' ? 'high' : 'medium'}">
          <span class="indicator-type">${escapeHtml(pattern.type)}</span>
          <span class="indicator-keyword">${escapeHtml(pattern.keyword)}</span>
          <span class="indicator-desc">${escapeHtml(pattern.description)}</span>
        </div>
      `).join('');
      container.innerHTML += createCard('Suspicious Patterns', patternsHtml, 'warning-card');
    }

    // Enriched URLs
    if (data.enrichedUrls && data.enrichedUrls.length > 0) {
      const urlsHtml = data.enrichedUrls.slice(0, 10).map(enriched => {
        let urlContent = `<div class="enriched-url-item">
          <div class="url-item">${escapeHtml(enriched.url)}</div>`;

        if (enriched.domain) {
          urlContent += `<div class="url-detail"><span class="url-detail-label">Domain:</span> ${escapeHtml(enriched.domain)}</div>`;
        }

        if (enriched.dns && enriched.dns.ips && enriched.dns.ips.length > 0) {
          urlContent += `<div class="url-detail"><span class="url-detail-label">Resolved IPs:</span> ${enriched.dns.ips.join(', ')}</div>`;
        }

        if (enriched.threat_info && enriched.threat_info.length > 0) {
          const threat = enriched.threat_info[0];
          if (threat.abuse_score > 0) {
            urlContent += `<div class="url-detail threat-detail"><span class="url-detail-label">Threat Score:</span> <span class="badge badge-${threat.abuse_score > 50 ? 'danger' : 'warning'}">${threat.abuse_score}</span></div>`;
          }
        }

        urlContent += '</div>';
        return urlContent;
      }).join('');
      container.innerHTML += createCard(`URLs in Macros (${data.urls.length})`, urlsHtml);
    }

    // Macro code preview
    if (data.macros.length > 0) {
      data.macros.forEach((macro, i) => {
        const codePreview = macro.codePreview ? `
          <pre class="code-preview">${escapeHtml(macro.codePreview)}</pre>
          ${macro.codeLength > 2000 ? `<p class="code-truncated">Code truncated (${macro.codeLength} total characters)</p>` : ''}
        ` : '<p class="no-code">No code extracted</p>';

        container.innerHTML += createCard(`Macro: ${escapeHtml(macro.filename)}`, `
          ${infoRow('Stream Path', escapeHtml(macro.streamPath))}
          ${infoRow('Code Length', `${macro.codeLength} characters`)}
          <div class="code-section">
            <h4>Code Preview</h4>
            ${codePreview}
          </div>
        `);
      });
    }

    // Parse error
    if (data.parseError) {
      container.innerHTML += createCard('Parse Warning', `
        <div class="parse-warning">${escapeHtml(data.parseError)}</div>
      `);
    }
  }

  function createCard(title, content, extraClass = '') {
    return `
      <div class="card ${extraClass}">
        <h3>${title}</h3>
        <div class="card-content">${content}</div>
      </div>
    `;
  }

  function authBadge(status) {
    const statusLower = (status || 'unknown').toLowerCase();
    let className, displayText;

    if (statusLower === 'pass') {
      className = 'badge-safe';
      displayText = 'Pass';
    } else if (statusLower === 'fail') {
      className = 'badge-danger';
      displayText = 'Fail';
    } else if (statusLower === 'softfail') {
      className = 'badge-warning';
      displayText = 'Soft Fail';
    } else if (statusLower === 'none') {
      className = 'badge-neutral';
      displayText = 'None';
    } else {
      className = 'badge-neutral';
      displayText = status || 'Unknown';
    }

    return `<span class="badge ${className}">${displayText}</span>`;
  }

  function indicatorBadge(isPresent, presentText, absentText, isLowRisk = false) {
    if (isPresent) {
      const className = isLowRisk ? 'badge-warning' : 'badge-danger';
      return `<span class="badge ${className}">${presentText}</span>`;
    }
    return `<span class="badge badge-safe">${absentText}</span>`;
  }

  function formatIndicatorType(type) {
    const typeMap = {
      'auth_failure': 'Auth Failure',
      'url_mismatch': 'URL Mismatch',
      'lookalike_domain': 'Lookalike Domain',
      'urgency': 'Urgency',
      'suspicious_attachment': 'Suspicious Attachment',
      'reply_mismatch': 'Reply-To Mismatch'
    };
    return typeMap[type] || type;
  }

  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  function displayQRCodes(qrCodes, container) {
    if (!qrCodes || qrCodes.length === 0) return;

    const qrHtml = qrCodes.map(qr => {
      let content = `<div class="qr-code-item">
        <div class="qr-header">
          <span class="qr-type badge badge-${qr.risk_level === 'critical' || qr.risk_level === 'high' ? 'danger' : qr.risk_level === 'medium' ? 'warning' : 'safe'}">${escapeHtml(qr.type.toUpperCase())}</span>
          <span class="qr-risk">Risk: ${escapeHtml(qr.risk_level)}</span>
        </div>
        <div class="qr-data">${escapeHtml(qr.data)}</div>`;

      // URL enrichment for QR codes containing URLs
      if (qr.url_analysis) {
        const urlAnalysis = qr.url_analysis;
        content += `<div class="qr-enrichment">`;

        if (urlAnalysis.domain) {
          content += `<div class="url-detail"><span class="url-detail-label">Domain:</span> ${escapeHtml(urlAnalysis.domain)}</div>`;
        }

        if (urlAnalysis.dns && urlAnalysis.dns.ips && urlAnalysis.dns.ips.length > 0) {
          content += `<div class="url-detail"><span class="url-detail-label">Resolved IPs:</span> ${urlAnalysis.dns.ips.join(', ')}</div>`;
        }

        if (urlAnalysis.ip_info && urlAnalysis.ip_info.length > 0) {
          const ipInfo = urlAnalysis.ip_info[0];
          if (ipInfo.country) {
            content += `<div class="url-detail"><span class="url-detail-label">Location:</span> ${ipInfo.city || ''}, ${ipInfo.country}</div>`;
          }
          if (ipInfo.isp) {
            content += `<div class="url-detail"><span class="url-detail-label">ISP:</span> ${escapeHtml(ipInfo.isp)}</div>`;
          }
        }

        if (urlAnalysis.threat_info && urlAnalysis.threat_info.length > 0) {
          const threat = urlAnalysis.threat_info[0];
          if (threat.abuse_score > 0) {
            content += `<div class="url-detail threat-detail"><span class="url-detail-label">Threat Score:</span> <span class="badge badge-${threat.abuse_score > 50 ? 'danger' : 'warning'}">${threat.abuse_score}</span></div>`;
          }
        }

        if (urlAnalysis.download && urlAnalysis.download.is_download) {
          const dl = urlAnalysis.download;
          const riskBadge = dl.is_high_risk ? '<span class="badge badge-danger">HIGH RISK</span>' : '';
          content += `<div class="url-detail download-detail"><span class="url-detail-label">Download Target:</span> ${escapeHtml(dl.target_filename)} ${riskBadge}</div>`;
        }

        content += `</div>`;
      }

      // WiFi QR details
      if (qr.wifi_details) {
        content += `<div class="qr-enrichment">`;
        if (qr.wifi_details.ssid) content += `<div class="url-detail"><span class="url-detail-label">SSID:</span> ${escapeHtml(qr.wifi_details.ssid)}</div>`;
        if (qr.wifi_details.encryption) content += `<div class="url-detail"><span class="url-detail-label">Encryption:</span> ${escapeHtml(qr.wifi_details.encryption)}</div>`;
        if (qr.wifi_details.hidden) content += `<div class="url-detail"><span class="url-detail-label">Hidden:</span> Yes</div>`;
        content += `</div>`;
      }

      // Indicators
      if (qr.indicators && qr.indicators.length > 0) {
        content += `<div class="qr-indicators">`;
        qr.indicators.forEach(ind => {
          content += `<div class="indicator-item ${ind.severity || 'medium'}">
            <span class="indicator-desc">${escapeHtml(ind.description)}</span>
          </div>`;
        });
        content += `</div>`;
      }

      content += `</div>`;
      return content;
    }).join('');

    const hasHighRisk = qrCodes.some(qr => qr.risk_level === 'high' || qr.risk_level === 'critical');
    container.innerHTML += createCard(`QR Codes Detected (${qrCodes.length})`, qrHtml, hasHighRisk ? 'warning-card' : '');
  }

  // IP Lookup event listeners
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
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
});
