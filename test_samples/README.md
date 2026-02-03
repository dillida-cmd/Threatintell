# Test Samples for Manny Threat Intel

This folder contains test files for validating the sandbox analysis capabilities.

## Malicious Samples

### Email Files (.eml)

| File | Type | Indicators |
|------|------|------------|
| `phishing_email.eml` | Phishing | Typosquatting domain (paypa1-secure.com), executable attachment, malicious URLs, tracking pixel |
| `spear_phishing.eml` | BEC/Spear Phishing | CEO fraud, wire transfer request, spoofed sender |
| `credential_harvesting.eml` | Credential Theft | Fake Microsoft login, typosquatting (m1crosoft-secure.com), urgency tactics |

### Office Documents

| File | Type | Indicators |
|------|------|------------|
| `malicious_invoice.docm` | Macro Malware | VBA macros, AutoOpen trigger, PowerShell execution, external template injection, C2 URLs |

### PDF Documents

| File | Type | Indicators |
|------|------|------------|
| `malicious_document.pdf` | PDF Malware | JavaScript auto-execution, embedded executable, malicious URLs, form submission to C2 |

## Clean/Legitimate Samples

| File | Type | Description |
|------|------|-------------|
| `legitimate_email.eml` | Newsletter | Standard marketing email with proper headers |

## Malicious URLs Used in Samples

| URL | Purpose |
|-----|---------|
| `http://185.220.101.1/payload.exe` | Known Tor exit node, payload delivery |
| `http://malware.wicar.org/data/eicar.com` | EICAR test file (safe malware test) |
| `http://evil-c2-server.ru/beacon.php` | Simulated C2 beacon |
| `http://paypa1-secure.com/*` | PayPal typosquatting |
| `http://m1crosoft-secure.com/*` | Microsoft typosquatting |

## Malicious Hashes for Testing

Use these known malicious hashes for hash lookup testing:

| Hash | Type | Description |
|------|------|-------------|
| `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` | SHA256 | EICAR test file |
| `24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c` | SHA256 | WannaCry ransomware |
| `44d88612fea8a8f36de82e1278abb02f` | MD5 | EICAR test file |

## Malicious IPs for Testing

| IP | Description |
|----|-------------|
| `185.220.101.1` | Known Tor exit node, frequently reported for abuse |
| `45.33.32.156` | Scanme.nmap.org (safe for testing) |

## Usage

### Test via UI
1. Go to **Sandbox** tab
2. Upload any sample file
3. Enter a secret key (min 8 characters)
4. View analysis results

### Test via API

```bash
# Email analysis
curl -X POST http://localhost:3000/api/analyze/email \
  -F "file=@test_samples/phishing_email.eml" \
  -F "secretKey=testkey123"

# Office analysis
curl -X POST http://localhost:3000/api/analyze/office \
  -F "file=@test_samples/malicious_invoice.docm" \
  -F "secretKey=testkey123"

# PDF analysis
curl -X POST http://localhost:3000/api/analyze/pdf \
  -F "file=@test_samples/malicious_document.pdf" \
  -F "secretKey=testkey123"
```

## Expected Detection Results

### phishing_email.eml
- Risk Level: **High** (60-80)
- Findings: Typosquatting domain, executable attachment, suspicious URLs, tracking pixel

### malicious_invoice.docm
- Risk Level: **Critical** (90-100)
- Findings: VBA macros, AutoOpen trigger, external references, process execution patterns

### malicious_document.pdf
- Risk Level: **High** (70-90)
- Findings: JavaScript, auto-open action, malicious URLs, embedded file

### legitimate_email.eml
- Risk Level: **Low** (0-20)
- Findings: None or minimal

## Warning

These files are for **testing purposes only**. They contain simulated malicious indicators but are not actual malware. Do not use these techniques for malicious purposes.
