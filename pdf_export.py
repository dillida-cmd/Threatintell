#!/usr/bin/env python3
"""
Encrypted PDF Export Service for ShieldTier
Generates password-protected PDF reports from analysis results
"""

import os
import io
import json
import base64
from datetime import datetime
from typing import Dict, Optional, List, Any

# Try to import PDF libraries
PDF_LIBRARY = None

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
    from reportlab.platypus.flowables import HRFlowable
    PDF_LIBRARY = 'reportlab'
except ImportError:
    pass

try:
    from PyPDF2 import PdfReader, PdfWriter
    PDF_ENCRYPTION = 'pypdf2'
except ImportError:
    try:
        import pikepdf
        PDF_ENCRYPTION = 'pikepdf'
    except ImportError:
        PDF_ENCRYPTION = None


# ============ DEFANGING FUNCTIONS ============
# Prevent accidental clicks on malicious URLs/IPs in PDF reports

def defang_url(url: str) -> str:
    """Defang URL: http://evil.com -> hxxp://evil[.]com"""
    if not url:
        return url
    import re
    result = url
    result = re.sub(r'^http:', 'hxxp:', result, flags=re.IGNORECASE)
    result = re.sub(r'^https:', 'hxxps:', result, flags=re.IGNORECASE)
    result = re.sub(r'^ftp:', 'fxp:', result, flags=re.IGNORECASE)
    result = result.replace('.', '[.]')
    return result

def defang_ip(ip: str) -> str:
    """Defang IP: 192.168.1.1 -> 192[.]168[.]1[.]1"""
    if not ip:
        return ip
    return ip.replace('.', '[.]')

def defang_domain(domain: str) -> str:
    """Defang domain: evil.com -> evil[.]com"""
    if not domain:
        return domain
    return domain.replace('.', '[.]')

def defang_email(email: str) -> str:
    """Defang email: user@evil.com -> user[@]evil[.]com"""
    if not email:
        return email
    return email.replace('@', '[@]').replace('.', '[.]')

def is_ip_address(s: str) -> bool:
    """Check if string looks like an IP address"""
    import re
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(ipv4_pattern, s))

def is_url(s: str) -> bool:
    """Check if string looks like a URL"""
    import re
    return bool(re.match(r'^(https?|ftp)://', s, re.IGNORECASE))

def smart_defang(value: str) -> str:
    """Auto-detect type and apply appropriate defanging"""
    if not value:
        return value
    if is_url(value):
        return defang_url(value)
    elif is_ip_address(value):
        return defang_ip(value)
    elif '@' in value:
        return defang_email(value)
    elif '.' in value and ' ' not in value:
        return defang_domain(value)
    return value


def check_pdf_available() -> Dict[str, bool]:
    """Check PDF generation capabilities"""
    return {
        'pdf_generation': PDF_LIBRARY is not None,
        'pdf_library': PDF_LIBRARY,
        'pdf_encryption': PDF_ENCRYPTION is not None,
        'encryption_library': PDF_ENCRYPTION,
    }


def encrypt_pdf_pypdf2(input_path: str, output_path: str, password: str) -> bool:
    """Encrypt PDF using PyPDF2"""
    try:
        from PyPDF2 import PdfReader, PdfWriter

        reader = PdfReader(input_path)
        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        writer.encrypt(password)

        with open(output_path, 'wb') as f:
            writer.write(f)

        return True
    except Exception as e:
        print(f"PyPDF2 encryption error: {e}")
        return False


def encrypt_pdf_pikepdf(input_path: str, output_path: str, password: str) -> bool:
    """Encrypt PDF using pikepdf"""
    try:
        import pikepdf

        with pikepdf.open(input_path) as pdf:
            pdf.save(output_path, encryption=pikepdf.Encryption(
                owner=password,
                user=password,
                R=6  # AES-256 encryption
            ))
        return True
    except Exception as e:
        print(f"pikepdf encryption error: {e}")
        return False


def create_analysis_pdf(analysis_result: Dict, output_path: str,
                        include_screenshot: bool = True) -> bool:
    """
    Create PDF report from analysis results using ReportLab

    Args:
        analysis_result: The analysis result dictionary
        output_path: Output PDF file path
        include_screenshot: Whether to include URL screenshots

    Returns:
        True if successful, False otherwise
    """

    if PDF_LIBRARY != 'reportlab':
        return False

    try:
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )

        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a2e'),
            spaceAfter=20,
        )

        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#00d4ff'),
            spaceBefore=15,
            spaceAfter=10,
        )

        subheading_style = ParagraphStyle(
            'CustomSubheading',
            parent=styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#333333'),
            spaceBefore=10,
            spaceAfter=5,
        )

        body_style = ParagraphStyle(
            'CustomBody',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#333333'),
            spaceAfter=5,
        )

        # Build document content
        story = []

        # Title
        story.append(Paragraph("ShieldTier", title_style))
        story.append(Paragraph("<font size='10' color='#666666'>ShieldTier Threat Intelligence</font>", styles['Normal']))
        story.append(Paragraph("Security Analysis Report", styles['Heading2']))
        story.append(Spacer(1, 10))

        # Report metadata
        report_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        story.append(Paragraph(f"<b>Generated:</b> {report_time}", body_style))

        if analysis_result.get('entryRef'):
            story.append(Paragraph(f"<b>Reference:</b> {analysis_result['entryRef']}", body_style))

        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#00d4ff')))
        story.append(Spacer(1, 15))

        # Analysis type and target info
        file_type = analysis_result.get('type', 'Unknown')
        filename = analysis_result.get('filename', 'N/A')

        # Determine if this is IP, URL, Hash, or File analysis
        is_ip_analysis = file_type == 'ip' or analysis_result.get('ip') or (analysis_result.get('basic') and analysis_result.get('threat'))
        is_url_analysis = file_type == 'url' or analysis_result.get('url') and not analysis_result.get('filename')
        is_hash_analysis = file_type == 'hash' or (analysis_result.get('hash') and analysis_result.get('sources'))

        # Target Information Section
        story.append(Paragraph("Target Information", heading_style))

        if is_ip_analysis:
            ip_addr = analysis_result.get('ip', analysis_result.get('basic', {}).get('ip', 'N/A'))
            target_info = [['Analysis Type:', 'IP ADDRESS INVESTIGATION'], ['Target IP:', defang_ip(ip_addr)]]
            basic = analysis_result.get('basic', {})
            if basic.get('location', {}).get('country'):
                target_info.append(['Country:', f"{basic['location'].get('country', '')} ({basic['location'].get('countryCode', '')})"])
            if basic.get('network', {}).get('isp'):
                target_info.append(['ISP:', basic['network']['isp']])
        elif is_url_analysis:
            url = analysis_result.get('url', 'N/A')
            defanged_url = defang_url(url)
            target_info = [['Analysis Type:', 'URL THREAT ANALYSIS'], ['Target URL:', defanged_url[:80] + '...' if len(defanged_url) > 80 else defanged_url]]
            if analysis_result.get('finalUrl') and analysis_result.get('finalUrl') != url:
                final_defanged = defang_url(analysis_result['finalUrl'])
                target_info.append(['Final URL:', final_defanged[:80]])
        elif is_hash_analysis:
            hash_val = analysis_result.get('hash', 'N/A')
            target_info = [['Analysis Type:', 'FILE HASH LOOKUP'], ['Hash:', hash_val]]
            sources = analysis_result.get('sources', {})
            if sources.get('virustotal', {}).get('fileName'):
                target_info.append(['File Name:', sources['virustotal']['fileName']])
            if sources.get('virustotal', {}).get('fileType'):
                target_info.append(['File Type:', sources['virustotal']['fileType']])
        else:
            target_info = [['Analysis Type:', file_type.upper()], ['Filename:', filename]]
            if analysis_result.get('documentType'):
                target_info.append(['Document Type:', analysis_result['documentType']])

        target_table = Table(target_info, colWidths=[1.5*inch, 5*inch])
        target_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TEXTCOLOR', (1, 0), (1, 0), colors.HexColor('#00d4ff')),
        ]))
        story.append(target_table)
        story.append(Spacer(1, 15))

        # Risk Assessment - Get score from various result structures
        story.append(Paragraph("Risk Assessment", heading_style))

        # Try to get risk score from different locations
        risk_score = analysis_result.get('riskScore', 0)
        risk_level = analysis_result.get('riskLevel', 'Unknown')

        # Check nested structures for IP/URL/Hash results
        if not risk_score:
            summary = analysis_result.get('summary', {}) or analysis_result.get('threat', {}).get('summary', {})
            risk_score = summary.get('riskScore', 0)
            risk_level = summary.get('riskLevel', risk_level)
            if summary.get('isMalicious'):
                risk_level = 'Critical' if risk_score >= 70 else 'High'

        # Color code risk level
        risk_color = colors.green
        if risk_score >= 70:
            risk_color = colors.red
        elif risk_score >= 40:
            risk_color = colors.orange

        # Determine malicious status from multiple sources
        is_malicious = (
            analysis_result.get('summary', {}).get('isMalicious', False) or
            analysis_result.get('threat', {}).get('summary', {}).get('isMalicious', False) or
            risk_score >= 70 or  # Critical risk score
            risk_level in ['Critical', 'High'] or  # High/Critical risk level
            'MALICIOUS' in str(analysis_result.get('summary', {}).get('verdict', '')).upper() or
            analysis_result.get('iocInvestigation', {}).get('summary', {}).get('maliciousIOCs', 0) > 0
        )

        # Determine status text based on risk
        if is_malicious:
            status_text = 'MALICIOUS'
        elif risk_score >= 40:
            status_text = 'SUSPICIOUS'
        else:
            status_text = 'CLEAN'

        risk_data = [
            ['Risk Score:', f"{risk_score}/100"],
            ['Risk Level:', risk_level],
            ['Status:', status_text],
        ]

        # Status color based on text
        status_color = colors.green
        if status_text == 'MALICIOUS':
            status_color = colors.red
        elif status_text == 'SUSPICIOUS':
            status_color = colors.orange

        risk_table = Table(risk_data, colWidths=[1.5*inch, 5*inch])
        risk_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('TEXTCOLOR', (1, 0), (1, 0), risk_color),
            ('TEXTCOLOR', (1, 1), (1, 1), risk_color),
            ('TEXTCOLOR', (1, 2), (1, 2), status_color),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 15))

        # ============ IP ADDRESS ANALYSIS SECTION ============
        if is_ip_analysis:
            basic = analysis_result.get('basic', {})
            threat = analysis_result.get('threat', {})
            sources = threat.get('sources', {}) or analysis_result.get('sources', {})

            # Location Information
            location = basic.get('location', {})
            if location:
                story.append(Paragraph("📍 Location Information", heading_style))
                loc_data = []
                if location.get('country'):
                    loc_data.append(['Country:', f"{location.get('country')} ({location.get('countryCode', '')})"])
                if location.get('city'):
                    loc_data.append(['City:', location['city']])
                if location.get('region'):
                    loc_data.append(['Region:', location['region']])
                if location.get('timezone'):
                    loc_data.append(['Timezone:', location['timezone']])

                if loc_data:
                    loc_table = Table(loc_data, colWidths=[1.5*inch, 5*inch])
                    loc_table.setStyle(TableStyle([
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                    ]))
                    story.append(loc_table)
                    story.append(Spacer(1, 10))

            # Network Information
            network = basic.get('network', {})
            if network:
                story.append(Paragraph("🌐 Network Information", heading_style))
                net_data = []
                if network.get('isp'):
                    net_data.append(['ISP:', network['isp']])
                if network.get('asn'):
                    net_data.append(['ASN:', network['asn']])
                if network.get('org'):
                    net_data.append(['Organization:', network['org']])
                if basic.get('domain'):
                    net_data.append(['Domain:', defang_domain(basic['domain'])])

                if net_data:
                    net_table = Table(net_data, colWidths=[1.5*inch, 5*inch])
                    net_table.setStyle(TableStyle([
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                    ]))
                    story.append(net_table)
                    story.append(Spacer(1, 10))

            # Security Flags
            security = basic.get('security', {})
            ipqs = sources.get('ipqualityscore', {})
            abuseipdb = sources.get('abuseipdb', {})

            flags = []
            if ipqs.get('isVpn') or security.get('isVpn'):
                flags.append('VPN')
            if ipqs.get('isProxy') or security.get('isProxy'):
                flags.append('Proxy')
            if ipqs.get('isTor') or abuseipdb.get('isTor'):
                flags.append('Tor Exit Node')
            if ipqs.get('isBot'):
                flags.append('Bot')
            if security.get('isHosting'):
                flags.append('Hosting Provider')
            if ipqs.get('isCrawler'):
                flags.append('Crawler')

            if flags:
                story.append(Paragraph("⚠️ Security Flags Detected", heading_style))
                for flag in flags:
                    story.append(Paragraph(f"  • {flag}", body_style))
                story.append(Spacer(1, 10))

            # VirusTotal Results
            vt = sources.get('virustotal', {})
            if vt:
                story.append(Paragraph("🛡️ VirusTotal Analysis", heading_style))
                vt_data = [
                    ['Malicious:', str(vt.get('malicious', 0))],
                    ['Suspicious:', str(vt.get('suspicious', 0))],
                    ['Clean:', str(vt.get('harmless', 0))],
                    ['Undetected:', str(vt.get('undetected', 0))],
                ]
                if vt.get('asOwner'):
                    vt_data.append(['AS Owner:', vt['asOwner']])
                if vt.get('reputation') is not None:
                    vt_data.append(['Reputation:', str(vt['reputation'])])

                vt_table = Table(vt_data, colWidths=[1.5*inch, 5*inch])
                vt_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('TEXTCOLOR', (1, 0), (1, 0), colors.red if vt.get('malicious', 0) > 0 else colors.green),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ]))
                story.append(vt_table)
                story.append(Spacer(1, 10))

            # AbuseIPDB Results
            if abuseipdb:
                story.append(Paragraph("🚨 AbuseIPDB Analysis", heading_style))
                abuse_data = [
                    ['Abuse Score:', f"{abuseipdb.get('abuseScore', 0)}%"],
                    ['Total Reports:', str(abuseipdb.get('totalReports', 0))],
                ]
                if abuseipdb.get('usageType'):
                    abuse_data.append(['Usage Type:', abuseipdb['usageType']])
                if abuseipdb.get('isWhitelisted'):
                    abuse_data.append(['Status:', 'WHITELISTED'])

                abuse_score = abuseipdb.get('abuseScore', 0)
                abuse_color = colors.red if abuse_score > 50 else (colors.orange if abuse_score > 20 else colors.green)

                abuse_table = Table(abuse_data, colWidths=[1.5*inch, 5*inch])
                abuse_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('TEXTCOLOR', (1, 0), (1, 0), abuse_color),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ]))
                story.append(abuse_table)
                story.append(Spacer(1, 10))

            # IPQualityScore
            if ipqs and ipqs.get('fraudScore') is not None:
                story.append(Paragraph("🎯 Fraud Analysis (IPQualityScore)", heading_style))
                fraud_score = ipqs.get('fraudScore', 0)
                fraud_color = colors.red if fraud_score > 75 else (colors.orange if fraud_score > 50 else colors.green)
                story.append(Paragraph(f"<b>Fraud Score:</b> <font color='{fraud_color}'>{fraud_score}</font>", body_style))
                story.append(Spacer(1, 10))

            # Shodan Infrastructure
            shodan = sources.get('shodan', {})
            if shodan:
                story.append(Paragraph("🖥️ Infrastructure (Shodan)", heading_style))

                if shodan.get('hostnames'):
                    defanged_hostnames = [defang_domain(h) for h in shodan['hostnames'][:5]]
                    story.append(Paragraph(f"<b>Hostnames:</b> {', '.join(defanged_hostnames)}", body_style))
                if shodan.get('ports'):
                    story.append(Paragraph(f"<b>Open Ports:</b> {', '.join(map(str, shodan['ports'][:10]))}", body_style))
                if shodan.get('vulns'):
                    story.append(Paragraph(f"<font color='red'><b>Vulnerabilities:</b> {', '.join(shodan['vulns'][:5])}</font>", body_style))
                story.append(Spacer(1, 10))

            # ThreatFox
            threatfox = sources.get('threatfox', {})
            if threatfox and threatfox.get('found'):
                story.append(Paragraph("🦊 ThreatFox - Known Malware", heading_style))
                story.append(Paragraph(f"<font color='red'><b>MALWARE DETECTED: {threatfox.get('malwareFamily', 'Unknown')}</b></font>", body_style))
                story.append(Spacer(1, 10))

            # AlienVault OTX
            otx = sources.get('alienvault_otx', {})
            if otx:
                story.append(Paragraph("👽 AlienVault OTX Intelligence", heading_style))
                story.append(Paragraph(f"<b>Threat Pulses:</b> {otx.get('pulseCount', 0)}", body_style))
                if otx.get('reputation'):
                    story.append(Paragraph(f"<b>Reputation:</b> {otx['reputation']}", body_style))
                story.append(Spacer(1, 10))

        # ============ URL ANALYSIS SECTION ============
        elif is_url_analysis:
            sources = analysis_result.get('sources', {})
            summary = analysis_result.get('summary', {})

            # VirusTotal URL Results
            vt = sources.get('virustotal', {})
            if vt:
                story.append(Paragraph("🛡️ VirusTotal URL Analysis", heading_style))
                vt_data = [
                    ['Malicious:', str(vt.get('malicious', 0))],
                    ['Suspicious:', str(vt.get('suspicious', 0))],
                    ['Clean:', str(vt.get('harmless', 0))],
                    ['Undetected:', str(vt.get('undetected', 0))],
                ]

                vt_table = Table(vt_data, colWidths=[1.5*inch, 5*inch])
                vt_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('TEXTCOLOR', (1, 0), (1, 0), colors.red if vt.get('malicious', 0) > 0 else colors.green),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ]))
                story.append(vt_table)

                # Categories
                if vt.get('categories'):
                    cats = list(vt['categories'].values()) if isinstance(vt['categories'], dict) else vt['categories']
                    story.append(Paragraph(f"<b>Categories:</b> {', '.join(cats[:5])}", body_style))
                story.append(Spacer(1, 10))

            # URLhaus
            urlhaus = sources.get('urlhaus', {})
            if urlhaus and (urlhaus.get('found') or urlhaus.get('threat')):
                story.append(Paragraph("🔴 URLhaus - Known Malicious URL", heading_style))
                story.append(Paragraph(f"<font color='red'><b>Threat Type:</b> {urlhaus.get('threat', 'Malware')}</font>", body_style))
                if urlhaus.get('urlStatus'):
                    story.append(Paragraph(f"<b>Status:</b> {urlhaus['urlStatus']}", body_style))
                if urlhaus.get('tags'):
                    story.append(Paragraph(f"<b>Tags:</b> {', '.join(urlhaus['tags'])}", body_style))
                story.append(Spacer(1, 10))

            # AlienVault OTX
            otx = sources.get('alienvault_otx', {})
            if otx:
                story.append(Paragraph("👽 AlienVault OTX Intelligence", heading_style))
                story.append(Paragraph(f"<b>Threat Reports:</b> {otx.get('pulseCount', 0)}", body_style))
                if otx.get('domain'):
                    story.append(Paragraph(f"<b>Domain:</b> {defang_domain(otx['domain'])}", body_style))

                # Validation messages
                if otx.get('validation'):
                    for v in otx['validation'][:3]:
                        msg_color = 'green' if v.get('source') in ['whitelist', 'akamai', 'majestic'] else 'orange'
                        story.append(Paragraph(f"<font color='{msg_color}'>{v.get('message', '')}</font>", body_style))

                # Related pulses
                if otx.get('pulses'):
                    story.append(Paragraph("<b>Related Threat Reports:</b>", body_style))
                    for pulse in otx['pulses'][:3]:
                        story.append(Paragraph(f"  • {pulse.get('name', 'Unknown')}", body_style))
                story.append(Spacer(1, 10))

        # ============ HASH ANALYSIS SECTION ============
        elif is_hash_analysis:
            sources = analysis_result.get('sources', {})
            summary = analysis_result.get('summary', {})

            # VirusTotal Hash Results
            vt = sources.get('virustotal', {})
            if vt:
                story.append(Paragraph("🛡️ VirusTotal File Analysis", heading_style))
                vt_data = [
                    ['Malicious:', str(vt.get('malicious', 0))],
                    ['Suspicious:', str(vt.get('suspicious', 0))],
                    ['Clean:', str(vt.get('harmless', 0))],
                    ['Undetected:', str(vt.get('undetected', 0))],
                ]

                vt_table = Table(vt_data, colWidths=[1.5*inch, 5*inch])
                vt_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('TEXTCOLOR', (1, 0), (1, 0), colors.red if vt.get('malicious', 0) > 0 else colors.green),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ]))
                story.append(vt_table)

                # File details
                if vt.get('fileName'):
                    story.append(Paragraph(f"<b>File Name:</b> {vt['fileName']}", body_style))
                if vt.get('fileSize'):
                    story.append(Paragraph(f"<b>File Size:</b> {vt['fileSize']:,} bytes", body_style))
                if vt.get('fileType'):
                    story.append(Paragraph(f"<b>File Type:</b> {vt['fileType']}", body_style))
                if vt.get('tags'):
                    story.append(Paragraph(f"<b>Tags:</b> {', '.join(vt['tags'][:10])}", body_style))
                story.append(Spacer(1, 10))

            # MalwareBazaar
            mb = sources.get('malwarebazaar', {})
            if mb and mb.get('found'):
                story.append(Paragraph("🔴 MalwareBazaar - Known Malware", heading_style))
                if mb.get('signature'):
                    story.append(Paragraph(f"<font color='red'><b>Signature:</b> {mb['signature']}</font>", body_style))
                if mb.get('fileType'):
                    story.append(Paragraph(f"<b>File Type:</b> {mb['fileType']}", body_style))
                if mb.get('firstSeen'):
                    story.append(Paragraph(f"<b>First Seen:</b> {mb['firstSeen']}", body_style))
                if mb.get('tags'):
                    story.append(Paragraph(f"<b>Tags:</b> {', '.join(mb['tags'])}", body_style))
                story.append(Spacer(1, 10))

            # AlienVault OTX
            otx = sources.get('alienvault_otx', {})
            if otx:
                story.append(Paragraph("👽 AlienVault OTX Intelligence", heading_style))
                story.append(Paragraph(f"<b>Threat Reports:</b> {otx.get('pulseCount', 0)}", body_style))
                if otx.get('fileType'):
                    story.append(Paragraph(f"<b>File Type:</b> {otx['fileType']}", body_style))
                if otx.get('fileSize'):
                    story.append(Paragraph(f"<b>File Size:</b> {otx['fileSize']:,} bytes", body_style))

                # Related pulses
                if otx.get('pulses'):
                    story.append(Paragraph("<b>Related Threat Pulses:</b>", body_style))
                    for pulse in otx['pulses'][:5]:
                        story.append(Paragraph(f"  • {pulse.get('name', 'Unknown')}", body_style))
                        if pulse.get('tags'):
                            story.append(Paragraph(f"    Tags: {', '.join(pulse['tags'][:5])}", body_style))
                story.append(Spacer(1, 10))

        # Email-specific sections
        if file_type == 'email':
            # Headers
            headers = analysis_result.get('headers', {})
            if headers:
                story.append(Paragraph("Email Headers (defanged)", heading_style))
                header_data = []
                for key in ['from', 'to', 'subject', 'date', 'return-path', 'x-originating-ip']:
                    if headers.get(key):
                        value = str(headers[key])[:80]
                        # Defang email addresses and IPs in headers
                        if key in ['from', 'to', 'return-path']:
                            value = defang_email(value)
                        elif key == 'x-originating-ip':
                            # Extract IP from brackets if present
                            import re
                            ip_match = re.search(r'\[?([\d\.]+)\]?', value)
                            if ip_match:
                                value = defang_ip(ip_match.group(1))
                        header_data.append([key.title() + ':', value])

                if header_data:
                    header_table = Table(header_data, colWidths=[1.5*inch, 5*inch])
                    header_table.setStyle(TableStyle([
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                    ]))
                    story.append(header_table)
                    story.append(Spacer(1, 10))

            # Attachments
            attachments = analysis_result.get('attachments', [])
            if attachments:
                story.append(Paragraph("Attachments", heading_style))
                for att in attachments:
                    att_text = f"• {att.get('filename', 'Unknown')} ({att.get('size', 0)} bytes)"
                    if att.get('isExecutable'):
                        att_text += " <font color='red'>[EXECUTABLE]</font>"
                    story.append(Paragraph(att_text, body_style))
                story.append(Spacer(1, 10))

        # Office-specific sections
        if file_type == 'office':
            # Macros
            if analysis_result.get('hasMacros'):
                story.append(Paragraph("⚠ VBA Macros Detected", heading_style))
                macros = analysis_result.get('macros', [])
                for macro in macros:
                    story.append(Paragraph(f"• {macro.get('filename', 'Unknown')} ({macro.get('codeLength', 0)} bytes)", body_style))
                story.append(Spacer(1, 10))

            # Auto-execution triggers
            auto_exec = analysis_result.get('autoExecution', [])
            if auto_exec:
                story.append(Paragraph("Auto-Execution Triggers", heading_style))
                for trigger in auto_exec:
                    story.append(Paragraph(f"• {trigger.get('trigger', 'Unknown')} in {trigger.get('location', 'Unknown')}", body_style))
                story.append(Spacer(1, 10))

            # External References
            ext_refs = analysis_result.get('externalReferences', [])
            if ext_refs:
                story.append(Paragraph("External References", heading_style))
                for ref in ext_refs[:10]:  # Limit to 10
                    ref_text = f"• [{ref.get('type', 'Unknown')}] {ref.get('target', 'N/A')[:60]}"
                    story.append(Paragraph(ref_text, body_style))
                story.append(Spacer(1, 10))

        # PDF-specific sections
        if file_type == 'pdf':
            if analysis_result.get('hasJavaScript'):
                story.append(Paragraph("⚠ JavaScript Detected", heading_style))
                story.append(Paragraph("This PDF contains embedded JavaScript code.", body_style))
                story.append(Spacer(1, 10))

            if analysis_result.get('hasAutoAction'):
                story.append(Paragraph("⚠ Auto-Open Actions", heading_style))
                story.append(Paragraph("This PDF contains automatic actions that execute on open.", body_style))
                story.append(Spacer(1, 10))

        # Sandbox-specific sections
        if file_type in ('sandbox', 'sandbox_url'):
            # Session info
            if analysis_result.get('sessionId'):
                story.append(Paragraph("Sandbox Analysis", heading_style))
                sandbox_info = [
                    ['Session ID:', analysis_result.get('sessionId', 'N/A')],
                    ['Backend:', analysis_result.get('backend_type', 'N/A')],
                ]

                sandbox_table = Table(sandbox_info, colWidths=[1.5*inch, 5*inch])
                sandbox_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ]))
                story.append(sandbox_table)
                story.append(Spacer(1, 10))

            # File analysis info
            file_analysis = analysis_result.get('fileAnalysis', {})
            if file_analysis:
                story.append(Paragraph("File Analysis", heading_style))
                file_info_data = [
                    ['Detected Type:', file_analysis.get('detectedType', 'Unknown')],
                    ['File Size:', f"{file_analysis.get('fileSize', 0):,} bytes"],
                ]

                hashes = file_analysis.get('hashes', {})
                if hashes.get('md5'):
                    file_info_data.append(['MD5:', hashes['md5']])
                if hashes.get('sha256'):
                    file_info_data.append(['SHA256:', hashes['sha256'][:32] + '...'])

                file_info_table = Table(file_info_data, colWidths=[1.5*inch, 5*inch])
                file_info_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ]))
                story.append(file_info_table)
                story.append(Spacer(1, 10))

            # Execution results
            execution = analysis_result.get('execution', {})
            if execution:
                story.append(Paragraph("Execution Results", heading_style))
                exec_time = execution.get('execution_time', 0)
                exit_code = execution.get('exit_code', 'N/A')
                story.append(Paragraph(f"Exit Code: {exit_code} | Execution Time: {exec_time:.2f}s", body_style))

                if execution.get('error'):
                    story.append(Paragraph(f"<font color='red'>Error: {execution['error']}</font>", body_style))

                # Suspicious elements (from PDF analysis in sandbox)
                suspicious = execution.get('suspiciousElements', [])
                if suspicious:
                    story.append(Paragraph("Suspicious Elements:", body_style))
                    for elem in suspicious:
                        story.append(Paragraph(f"  • {elem}", body_style))

                story.append(Spacer(1, 10))

            # Risk Reasons (detailed explanations)
            risk_reasons = analysis_result.get('riskReasons', [])
            if risk_reasons:
                story.append(Paragraph("Risk Analysis Details", heading_style))
                for reason in risk_reasons[:10]:  # Limit to 10
                    severity = reason.get('severity', 'unknown').upper()
                    category = reason.get('category', 'Unknown')
                    description = reason.get('description', '')
                    technique = reason.get('technique', '')

                    severity_color = 'red' if severity in ['CRITICAL', 'HIGH'] else 'orange' if severity == 'MEDIUM' else 'black'
                    story.append(Paragraph(
                        f"<font color='{severity_color}'><b>[{severity}]</b></font> "
                        f"<b>{category}:</b> {description}",
                        body_style
                    ))
                    if technique:
                        story.append(Paragraph(f"    <i>MITRE ATT&CK: {technique}</i>", body_style))

                if len(risk_reasons) > 10:
                    story.append(Paragraph(f"... and {len(risk_reasons) - 10} more risk factors", body_style))
                story.append(Spacer(1, 10))

            # Threat Map (MITRE ATT&CK behaviors)
            threat_map = analysis_result.get('threatMap', {})
            if threat_map:
                story.append(Paragraph("Threat Map (MITRE ATT&CK)", heading_style))
                category_icons = {
                    'network': 'Network Activity',
                    'process': 'Process Activity',
                    'evasion': 'Defense Evasion',
                    'persistence': 'Persistence',
                    'credential': 'Credential Access',
                    'discovery': 'Discovery',
                    'registry': 'Registry',
                    'filesystem': 'File System'
                }
                for category, behaviors in threat_map.items():
                    if behaviors:
                        cat_name = category_icons.get(category, category.title())
                        story.append(Paragraph(f"<b>{cat_name}:</b>", subheading_style))
                        for behavior in behaviors[:5]:  # Limit per category
                            beh_text = behavior.get('behavior', str(behavior))
                            technique = behavior.get('technique', '')
                            severity = behavior.get('severity', 'medium')
                            sev_color = 'red' if severity in ['critical', 'high'] else 'orange' if severity == 'medium' else 'black'
                            tech_str = f" ({technique})" if technique else ""
                            story.append(Paragraph(
                                f"  • <font color='{sev_color}'>{beh_text}</font>{tech_str}",
                                body_style
                            ))
                story.append(Spacer(1, 10))

            # PE Analysis Details
            pe_analysis = analysis_result.get('peAnalysis', {})
            if pe_analysis and pe_analysis.get('isPE'):
                story.append(Paragraph("PE Analysis", heading_style))

                # Basic properties
                basic = pe_analysis.get('basicProperties', {})
                header = pe_analysis.get('header', {})
                pe_data = [
                    ['File Type:', basic.get('fileType', 'Unknown')],
                    ['Target Machine:', header.get('targetMachine', 'Unknown')],
                    ['Compiled:', header.get('compilationTimestamp', 'Unknown')],
                    ['Entry Point:', header.get('entryPoint', 'Unknown')],
                    ['Subsystem:', header.get('subsystem', 'Unknown')],
                    ['Import Hash:', basic.get('imphash', 'N/A')],
                ]
                pe_table = Table(pe_data, colWidths=[1.5*inch, 5*inch])
                pe_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ]))
                story.append(pe_table)

                # Imports
                imports = pe_analysis.get('imports', [])
                if imports:
                    story.append(Paragraph("Imports:", subheading_style))
                    for imp in imports[:5]:
                        dll = imp.get('dll', 'Unknown')
                        funcs = [f.get('name', '?') for f in imp.get('functions', [])[:5]]
                        func_str = ', '.join(funcs)
                        if len(imp.get('functions', [])) > 5:
                            func_str += f" (+{len(imp['functions']) - 5} more)"
                        story.append(Paragraph(f"  • <b>{dll}:</b> {func_str}", body_style))

                # Suspicious strings (C2, network libs, etc.)
                sus_strings = pe_analysis.get('suspiciousStrings', {})
                if sus_strings:
                    findings = sus_strings.get('findings', [])
                    if findings:
                        story.append(Paragraph("Suspicious Indicators:", subheading_style))
                        for finding in findings[:8]:
                            color = 'red' if 'REVERSE SHELL' in finding or 'C2' in finding else 'orange'
                            story.append(Paragraph(f"  • <font color='{color}'>{finding}</font>", body_style))

                    # Embedded IPs (C2)
                    embedded_ips = sus_strings.get('embeddedIPs', [])
                    if embedded_ips:
                        story.append(Paragraph("Embedded C2/IPs (defanged):", subheading_style))
                        for ip in embedded_ips:
                            defanged = defang_ip(ip.split(':')[0]) + (':' + ip.split(':')[1] if ':' in ip else '')
                            story.append(Paragraph(f"  • <font color='red'><b>{defanged}</b></font>", body_style))

                story.append(Spacer(1, 10))

            # Attack Flow Diagram Data (DLLs, C2, APIs)
            attack_flow = analysis_result.get('attackFlow', {})
            if attack_flow and attack_flow.get('nodes'):
                story.append(Paragraph("Attack Flow Analysis", heading_style))

                nodes = attack_flow.get('nodes', [])

                # C2 Servers
                c2_nodes = [n for n in nodes if n.get('type') == 'ip']
                if c2_nodes:
                    story.append(Paragraph("<font color='red'><b>C2 Server Connections (defanged):</b></font>", subheading_style))
                    for node in c2_nodes:
                        data = node.get('data', {})
                        ip = data.get('ip', '')
                        port = data.get('port', '')
                        c2_addr = f"{ip}:{port}" if port else ip
                        story.append(Paragraph(f"  • <font color='red'><b>{defang_ip(c2_addr)}</b></font>", body_style))
                    story.append(Spacer(1, 5))

                # DLL Loads with full paths
                dll_nodes = [n for n in nodes if n.get('type') == 'dll']
                if dll_nodes:
                    story.append(Paragraph("<b>DLL Loads:</b>", subheading_style))
                    for node in dll_nodes:
                        data = node.get('data', {})
                        dll_name = data.get('dll', node.get('label', 'Unknown'))
                        dll_path = data.get('path', '')
                        if dll_path:
                            story.append(Paragraph(f"  • <b>{dll_name}</b>", body_style))
                            story.append(Paragraph(f"    <font color='#006600'><i>{dll_path}</i></font>", body_style))
                        else:
                            story.append(Paragraph(f"  • {dll_name}", body_style))
                    story.append(Spacer(1, 5))

                # API Calls with source DLLs
                api_nodes = [n for n in nodes if n.get('type') == 'api']
                if api_nodes:
                    story.append(Paragraph("<b>Suspicious API Calls:</b>", subheading_style))
                    for node in api_nodes:
                        data = node.get('data', {})
                        api_name = data.get('api', node.get('label', 'Unknown'))
                        source_dll = data.get('dll', '')
                        severity = node.get('severity', 'info')
                        sev_color = 'red' if severity in ['critical', 'high'] else 'orange' if severity == 'medium' else 'black'
                        if source_dll:
                            story.append(Paragraph(f"  • <font color='{sev_color}'><b>{api_name}</b></font> from <b>{source_dll}</b>", body_style))
                        else:
                            story.append(Paragraph(f"  • <font color='{sev_color}'><b>{api_name}</b></font>", body_style))
                    story.append(Spacer(1, 5))

                # Domain connections
                domain_nodes = [n for n in nodes if n.get('type') == 'domain']
                if domain_nodes:
                    story.append(Paragraph("<b>Domain Connections (defanged):</b>", subheading_style))
                    for node in domain_nodes:
                        data = node.get('data', {})
                        domain = data.get('domain', node.get('label', 'Unknown'))
                        story.append(Paragraph(f"  • {defang_domain(domain)}", body_style))
                    story.append(Spacer(1, 5))

                story.append(Spacer(1, 10))

            # Runtime DLL Loads (from execution)
            execution = analysis_result.get('execution', {})
            dll_loads = execution.get('dllLoads', [])
            if dll_loads:
                story.append(Paragraph("Runtime DLL Loads", heading_style))
                # Filter to show interesting DLLs
                network_dlls = ['ws2_32', 'winhttp', 'wininet', 'dnsapi', 'iphlpapi', 'mswsock']
                security_dlls = ['advapi32', 'crypt32', 'bcrypt', 'ncrypt']

                interesting = []
                other = []
                for dll in dll_loads:
                    dll_lower = dll.lower()
                    if any(net in dll_lower for net in network_dlls):
                        interesting.append(('Network', dll))
                    elif any(sec in dll_lower for sec in security_dlls):
                        interesting.append(('Security', dll))
                    elif 'payload' in dll_lower or 'sandbox' in dll_lower:
                        interesting.append(('Payload', dll))
                    else:
                        other.append(dll)

                if interesting:
                    story.append(Paragraph("<b>Interesting DLLs:</b>", subheading_style))
                    for cat, dll in interesting[:15]:
                        color = 'red' if cat == 'Payload' else 'orange' if cat == 'Network' else 'black'
                        story.append(Paragraph(f"  • <font color='{color}'>[{cat}]</font> {dll}", body_style))

                if other and len(other) <= 10:
                    story.append(Paragraph("<b>Other DLLs:</b>", subheading_style))
                    for dll in other:
                        story.append(Paragraph(f"  • {dll}", body_style))
                elif other:
                    story.append(Paragraph(f"<i>Plus {len(other)} other system DLLs loaded</i>", body_style))

                story.append(Spacer(1, 10))

            # Extracted IOCs
            iocs = analysis_result.get('iocs', {})
            if iocs:
                story.append(Paragraph("Extracted IOCs (defanged)", heading_style))

                ioc_summary = iocs.get('summary', {})
                story.append(Paragraph(
                    f"IPs: {ioc_summary.get('totalIPs', 0)} | "
                    f"URLs: {ioc_summary.get('totalURLs', 0)} | "
                    f"Domains: {ioc_summary.get('totalDomains', 0)} | "
                    f"Hashes: {ioc_summary.get('totalHashes', 0)}",
                    body_style
                ))

                # List IPs (defanged)
                ips = iocs.get('ips', [])
                if ips:
                    story.append(Paragraph("IP Addresses:", subheading_style))
                    for ip in ips[:15]:
                        story.append(Paragraph(f"  • {defang_ip(ip)}", body_style))
                    if len(ips) > 15:
                        story.append(Paragraph(f"  ... and {len(ips) - 15} more", body_style))

                # List domains (defanged)
                domains = iocs.get('domains', [])
                if domains:
                    story.append(Paragraph("Domains:", subheading_style))
                    for domain in domains[:15]:
                        story.append(Paragraph(f"  • {defang_domain(domain)}", body_style))
                    if len(domains) > 15:
                        story.append(Paragraph(f"  ... and {len(domains) - 15} more", body_style))

                story.append(Spacer(1, 10))

            # URL analysis specific (redirect chain, etc.)
            if file_type == 'sandbox_url':
                redirect_chain = analysis_result.get('redirectChain', [])
                if redirect_chain:
                    story.append(Paragraph("Redirect Chain (defanged)", heading_style))
                    for i, redirect in enumerate(redirect_chain):
                        redirect_url = defang_url(redirect.get('url', 'N/A'))
                        story.append(Paragraph(
                            f"{i+1}. [{redirect.get('statusCode')}] {redirect_url[:70]}",
                            body_style
                        ))
                    story.append(Spacer(1, 10))

                if analysis_result.get('finalUrl'):
                    story.append(Paragraph(f"Final URL: {defang_url(analysis_result['finalUrl'][:70])}", body_style))

        # URLs Found (defanged)
        urls = analysis_result.get('urls', [])
        if urls:
            story.append(Paragraph("URLs Detected (defanged)", heading_style))
            for url in urls[:20]:  # Limit to 20
                defanged = defang_url(url)
                url_text = defanged if len(defanged) < 80 else defanged[:77] + "..."
                story.append(Paragraph(f"• {url_text}", body_style))
            if len(urls) > 20:
                story.append(Paragraph(f"... and {len(urls) - 20} more URLs", body_style))
            story.append(Spacer(1, 10))

        # Suspicious Indicators / Phishing Indicators
        indicators = analysis_result.get('suspiciousIndicators', []) or analysis_result.get('phishingIndicators', [])
        if indicators:
            story.append(Paragraph("Suspicious Indicators", heading_style))
            for ind in indicators:
                severity = ind.get('severity', 'unknown')
                ind_type = ind.get('type', 'Unknown')
                desc = ind.get('description', 'N/A')
                severity_color = 'red' if severity == 'high' else ('orange' if severity == 'medium' else 'black')
                ind_text = f"• <font color='{severity_color}'>[{severity.upper()}]</font> {ind_type}: {desc}"
                story.append(Paragraph(ind_text, body_style))
            story.append(Spacer(1, 10))

        # Process Triggers (Office)
        proc_triggers = analysis_result.get('processTriggers', [])
        if proc_triggers:
            story.append(Paragraph("Process Execution Patterns", heading_style))
            for proc in proc_triggers:
                story.append(Paragraph(f"• {proc.get('type', 'Unknown')}", body_style))
            story.append(Spacer(1, 10))

        # IOC Investigation Results
        ioc_inv = analysis_result.get('iocInvestigation', {})
        if ioc_inv:
            story.append(PageBreak())
            story.append(Paragraph("IOC Investigation Results", heading_style))

            summary = ioc_inv.get('summary', {})
            if summary:
                story.append(Paragraph(f"Total IOCs Investigated: {summary.get('totalIOCs', 0)}", body_style))
                story.append(Paragraph(f"Malicious IOCs Found: {summary.get('maliciousIOCs', 0)}", body_style))
                story.append(Spacer(1, 10))

            # URL investigations (defanged)
            url_invs = ioc_inv.get('urls', [])
            if url_invs:
                story.append(Paragraph("URL Investigation Details (defanged)", subheading_style))
                for url_inv in url_invs[:10]:
                    url_summary = url_inv.get('summary', {})
                    status = "MALICIOUS" if url_summary.get('isMalicious') else "Clean"
                    risk = url_summary.get('riskScore', 0)
                    inv_url = defang_url(url_inv.get('url', 'N/A'))
                    story.append(Paragraph(f"• [{status}] (Risk: {risk}) {inv_url[:60]}", body_style))
                story.append(Spacer(1, 10))

        # Screenshots section
        if include_screenshot and analysis_result.get('screenshots'):
            story.append(PageBreak())
            story.append(Paragraph("URL Screenshots", heading_style))

            for screenshot in analysis_result.get('screenshots', []):
                if screenshot.get('screenshot_base64'):
                    try:
                        img_data = base64.b64decode(screenshot['screenshot_base64'])
                        img_buffer = io.BytesIO(img_data)
                        img = Image(img_buffer, width=6*inch, height=4*inch)
                        screenshot_url = defang_url(screenshot.get('url', 'N/A'))
                        story.append(Paragraph(f"URL: {screenshot_url}", body_style))
                        story.append(img)
                        story.append(Spacer(1, 15))
                    except Exception as e:
                        screenshot_url = defang_url(screenshot.get('url', 'N/A'))
                        story.append(Paragraph(f"Screenshot for {screenshot_url}: Error loading image", body_style))

        # Footer
        story.append(Spacer(1, 30))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cccccc')))
        story.append(Spacer(1, 10))
        story.append(Paragraph(
            "<font size='8' color='#666666'>This report was generated by ShieldTier (ShieldTier Threat Intelligence)."
            "The information contained herein is for authorized security analysis purposes only.</font>",
            styles['Normal']
        ))

        # Build PDF
        doc.build(story)
        return True

    except Exception as e:
        print(f"PDF generation error: {e}")
        import traceback
        traceback.print_exc()
        return False


def export_analysis_to_pdf(analysis_result: Dict, secret_key: str,
                           output_path: Optional[str] = None,
                           include_screenshot: bool = True) -> Dict:
    """
    Export analysis results to encrypted PDF

    Args:
        analysis_result: The analysis result dictionary
        secret_key: Password for PDF encryption
        output_path: Optional output path (auto-generated if not provided)
        include_screenshot: Whether to include URL screenshots

    Returns:
        Dict with export status and file info
    """

    result = {
        'success': False,
        'pdf_path': None,
        'pdf_base64': None,
        'file_size': 0,
        'encrypted': False,
        'error': None,
    }

    # Check capabilities
    caps = check_pdf_available()
    if not caps['pdf_generation']:
        result['error'] = "PDF generation not available. Install reportlab: pip install reportlab"
        return result

    # Generate output path if not provided
    if not output_path:
        entry_ref = analysis_result.get('entryRef', 'report')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = os.path.join(os.path.dirname(__file__), 'exports')
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"analysis_{entry_ref}_{timestamp}.pdf")

    # Create temporary unencrypted PDF
    temp_path = output_path + '.tmp'

    try:
        # Generate PDF
        if not create_analysis_pdf(analysis_result, temp_path, include_screenshot):
            result['error'] = "Failed to generate PDF"
            return result

        # Encrypt PDF
        if caps['pdf_encryption']:
            if PDF_ENCRYPTION == 'pypdf2':
                encrypted = encrypt_pdf_pypdf2(temp_path, output_path, secret_key)
            elif PDF_ENCRYPTION == 'pikepdf':
                encrypted = encrypt_pdf_pikepdf(temp_path, output_path, secret_key)
            else:
                encrypted = False

            if encrypted:
                result['encrypted'] = True
                os.remove(temp_path)
            else:
                # Fall back to unencrypted
                os.rename(temp_path, output_path)
                result['encrypted'] = False
        else:
            # No encryption available
            os.rename(temp_path, output_path)
            result['encrypted'] = False

        # Read PDF and encode as base64
        with open(output_path, 'rb') as f:
            result['pdf_base64'] = base64.b64encode(f.read()).decode('utf-8')

        result['success'] = True
        result['pdf_path'] = output_path
        result['file_size'] = os.path.getsize(output_path)

    except Exception as e:
        result['error'] = f"Export error: {str(e)}"
        # Cleanup temp file
        if os.path.exists(temp_path):
            os.remove(temp_path)

    return result


def get_export_status() -> Dict:
    """Get PDF export service status"""
    caps = check_pdf_available()

    return {
        'service': 'pdf_export',
        'status': 'available' if caps['pdf_generation'] else 'unavailable',
        'capabilities': caps,
        'export_dir': os.path.join(os.path.dirname(__file__), 'exports'),
    }


# CLI interface for testing
if __name__ == '__main__':
    import sys

    print("PDF Export Service Status:")
    print(json.dumps(get_export_status(), indent=2))

    if len(sys.argv) > 1:
        # Test with a sample analysis result
        sample_result = {
            'type': 'email',
            'filename': 'test_phishing.eml',
            'entryRef': 'TEST001',
            'riskScore': 75,
            'riskLevel': 'High',
            'headers': {
                'from': 'attacker@malicious.com',
                'to': 'victim@company.com',
                'subject': 'Urgent: Action Required',
            },
            'urls': [
                'http://malicious-site.com/phishing',
                'http://evil-tracker.ru/pixel.gif',
            ],
            'attachments': [
                {'filename': 'invoice.exe', 'size': 1024, 'isExecutable': True}
            ],
            'suspiciousIndicators': [
                {'type': 'Executable', 'description': 'Contains executable attachment'},
                {'type': 'Phishing', 'description': 'Suspicious sender domain'},
            ],
        }

        secret_key = sys.argv[1]
        print(f"\nGenerating test PDF with password: {secret_key}")

        result = export_analysis_to_pdf(sample_result, secret_key)
        print(json.dumps({k: v for k, v in result.items() if k != 'pdf_base64'}, indent=2))
