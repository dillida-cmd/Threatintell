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
        story.append(Paragraph("<font size='10' color='#666666'>Powered by MTI</font>", styles['Normal']))
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

        # Analysis type and file info
        file_type = analysis_result.get('type', 'Unknown')
        filename = analysis_result.get('filename', 'N/A')

        story.append(Paragraph("File Information", heading_style))
        file_info = [
            ['Type:', file_type.upper()],
            ['Filename:', filename],
        ]

        if analysis_result.get('documentType'):
            file_info.append(['Document Type:', analysis_result['documentType']])

        file_table = Table(file_info, colWidths=[1.5*inch, 5*inch])
        file_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(file_table)
        story.append(Spacer(1, 15))

        # Risk Assessment
        story.append(Paragraph("Risk Assessment", heading_style))

        risk_score = analysis_result.get('riskScore', 0)
        risk_level = analysis_result.get('riskLevel', 'Unknown')

        # Color code risk level
        risk_color = colors.green
        if risk_score >= 70:
            risk_color = colors.red
        elif risk_score >= 40:
            risk_color = colors.orange

        risk_data = [
            ['Risk Score:', f"{risk_score}/100"],
            ['Risk Level:', risk_level],
        ]

        risk_table = Table(risk_data, colWidths=[1.5*inch, 5*inch])
        risk_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('TEXTCOLOR', (1, 0), (1, 0), risk_color),
            ('TEXTCOLOR', (1, 1), (1, 1), risk_color),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 15))

        # Email-specific sections
        if file_type == 'email':
            # Headers
            headers = analysis_result.get('headers', {})
            if headers:
                story.append(Paragraph("Email Headers", heading_style))
                header_data = []
                for key in ['from', 'to', 'subject', 'date', 'return-path', 'x-originating-ip']:
                    if headers.get(key):
                        header_data.append([key.title() + ':', str(headers[key])[:80]])

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

            # Extracted IOCs
            iocs = analysis_result.get('iocs', {})
            if iocs:
                story.append(Paragraph("Extracted IOCs", heading_style))

                ioc_summary = iocs.get('summary', {})
                story.append(Paragraph(
                    f"IPs: {ioc_summary.get('totalIPs', 0)} | "
                    f"URLs: {ioc_summary.get('totalURLs', 0)} | "
                    f"Domains: {ioc_summary.get('totalDomains', 0)} | "
                    f"Hashes: {ioc_summary.get('totalHashes', 0)}",
                    body_style
                ))

                # List IPs
                ips = iocs.get('ips', [])
                if ips:
                    story.append(Paragraph("IP Addresses:", subheading_style))
                    for ip in ips[:15]:
                        story.append(Paragraph(f"  • {ip}", body_style))
                    if len(ips) > 15:
                        story.append(Paragraph(f"  ... and {len(ips) - 15} more", body_style))

                # List domains
                domains = iocs.get('domains', [])
                if domains:
                    story.append(Paragraph("Domains:", subheading_style))
                    for domain in domains[:15]:
                        story.append(Paragraph(f"  • {domain}", body_style))
                    if len(domains) > 15:
                        story.append(Paragraph(f"  ... and {len(domains) - 15} more", body_style))

                story.append(Spacer(1, 10))

            # URL analysis specific (redirect chain, etc.)
            if file_type == 'sandbox_url':
                redirect_chain = analysis_result.get('redirectChain', [])
                if redirect_chain:
                    story.append(Paragraph("Redirect Chain", heading_style))
                    for i, redirect in enumerate(redirect_chain):
                        story.append(Paragraph(
                            f"{i+1}. [{redirect.get('statusCode')}] {redirect.get('url', 'N/A')[:60]}",
                            body_style
                        ))
                    story.append(Spacer(1, 10))

                if analysis_result.get('finalUrl'):
                    story.append(Paragraph(f"Final URL: {analysis_result['finalUrl'][:70]}", body_style))

        # URLs Found
        urls = analysis_result.get('urls', [])
        if urls:
            story.append(Paragraph("URLs Detected", heading_style))
            for url in urls[:20]:  # Limit to 20
                url_text = url if len(url) < 70 else url[:67] + "..."
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

            # URL investigations
            url_invs = ioc_inv.get('urls', [])
            if url_invs:
                story.append(Paragraph("URL Investigation Details", subheading_style))
                for url_inv in url_invs[:10]:
                    url_summary = url_inv.get('summary', {})
                    status = "MALICIOUS" if url_summary.get('isMalicious') else "Clean"
                    risk = url_summary.get('riskScore', 0)
                    story.append(Paragraph(f"• [{status}] (Risk: {risk}) {url_inv.get('url', 'N/A')[:50]}", body_style))
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
                        story.append(Paragraph(f"URL: {screenshot.get('url', 'N/A')}", body_style))
                        story.append(img)
                        story.append(Spacer(1, 15))
                    except Exception as e:
                        story.append(Paragraph(f"Screenshot for {screenshot.get('url', 'N/A')}: Error loading image", body_style))

        # Footer
        story.append(Spacer(1, 30))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cccccc')))
        story.append(Spacer(1, 10))
        story.append(Paragraph(
            "<font size='8' color='#666666'>This report was generated by ShieldTier (Powered by MTI)."
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
