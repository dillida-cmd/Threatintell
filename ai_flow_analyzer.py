#!/usr/bin/env python3
"""
AI Attack Flow Analyzer
Generates detailed sequential attack flow diagrams showing step-by-step
what happens when a URL is visited or a file is executed.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
from urllib.parse import urlparse
import re


def parse_strace_output(strace_output: str) -> Dict:
    """Parse strace output to extract execution behavior"""
    result = {
        'processes': [],      # execve calls
        'files_read': [],     # openat/read calls
        'files_written': [],  # write calls
        'network': [],        # socket/connect calls
        'commands': [],       # shell commands executed
    }

    if not strace_output:
        return result

    seen_procs = set()
    seen_files = set()

    for line in strace_output.split('\n'):
        # Process execution: execve("/bin/bash", ["/bin/bash", "script.sh"], ...)
        if 'execve(' in line:
            match = re.search(r'execve\("([^"]+)"', line)
            if match:
                cmd = match.group(1)
                # Extract command name
                cmd_name = cmd.split('/')[-1]
                if cmd_name not in seen_procs and cmd_name not in ['bash', 'sh', 'dash']:
                    seen_procs.add(cmd_name)
                    result['processes'].append({
                        'command': cmd_name,
                        'path': cmd,
                    })

        # File operations: openat(AT_FDCWD, "/etc/passwd", O_RDONLY)
        if 'openat(' in line and '= ' in line and '= -1' not in line:
            match = re.search(r'openat\([^,]+,\s*"([^"]+)"', line)
            if match:
                filepath = match.group(1)
                # Filter interesting files (not system libs)
                if not any(skip in filepath for skip in ['/lib/', '/usr/lib/', '/proc/', '/sys/', 'ld.so', '.so.']):
                    if filepath not in seen_files:
                        seen_files.add(filepath)
                        if 'O_WRONLY' in line or 'O_RDWR' in line or 'O_CREAT' in line:
                            result['files_written'].append(filepath)
                        else:
                            result['files_read'].append(filepath)

        # Network: socket() or connect()
        if 'socket(' in line and 'AF_INET' in line:
            result['network'].append({'type': 'socket', 'details': 'TCP/IP socket created'})
        if 'connect(' in line and 'AF_INET' in line:
            # Try to extract IP:port
            match = re.search(r'sin_addr=inet_addr\("([^"]+)"\).*sin_port=htons\((\d+)\)', line)
            if match:
                result['network'].append({
                    'type': 'connect',
                    'ip': match.group(1),
                    'port': match.group(2)
                })

    return result


class AttackFlowAnalyzer:
    """Analyzes URL/sandbox results and generates detailed sequential attack flow"""

    # MITRE ATT&CK technique mappings
    MITRE_TECHNIQUES = {
        'VirtualProtect': {'id': 'T1055', 'name': 'Process Injection', 'tactic': 'Defense Evasion'},
        'VirtualAlloc': {'id': 'T1055', 'name': 'Process Injection', 'tactic': 'Defense Evasion'},
        'WriteProcessMemory': {'id': 'T1055.001', 'name': 'DLL Injection', 'tactic': 'Defense Evasion'},
        'CreateRemoteThread': {'id': 'T1055.001', 'name': 'DLL Injection', 'tactic': 'Privilege Escalation'},
        'NtUnmapViewOfSection': {'id': 'T1055.012', 'name': 'Process Hollowing', 'tactic': 'Defense Evasion'},
        'GetProcAddress': {'id': 'T1106', 'name': 'Native API', 'tactic': 'Execution'},
        'LoadLibrary': {'id': 'T1129', 'name': 'Shared Modules', 'tactic': 'Execution'},
        'ws2_32': {'id': 'T1071', 'name': 'Application Layer Protocol', 'tactic': 'C2'},
        'InternetConnect': {'id': 'T1071.001', 'name': 'Web Protocols', 'tactic': 'C2'},
        'HttpOpenRequest': {'id': 'T1071.001', 'name': 'Web Protocols', 'tactic': 'C2'},
        'WSAStartup': {'id': 'T1095', 'name': 'Non-Application Layer Protocol', 'tactic': 'C2'},
        'connect': {'id': 'T1095', 'name': 'Non-Application Layer Protocol', 'tactic': 'C2'},
        'RegSetValue': {'id': 'T1547.001', 'name': 'Registry Run Keys', 'tactic': 'Persistence'},
        'CreateService': {'id': 'T1543.003', 'name': 'Windows Service', 'tactic': 'Persistence'},
        'ShellExecute': {'id': 'T1059', 'name': 'Command and Scripting', 'tactic': 'Execution'},
        'CreateProcess': {'id': 'T1106', 'name': 'Native API', 'tactic': 'Execution'},
    }

    # Suspicious DLLs
    SUSPICIOUS_DLLS = {
        'ws2_32.dll': 'Network Socket Library',
        'wininet.dll': 'Internet Functions',
        'winhttp.dll': 'HTTP Services',
        'urlmon.dll': 'URL Moniker',
        'crypt32.dll': 'Cryptographic Functions',
        'advapi32.dll': 'Registry/Security',
        'ntdll.dll': 'Native API',
        'kernel32.dll': 'Core Windows API',
        'mswsock.dll': 'Winsock Helper',
        'wshtcpip.dll': 'TCP/IP Helper',
    }

    # Files that indicate malicious behavior
    SUSPICIOUS_FILES = {
        'apphelp.dll': 'Application Compatibility',
        'sysmain.sdb': 'Shim Database',
        'mswsock.dll': 'Winsock Extension',
        'wshtcpip.dll': 'TCP/IP Winsock Helper',
    }

    # Registry paths indicating persistence or evasion
    SUSPICIOUS_REGISTRY = {
        'Run': 'Autostart Persistence',
        'RunOnce': 'One-time Autostart',
        'Services': 'Service Registration',
        'AppCompatFlags': 'Compatibility Evasion',
        'Shell Folders': 'User Profile Enum',
        'Winsock': 'Network Configuration',
        'Session Manager': 'Boot Configuration',
    }

    def __init__(self):
        self.node_id_counter = 0

    def _generate_node_id(self) -> str:
        """Generate unique node ID"""
        self.node_id_counter += 1
        return f"node_{self.node_id_counter}"

    def analyze_url_flow(self, analysis: Dict) -> Dict:
        """
        Analyze URL analysis results and generate attack flow
        Shows: Initial Request → Redirects → Final Page → Resources → Risks
        """
        self.node_id_counter = 0
        nodes = []
        edges = []

        url = analysis.get('url', '')
        final_url = analysis.get('finalUrl', analysis.get('final_url', url))
        redirect_chain = analysis.get('redirectChain', analysis.get('redirect_chain', []))
        screenshots = analysis.get('screenshots', [])
        risk_score = analysis.get('riskScore', analysis.get('risk_score', 0))

        # Get AI validated score if available
        ai_validation = analysis.get('aiValidation', {})
        if ai_validation and 'validatedScore' in ai_validation:
            risk_score = ai_validation['validatedScore']

        dns = analysis.get('dns', {})

        # Parse initial URL
        parsed_url = urlparse(url) if url else None
        initial_domain = parsed_url.netloc if parsed_url else 'Unknown'

        # Step 1: User Action (Entry Point)
        entry_node = self._generate_node_id()
        nodes.append({
            'id': entry_node,
            'type': 'entry',
            'label': 'User Clicks URL',
            'description': 'User initiates request',
            'data': {'action': 'click', 'target': url[:50] + '...' if len(url) > 50 else url},
            'step': 1,
            'severity': 'info'
        })

        # Step 2: DNS Resolution
        dns_node = self._generate_node_id()
        a_records = dns.get('records', {}).get('A', []) if dns else []
        nodes.append({
            'id': dns_node,
            'type': 'dns',
            'label': f'DNS Lookup: {initial_domain}',
            'description': f'Resolves to {a_records[0]}' if a_records else 'Resolving domain',
            'data': {'domain': initial_domain, 'ips': a_records},
            'step': 2,
            'severity': 'info'
        })
        edges.append({'source': entry_node, 'target': dns_node, 'label': 'DNS Query', 'type': 'request', 'style': 'dotted'})

        prev_node = dns_node
        step = 3

        # Step 3: HTTP Request
        http_node = self._generate_node_id()
        nodes.append({
            'id': http_node,
            'type': 'http',
            'label': 'HTTP Request',
            'description': f'GET {url[:40]}...' if len(url) > 40 else f'GET {url}',
            'data': {'method': 'GET', 'url': url, 'domain': initial_domain},
            'step': step,
            'severity': 'info'
        })
        edges.append({'source': prev_node, 'target': http_node, 'label': 'Connect', 'type': 'connection', 'style': 'dotted'})
        prev_node = http_node
        step += 1

        # Redirect Chain
        if redirect_chain:
            for i, redirect in enumerate(redirect_chain):
                redirect_url = redirect.get('url', redirect) if isinstance(redirect, dict) else redirect
                status_code = redirect.get('statusCode', 302) if isinstance(redirect, dict) else 302
                parsed_redirect = urlparse(redirect_url)
                is_cross_domain = parsed_redirect.netloc != initial_domain

                redirect_node = self._generate_node_id()
                nodes.append({
                    'id': redirect_node,
                    'type': 'redirect',
                    'label': f'Redirect {status_code}',
                    'description': f'→ {parsed_redirect.netloc}',
                    'data': {'url': redirect_url, 'statusCode': status_code, 'crossDomain': is_cross_domain},
                    'step': step,
                    'severity': 'warning' if is_cross_domain else 'info'
                })
                edges.append({'source': prev_node, 'target': redirect_node, 'label': f'{status_code}', 'type': 'redirect', 'style': 'dotted'})
                prev_node = redirect_node
                step += 1

        # Final Page
        if final_url and final_url != url:
            parsed_final = urlparse(final_url)
            final_node = self._generate_node_id()
            nodes.append({
                'id': final_node,
                'type': 'page',
                'label': 'Final Page',
                'description': parsed_final.netloc,
                'data': {'url': final_url, 'domain': parsed_final.netloc},
                'step': step,
                'severity': 'info'
            })
            edges.append({'source': prev_node, 'target': final_node, 'label': '200 OK', 'type': 'response', 'style': 'dotted'})
            prev_node = final_node
            step += 1

        # Screenshot
        if screenshots:
            render_node = self._generate_node_id()
            nodes.append({
                'id': render_node,
                'type': 'render',
                'label': 'Page Rendered',
                'description': f'{len(screenshots)} screenshot(s)',
                'data': {'screenshots': len(screenshots)},
                'step': step,
                'severity': 'info'
            })
            edges.append({'source': prev_node, 'target': render_node, 'label': 'Render', 'type': 'action', 'style': 'dotted'})
            prev_node = render_node
            step += 1

        # Risk Assessment
        risk_node = self._generate_node_id()
        risk_severity = 'critical' if risk_score >= 70 else 'high' if risk_score >= 50 else 'medium' if risk_score >= 30 else 'low'
        nodes.append({
            'id': risk_node,
            'type': 'assessment',
            'label': f'Risk Score: {risk_score}/100',
            'description': f'{risk_severity.upper()} risk level',
            'data': {'score': risk_score, 'level': risk_severity},
            'step': step,
            'severity': risk_severity
        })
        edges.append({'source': prev_node, 'target': risk_node, 'label': 'Analysis', 'type': 'assessment', 'style': 'dotted'})

        return {
            'nodes': nodes,
            'edges': edges,
            'summary': {
                'totalSteps': len(nodes),
                'redirects': len(redirect_chain),
                'riskScore': risk_score
            },
            'timeline': [{'step': n['step'], 'label': n['label'], 'type': n['type']} for n in sorted(nodes, key=lambda x: x['step'])]
        }

    def analyze_sandbox_flow(self, analysis: Dict) -> Dict:
        """
        Analyze sandbox execution and generate a relationship graph (VirusTotal style)
        Central node is the file, with connected nodes for IPs, DLLs, APIs, domains
        """
        self.node_id_counter = 0
        nodes = []
        edges = []

        filename = analysis.get('filename', analysis.get('file_name', 'unknown'))
        file_analysis = analysis.get('fileAnalysis', analysis.get('file_analysis', {}))
        pe_analysis = analysis.get('peAnalysis', analysis.get('pe_analysis', {}))
        execution = analysis.get('execution', {})
        iocs = analysis.get('iocs', analysis.get('extractedIocs', {}))
        risk_score = analysis.get('riskScore', analysis.get('risk_score', 0))

        # Get DLLs loaded
        dlls_from_exec = analysis.get('dllLoads', [])
        if not dlls_from_exec and execution:
            dlls_from_exec = execution.get('dllLoads', [])

        # Get embedded IPs from PE analysis
        embedded_ips = []
        if pe_analysis:
            suspicious_strings = pe_analysis.get('suspiciousStrings', {})
            embedded_ips = suspicious_strings.get('embeddedIPs', [])

        # Get IOC IPs
        ioc_ips = iocs.get('ips', [])
        all_ips = list(set(embedded_ips + ioc_ips))

        # Get domains
        ioc_domains = iocs.get('domains', [])

        # Get imports (APIs)
        imports = []
        if pe_analysis:
            for imp in pe_analysis.get('imports', []):
                dll_name = imp.get('dll', '')
                for func in imp.get('functions', []):
                    func_name = func.get('name', func) if isinstance(func, dict) else func
                    if isinstance(func_name, str):
                        imports.append({'dll': dll_name, 'api': func_name})

        # ===== CREATE CENTRAL FILE NODE =====
        file_hash = file_analysis.get('hashes', {}).get('sha256', '')[:16] or 'unknown'
        file_node_id = 'file_main'
        file_size = file_analysis.get('fileSize', file_analysis.get('size', 0))

        nodes.append({
            'id': file_node_id,
            'type': 'file',
            'label': filename[:25] + ('...' if len(filename) > 25 else ''),
            'description': f'{self._format_size(file_size)}',
            'data': {
                'filename': filename,
                'hash': file_hash,
                'size': file_size,
                'fileType': file_analysis.get('fileType', 'Unknown')
            },
            'severity': 'critical' if risk_score >= 70 else 'high' if risk_score >= 40 else 'medium',
            'isCenter': True  # Mark as center node for layout
        })

        # ===== CREATE IP NODES =====
        for i, ip in enumerate(all_ips[:5]):  # Limit to 5 IPs
            ip_node_id = f'ip_{i}'
            # Parse IP:port if present
            if ':' in ip:
                ip_addr, port = ip.rsplit(':', 1)
                label = f'{ip_addr}:{port}'
            else:
                ip_addr = ip
                label = ip

            nodes.append({
                'id': ip_node_id,
                'type': 'ip',
                'label': label,
                'description': 'C2 Server' if ':' in ip else 'IP Address',
                'data': {'ip': ip_addr, 'port': port if ':' in ip else None},
                'severity': 'critical'
            })
            edges.append({
                'source': file_node_id,
                'target': ip_node_id,
                'label': 'connects',
                'type': 'network',
                'style': 'dotted'
            })

        # ===== CREATE DOMAIN NODES =====
        for i, domain in enumerate(ioc_domains[:3]):  # Limit to 3 domains
            domain_node_id = f'domain_{i}'
            nodes.append({
                'id': domain_node_id,
                'type': 'domain',
                'label': domain[:20] + ('...' if len(domain) > 20 else ''),
                'description': 'Domain',
                'data': {'domain': domain},
                'severity': 'high'
            })
            edges.append({
                'source': file_node_id,
                'target': domain_node_id,
                'label': 'resolves',
                'type': 'dns',
                'style': 'dotted'
            })

        # ===== CREATE DLL NODES (filtered) =====
        # Filter out Wine system DLLs
        wine_system = {'wineboot', 'winemenu', 'services', 'winedevice', 'plugplay',
                       'svchost', 'explorer', 'ntoskrnl', 'conhost', 'rundll32'}
        system_dlls = {'kernel32', 'kernelbase', 'ntdll', 'msvcrt', 'ucrtbase', 'advapi32', 'sechost'}

        interesting_dlls = []
        for dll in dlls_from_exec:
            dll_name = dll.split('\\')[-1].split('/')[-1].lower()
            base_name = dll_name.replace('.dll', '').replace('.exe', '')
            if base_name not in wine_system and base_name not in system_dlls:
                if dll_name not in [d.split('\\')[-1].split('/')[-1].lower() for d in interesting_dlls]:
                    interesting_dlls.append(dll)

        # Prioritize network DLLs
        network_dll_names = ['ws2_32', 'mswsock', 'wshtcpip', 'wininet', 'winhttp', 'dnsapi', 'iphlpapi']
        network_dlls = [d for d in dlls_from_exec if any(n in d.lower() for n in network_dll_names)]

        # Add network DLLs first
        dll_nodes_added = 0
        for dll in network_dlls[:3]:
            dll_name = dll.split('\\')[-1].split('/')[-1]
            dll_node_id = f'dll_{dll_nodes_added}'
            nodes.append({
                'id': dll_node_id,
                'type': 'dll',
                'label': dll_name,
                'description': 'Network Library',
                'data': {'dll': dll_name, 'path': dll},
                'severity': 'high'
            })
            edges.append({
                'source': file_node_id,
                'target': dll_node_id,
                'label': 'loads',
                'type': 'library',
                'style': 'dotted'
            })
            dll_nodes_added += 1

        # Add other interesting DLLs
        for dll in interesting_dlls[:3]:
            if dll_nodes_added >= 5:
                break
            dll_name = dll.split('\\')[-1].split('/')[-1]
            if any(dll_name.lower() == d.split('\\')[-1].split('/')[-1].lower() for d in network_dlls):
                continue  # Skip if already added
            dll_node_id = f'dll_{dll_nodes_added}'
            nodes.append({
                'id': dll_node_id,
                'type': 'dll',
                'label': dll_name,
                'description': 'Library',
                'data': {'dll': dll_name, 'path': dll},
                'severity': 'info'
            })
            edges.append({
                'source': file_node_id,
                'target': dll_node_id,
                'label': 'loads',
                'type': 'library',
                'style': 'dotted'
            })
            dll_nodes_added += 1

        # ===== CREATE API NODES (suspicious APIs only) =====
        suspicious_apis = ['VirtualProtect', 'VirtualAlloc', 'WriteProcessMemory',
                          'CreateRemoteThread', 'LoadLibrary', 'GetProcAddress',
                          'WSAStartup', 'connect', 'send', 'recv', 'socket']

        api_nodes_added = 0
        for imp in imports:
            if api_nodes_added >= 4:
                break
            api_name = imp.get('api', '')
            if any(s in api_name for s in suspicious_apis):
                api_node_id = f'api_{api_nodes_added}'

                # Determine API category
                if any(x in api_name for x in ['Virtual', 'Memory', 'Process']):
                    desc = 'Memory Manipulation'
                    severity = 'critical'
                elif any(x in api_name for x in ['WSA', 'connect', 'send', 'recv', 'socket']):
                    desc = 'Network API'
                    severity = 'high'
                else:
                    desc = 'Dynamic Loading'
                    severity = 'warning'

                nodes.append({
                    'id': api_node_id,
                    'type': 'api',
                    'label': api_name,
                    'description': desc,
                    'data': {'api': api_name, 'dll': imp.get('dll', '')},
                    'severity': severity
                })
                edges.append({
                    'source': file_node_id,
                    'target': api_node_id,
                    'label': 'calls',
                    'type': 'api',
                    'style': 'dotted'
                })
                api_nodes_added += 1

        # ===== RETURN GRAPH DATA =====
        return {
            'nodes': nodes,
            'edges': edges,
            'layoutType': 'radial',  # Tell frontend to use radial layout
            'centerNode': file_node_id,
            'summary': {
                'totalNodes': len(nodes),
                'ips': len([n for n in nodes if n['type'] == 'ip']),
                'dlls': len([n for n in nodes if n['type'] == 'dll']),
                'apis': len([n for n in nodes if n['type'] == 'api']),
                'domains': len([n for n in nodes if n['type'] == 'domain'])
            }
        }
    def _format_size(self, size: int) -> str:
        """Format file size"""
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024 * 1024):.1f} MB"


# Singleton instance
_analyzer = None

def get_analyzer() -> AttackFlowAnalyzer:
    """Get singleton analyzer instance"""
    global _analyzer
    if _analyzer is None:
        _analyzer = AttackFlowAnalyzer()
    return _analyzer


def analyze_url_flow(analysis: Dict) -> Dict:
    """Convenience function for URL flow analysis"""
    return get_analyzer().analyze_url_flow(analysis)


def analyze_sandbox_flow(analysis: Dict) -> Dict:
    """Convenience function for sandbox flow analysis"""
    return get_analyzer().analyze_sandbox_flow(analysis)
