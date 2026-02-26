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
import sqlite3
import os
import json


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
        Pure behavioral chain: what actually happens step-by-step when the
        link is clicked.  No intel scores — only real observed actions.

        SafeLinks unwrap → actual domain → DNS resolves to IP → HTTP connects →
        redirects (each hop) → final destination → page served →
        payloads downloaded → outbound connections
        """
        self.node_id_counter = 0
        nodes = []
        edges = []
        step = 1

        url = analysis.get('url', '')
        parsed_url = urlparse(url) if url else None
        domain = parsed_url.netloc if parsed_url else 'Unknown'

        url_unwrap = analysis.get('urlUnwrap', {})
        sources = analysis.get('sources', {})
        vt = sources.get('virustotal', {})
        urlhaus = sources.get('urlhaus', {})
        dns_data = analysis.get('dns', {})
        redirect_chain = analysis.get('redirectChain', analysis.get('redirect_chain', []))
        final_url = analysis.get('finalUrl', analysis.get('final_url', ''))
        urlhaus_payloads = urlhaus.get('payloads', [])

        prev_node = None

        # ===== STEP: SafeLinks / Proofpoint unwrap (if wrapped) =====
        if url_unwrap.get('wasWrapped'):
            wrapper_id = self._generate_node_id()
            service = url_unwrap.get('wrapperService', 'URL Wrapper')
            wrapper_url = url_unwrap.get('wrapperUrl', '')
            wrapper_domain = urlparse(wrapper_url).netloc if wrapper_url else service
            nodes.append({
                'id': wrapper_id,
                'type': 'evasion',
                'label': wrapper_domain[:30],
                'description': service,
                'data': {
                    'wrapperService': service,
                    'wrapperUrl': wrapper_url,
                    'actualUrl': url_unwrap.get('actualUrl', ''),
                },
                'step': step,
                'severity': 'warning',
            })
            prev_node = wrapper_id
            step += 1

            # Unwrap edge → actual domain
            unwrap_id = self._generate_node_id()
            nodes.append({
                'id': unwrap_id,
                'type': 'redirect',
                'label': f'Unwrap → {domain[:25]}',
                'description': f'{service} strips wrapper',
                'data': {'url': url, 'domain': domain, 'wrapperService': service},
                'step': step,
                'severity': 'info',
            })
            edges.append({'source': prev_node, 'target': unwrap_id, 'label': 'unwraps', 'type': 'redirect'})
            prev_node = unwrap_id
            step += 1

        # ===== STEP: DNS resolution =====
        a_records = dns_data.get('records', {}).get('A', []) if dns_data else []
        dns_id = self._generate_node_id()
        if a_records:
            dns_desc = ', '.join(a_records[:3])
        else:
            dns_desc = 'resolving...'
        nodes.append({
            'id': dns_id,
            'type': 'dns',
            'label': f'{domain}',
            'description': f'→ {dns_desc}',
            'data': {'domain': domain, 'ips': a_records},
            'step': step,
            'severity': 'info',
        })
        if prev_node:
            edges.append({'source': prev_node, 'target': dns_id, 'label': 'DNS query', 'type': 'dns'})
        prev_node = dns_id
        step += 1

        # ===== STEP: Connect to resolved IP(s) =====
        connect_target = prev_node  # track who the HTTP node connects from
        if a_records:
            ip_id = self._generate_node_id()
            ip_display = a_records[0]
            port = '443' if (parsed_url and parsed_url.scheme == 'https') else '80'
            nodes.append({
                'id': ip_id,
                'type': 'ip',
                'label': f'{ip_display}:{port}',
                'description': f'TCP connect',
                'data': {'ip': ip_display, 'port': port, 'allIps': a_records},
                'step': step,
                'severity': 'info',
            })
            edges.append({'source': prev_node, 'target': ip_id, 'label': f':{port}', 'type': 'network'})
            prev_node = ip_id
            step += 1

        # ===== STEP: HTTP request =====
        http_id = self._generate_node_id()
        scheme = parsed_url.scheme.upper() if parsed_url else 'HTTP'
        path = parsed_url.path if parsed_url else '/'
        nodes.append({
            'id': http_id,
            'type': 'http',
            'label': f'{scheme} GET',
            'description': f'{domain}{path[:30]}',
            'data': {'method': 'GET', 'url': url, 'domain': domain, 'scheme': scheme},
            'step': step,
            'severity': 'info',
        })
        edges.append({'source': prev_node, 'target': http_id, 'label': f'{scheme} GET', 'type': 'request'})
        prev_node = http_id
        step += 1

        # ===== STEP: Redirect chain (each real hop) =====
        if redirect_chain:
            for i, redirect in enumerate(redirect_chain):
                redirect_url = redirect.get('url', redirect) if isinstance(redirect, dict) else redirect
                status_code = redirect.get('statusCode', 302) if isinstance(redirect, dict) else 302
                parsed_redir = urlparse(redirect_url)
                redir_domain = parsed_redir.netloc
                is_cross = redir_domain != domain

                redir_id = self._generate_node_id()
                nodes.append({
                    'id': redir_id,
                    'type': 'redirect',
                    'label': f'{status_code} → {redir_domain[:22]}',
                    'description': redir_domain,
                    'data': {
                        'url': redirect_url, 'domain': redir_domain,
                        'statusCode': status_code, 'crossDomain': is_cross,
                    },
                    'step': step,
                    'severity': 'warning' if is_cross else 'info',
                })
                edges.append({'source': prev_node, 'target': redir_id, 'label': str(status_code), 'type': 'redirect'})
                prev_node = redir_id
                step += 1

        # Also check VT finalUrl as an observed redirect destination
        vt_final = vt.get('finalUrl', '')
        if vt_final and vt_final != url and vt_final != final_url:
            parsed_vt = urlparse(vt_final)
            if parsed_vt.netloc and parsed_vt.netloc != domain:
                vt_redir_id = self._generate_node_id()
                nodes.append({
                    'id': vt_redir_id,
                    'type': 'redirect',
                    'label': f'→ {parsed_vt.netloc[:25]}',
                    'description': 'observed redirect',
                    'data': {'url': vt_final, 'domain': parsed_vt.netloc},
                    'step': step,
                    'severity': 'warning',
                })
                edges.append({'source': prev_node, 'target': vt_redir_id, 'label': 'redirect', 'type': 'redirect'})
                prev_node = vt_redir_id
                step += 1

        # ===== STEP: Final destination page =====
        dest_url = final_url or vt_final or url
        parsed_dest = urlparse(dest_url)
        dest_domain = parsed_dest.netloc or domain
        if dest_domain != domain or final_url:
            page_id = self._generate_node_id()
            page_title = vt.get('title', '')
            nodes.append({
                'id': page_id,
                'type': 'page',
                'label': dest_domain[:25],
                'description': page_title[:40] if page_title else f'{parsed_dest.path[:30] or "/"}',
                'data': {'url': dest_url, 'domain': dest_domain, 'title': page_title},
                'step': step,
                'severity': 'info',
            })
            edges.append({'source': prev_node, 'target': page_id, 'label': '200 OK', 'type': 'response'})
            prev_node = page_id
            step += 1

        # ===== STEP: Payloads downloaded (real files served by this URL) =====
        for i, payload in enumerate(urlhaus_payloads[:4]):
            pl_id = f'payload_{i}'
            fname = payload.get('filename', '') or payload.get('sha256', '')[:16] or f'file_{i}'
            sig = payload.get('signature', '')
            ftype = payload.get('fileType', '')
            nodes.append({
                'id': pl_id,
                'type': 'file',
                'label': fname[:25],
                'description': sig if sig else ftype or 'downloaded file',
                'data': {
                    'filename': fname, 'fileType': ftype,
                    'sha256': payload.get('sha256', ''), 'signature': sig,
                },
                'step': step,
                'severity': 'critical' if sig else 'high',
            })
            edges.append({'source': prev_node, 'target': pl_id, 'label': 'downloads', 'type': 'network'})
            # If the payload has a signature (malware family), it may phone home
            if sig:
                c2_id = self._generate_node_id()
                nodes.append({
                    'id': c2_id,
                    'type': 'c2',
                    'label': f'{sig} C2',
                    'description': f'{sig} phones home',
                    'data': {'malwareFamily': sig, 'filename': fname},
                    'step': step + 1,
                    'severity': 'critical',
                })
                edges.append({'source': pl_id, 'target': c2_id, 'label': 'calls back', 'type': 'c2'})
            step += 1

        # ===== BUILD EXPANDABLE + DETAILS =====
        expandable_nodes = [n['id'] for n in nodes]
        node_details = {n['id']: n['data'] for n in nodes}

        return {
            'nodes': nodes,
            'edges': edges,
            'expandableNodes': expandable_nodes,
            'nodeDetails': node_details,
            'summary': {
                'totalSteps': len(nodes),
                'redirects': len(redirect_chain) + (1 if url_unwrap.get('wasWrapped') else 0),
            },
            'timeline': [
                {'step': n['step'], 'label': n['label'], 'type': n['type']}
                for n in sorted(nodes, key=lambda x: x.get('step', 0))
            ],
        }

    def analyze_sandbox_flow(self, analysis: Dict) -> Dict:
        """
        Pure behavioral execution chain: what actually happens step-by-step
        when the file runs.  No scores — only real observed actions.

        File executed → PE parsed → DLLs loaded → memory allocated →
        process injected → DNS queries → connects IP:port →
        HTTP requests → files dropped → registry persistence → C2 callback
        """
        self.node_id_counter = 0
        nodes = []
        edges = []
        step = 1

        filename = analysis.get('filename', analysis.get('file_name', 'unknown'))
        file_analysis = analysis.get('fileAnalysis', analysis.get('file_analysis', {}))
        pe_analysis = analysis.get('peAnalysis', analysis.get('pe_analysis', {}))
        execution = analysis.get('execution', {})
        iocs = analysis.get('iocs', analysis.get('extractedIocs', {}))
        threat_map = analysis.get('threatMap', {})

        # Gather all behavioral data
        dlls_from_exec = execution.get('dllLoads', analysis.get('dllLoads', []))
        api_calls = execution.get('apiCalls', [])
        network_activity = execution.get('networkActivity', {})
        fs_changes = execution.get('filesystemChanges', {})
        reg_changes = execution.get('registryChanges', {})
        mitre_techniques = execution.get('mitreTechniques', [])
        dns_queries = network_activity.get('dnsQueries', [])
        connections = network_activity.get('connections', [])
        http_requests = network_activity.get('httpRequests', [])
        files_created = fs_changes.get('filesCreated', [])
        reg_modified = reg_changes.get('keysModified', [])

        # Also pull IPs/domains from IOCs if execution didn't capture them
        embedded_ips = []
        if pe_analysis:
            embedded_ips = pe_analysis.get('suspiciousStrings', {}).get('embeddedIPs', [])
        ioc_ips = iocs.get('ips', [])
        ioc_domains = iocs.get('domains', [])
        all_ips = list(set(embedded_ips + ioc_ips + [c['ip'] for c in connections if 'ip' in c]))
        all_domains = list(set(ioc_domains + dns_queries))

        prev_node = None

        # ===== STEP 1: File executed =====
        file_size = file_analysis.get('fileSize', file_analysis.get('size', 0))
        file_type = file_analysis.get('fileType', '')
        pe_type = ''
        if pe_analysis:
            bp = pe_analysis.get('basicProperties', {})
            pe_type = bp.get('fileType', '')
        file_hash = file_analysis.get('hashes', {}).get('sha256', '')[:16] or ''

        file_id = self._generate_node_id()
        nodes.append({
            'id': file_id,
            'type': 'file',
            'label': filename[:28],
            'description': pe_type or file_type or self._format_size(file_size),
            'data': {
                'filename': filename, 'fileType': pe_type or file_type,
                'size': file_size, 'hash': file_hash,
            },
            'step': step,
            'severity': 'high',
        })
        prev_node = file_id
        step += 1

        # ===== STEP 2: PE header parsed (if PE) =====
        if pe_analysis and pe_analysis.get('isPE'):
            header = pe_analysis.get('header', {})
            sections = pe_analysis.get('sections', [])
            packed = pe_analysis.get('signatures', {}).get('packed', {})

            pe_id = self._generate_node_id()
            arch = header.get('targetMachine', '?')
            subsys = header.get('subsystem', '')
            n_sections = header.get('numberOfSections', len(sections))
            desc = f'{arch} | {n_sections} sections'
            if packed.get('detected'):
                desc += f' | PACKED ({packed.get("name", "?")})'

            nodes.append({
                'id': pe_id,
                'type': 'analysis',
                'label': f'PE: {arch}',
                'description': desc,
                'data': {
                    'arch': arch, 'subsystem': subsys,
                    'sections': n_sections, 'packed': packed.get('detected', False),
                    'packerName': packed.get('name', ''),
                    'entryPoint': header.get('entryPoint', ''),
                    'compilationTimestamp': header.get('compilationTimestamp', ''),
                },
                'step': step,
                'severity': 'critical' if packed.get('detected') else 'info',
            })
            edges.append({'source': prev_node, 'target': pe_id, 'label': 'parsed', 'type': 'action'})
            prev_node = pe_id
            step += 1

            # High-entropy sections (packed/encrypted)
            for sec in sections:
                if sec.get('suspicious') or (sec.get('entropy', 0) > 7.0):
                    sec_id = self._generate_node_id()
                    nodes.append({
                        'id': sec_id,
                        'type': 'shellcode',
                        'label': f'{sec.get("name", "?")} entropy={sec.get("entropy", 0):.1f}',
                        'description': sec.get('suspicious', 'high entropy — packed/encrypted'),
                        'data': {
                            'section': sec.get('name'), 'entropy': sec.get('entropy'),
                            'virtualSize': sec.get('virtualSize'), 'rawSize': sec.get('rawSize'),
                        },
                        'step': step,
                        'severity': 'critical',
                    })
                    edges.append({'source': prev_node, 'target': sec_id, 'label': 'contains', 'type': 'action'})
                    step += 1
                    break  # only show most suspicious section

        # ===== STEP 3: DLLs loaded (network/suspicious ones) =====
        wine_system = {'wineboot', 'winemenu', 'services', 'winedevice', 'plugplay',
                       'svchost', 'explorer', 'ntoskrnl', 'conhost', 'rundll32'}
        system_dlls_set = {'kernel32', 'kernelbase', 'ntdll', 'msvcrt', 'ucrtbase',
                           'advapi32', 'sechost', 'rpcrt4', 'user32', 'gdi32'}
        network_dll_names = {'ws2_32', 'mswsock', 'wshtcpip', 'wininet', 'winhttp', 'dnsapi', 'iphlpapi'}

        interesting_loaded = []
        for dll_path in dlls_from_exec:
            dll_name = dll_path.split('\\')[-1].split('/')[-1].lower()
            base = dll_name.replace('.dll', '').replace('.exe', '')
            if base in wine_system or base in system_dlls_set:
                continue
            if dll_name not in [d[0] for d in interesting_loaded]:
                is_net = base in network_dll_names
                interesting_loaded.append((dll_name, dll_path, is_net))

        # Sort: network DLLs first
        interesting_loaded.sort(key=lambda x: (not x[2], x[0]))

        dll_prev = prev_node
        for dll_name, dll_path, is_net in interesting_loaded[:5]:
            dll_id = self._generate_node_id()
            susp_reason = self.SUSPICIOUS_DLLS.get(dll_name, '')
            nodes.append({
                'id': dll_id,
                'type': 'dll',
                'label': dll_name,
                'description': susp_reason or ('Network Library' if is_net else 'loaded'),
                'data': {'dll': dll_name, 'path': dll_path, 'isNetwork': is_net},
                'step': step,
                'severity': 'high' if is_net else 'info',
            })
            edges.append({'source': dll_prev, 'target': dll_id, 'label': 'loads', 'type': 'library'})
            dll_prev = dll_id
            step += 1

        if interesting_loaded:
            prev_node = dll_prev

        # ===== STEP 4: Suspicious API calls (from runtime trace) =====
        # Use runtime apiCalls if available, otherwise fall back to static imports
        suspicious_api_names = {
            'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory', 'CreateRemoteThread',
            'NtUnmapViewOfSection', 'LoadLibrary', 'GetProcAddress',
            'WSAStartup', 'connect', 'send', 'recv', 'socket',
            'CreateProcess', 'ShellExecute', 'RegSetValue', 'CreateService',
            'InternetConnect', 'HttpOpenRequest',
        }

        api_entries = api_calls if api_calls else []
        # If no runtime API calls, build from static imports
        if not api_entries and pe_analysis:
            for imp in pe_analysis.get('imports', []):
                dll = imp.get('dll', '')
                for func in imp.get('functions', []):
                    fname = func.get('name', func) if isinstance(func, dict) else func
                    if isinstance(fname, str) and any(s in fname for s in suspicious_api_names):
                        mitre = self.MITRE_TECHNIQUES.get(fname, {})
                        api_entries.append({
                            'module': dll, 'api': fname,
                            'technique': mitre.get('id', ''),
                            'techniqueName': mitre.get('name', ''),
                            'tactic': mitre.get('tactic', ''),
                        })

        api_prev = prev_node
        apis_added = 0
        seen_apis = set()
        for ac in api_entries:
            if apis_added >= 5:
                break
            api_name = ac.get('api', '')
            if api_name in seen_apis:
                continue
            if not any(s in api_name for s in suspicious_api_names):
                continue
            seen_apis.add(api_name)

            api_id = self._generate_node_id()
            technique = ac.get('technique', '')
            tactic = ac.get('tactic', '')
            tech_name = ac.get('techniqueName', '')
            # Look up MITRE if not provided
            if not technique:
                for key, mitre in self.MITRE_TECHNIQUES.items():
                    if key in api_name:
                        technique = mitre['id']
                        tech_name = mitre['name']
                        tactic = mitre['tactic']
                        break

            desc_parts = []
            if tech_name:
                desc_parts.append(tech_name)
            if tactic:
                desc_parts.append(tactic)
            desc = ' | '.join(desc_parts) if desc_parts else ac.get('module', '')

            nodes.append({
                'id': api_id,
                'type': 'api',
                'label': api_name,
                'description': desc,
                'data': {
                    'api': api_name, 'dll': ac.get('module', ''),
                    'mitre': {'id': technique, 'name': tech_name, 'tactic': tactic} if technique else None,
                },
                'step': step,
                'severity': 'critical' if tactic in ('Defense Evasion', 'Privilege Escalation') else 'high' if tactic == 'C2' else 'warning',
            })
            edges.append({'source': api_prev, 'target': api_id, 'label': 'calls', 'type': 'api'})
            api_prev = api_id
            apis_added += 1
            step += 1

        if apis_added:
            prev_node = api_prev

        # ===== STEP 5: DNS queries =====
        dns_prev = prev_node
        for i, domain in enumerate(all_domains[:3]):
            dns_id = self._generate_node_id()
            nodes.append({
                'id': dns_id,
                'type': 'dns',
                'label': domain[:28],
                'description': 'DNS query',
                'data': {'domain': domain},
                'step': step,
                'severity': 'high',
            })
            edges.append({'source': dns_prev, 'target': dns_id, 'label': 'resolves', 'type': 'dns'})
            dns_prev = dns_id
            step += 1

        if all_domains:
            prev_node = dns_prev

        # ===== STEP 6: Network connections (IP:port) =====
        conn_prev = prev_node
        seen_conns = set()
        conn_count = 0
        for ip in all_ips[:5]:
            if ':' in ip:
                ip_addr, port = ip.rsplit(':', 1)
            else:
                ip_addr = ip
                port = '443'
            conn_key = f'{ip_addr}:{port}'
            if conn_key in seen_conns:
                continue
            seen_conns.add(conn_key)
            if conn_count >= 4:
                break

            conn_id = self._generate_node_id()
            nodes.append({
                'id': conn_id,
                'type': 'ip',
                'label': f'{ip_addr}:{port}',
                'description': 'TCP connect',
                'data': {'ip': ip_addr, 'port': port},
                'step': step,
                'severity': 'critical',
            })
            edges.append({'source': conn_prev, 'target': conn_id, 'label': f':{port}', 'type': 'network'})
            conn_prev = conn_id
            conn_count += 1
            step += 1

        # Also add connections from execution.networkActivity
        for conn in connections[:3]:
            ip_addr = conn.get('ip', '')
            port = str(conn.get('port', ''))
            if not ip_addr:
                continue
            conn_key = f'{ip_addr}:{port}'
            if conn_key in seen_conns:
                continue
            seen_conns.add(conn_key)
            if conn_count >= 5:
                break

            conn_id = self._generate_node_id()
            nodes.append({
                'id': conn_id,
                'type': 'ip',
                'label': f'{ip_addr}:{port}',
                'description': 'TCP connect',
                'data': {'ip': ip_addr, 'port': port},
                'step': step,
                'severity': 'critical',
            })
            edges.append({'source': conn_prev, 'target': conn_id, 'label': f':{port}', 'type': 'network'})
            conn_prev = conn_id
            conn_count += 1
            step += 1

        if conn_count > 0:
            prev_node = conn_prev

        # ===== STEP 7: HTTP requests =====
        for i, req in enumerate(http_requests[:3]):
            http_id = self._generate_node_id()
            method = req.get('method', 'GET')
            req_url = req.get('url', '')
            parsed = urlparse(req_url)
            nodes.append({
                'id': http_id,
                'type': 'http',
                'label': f'{method} {parsed.netloc[:20]}',
                'description': f'{parsed.path[:35]}' or req_url[:35],
                'data': {
                    'method': method, 'url': req_url,
                    'domain': parsed.netloc, 'userAgent': req.get('userAgent', ''),
                },
                'step': step,
                'severity': 'high',
            })
            edges.append({'source': prev_node, 'target': http_id, 'label': method, 'type': 'request'})
            prev_node = http_id
            step += 1

        # ===== STEP 8: Files dropped/created =====
        for i, fpath in enumerate(files_created[:3]):
            drop_id = self._generate_node_id()
            fname = fpath.split('\\')[-1].split('/')[-1]
            nodes.append({
                'id': drop_id,
                'type': 'file',
                'label': fname[:28],
                'description': 'file dropped',
                'data': {'filename': fname, 'path': fpath},
                'step': step,
                'severity': 'high',
            })
            edges.append({'source': prev_node, 'target': drop_id, 'label': 'drops', 'type': 'action'})
            prev_node = drop_id
            step += 1

        # ===== STEP 9: Registry persistence =====
        for i, reg_key in enumerate(reg_modified[:2]):
            reg_id = self._generate_node_id()
            # Identify persistence-related keys
            is_persist = any(p in reg_key for p in ['Run', 'RunOnce', 'Services', 'Shell'])
            short_key = reg_key.split('\\')[-1][:28] if '\\' in reg_key else reg_key[:28]
            nodes.append({
                'id': reg_id,
                'type': 'registry',
                'label': short_key,
                'description': 'persistence' if is_persist else 'registry write',
                'data': {'key': reg_key, 'isPersistence': is_persist},
                'step': step,
                'severity': 'critical' if is_persist else 'warning',
            })
            edges.append({
                'source': prev_node, 'target': reg_id,
                'label': 'persists' if is_persist else 'modifies', 'type': 'action',
            })
            prev_node = reg_id
            step += 1

        # ===== STEP 10: C2 callback (if we saw both network + suspicious APIs) =====
        has_network = conn_count > 0 or len(http_requests) > 0
        has_injection = any(
            any(s in ac.get('api', '') for s in ['VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread'])
            for ac in api_entries
        )
        if has_network and has_injection:
            c2_id = self._generate_node_id()
            nodes.append({
                'id': c2_id,
                'type': 'c2',
                'label': 'C2 Communication',
                'description': 'injection + network = likely C2',
                'data': {
                    'connections': conn_count,
                    'injectionApis': [ac['api'] for ac in api_entries if any(s in ac.get('api', '') for s in ['VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread'])],
                },
                'step': step,
                'severity': 'critical',
            })
            edges.append({'source': prev_node, 'target': c2_id, 'label': 'C2', 'type': 'c2'})
            step += 1

        # ===== BUILD EXPANDABLE + DETAILS =====
        expandable_nodes = [n['id'] for n in nodes]
        node_details = {}
        for n in nodes:
            detail = dict(n.get('data', {}))
            if n['type'] == 'api' and detail.get('mitre'):
                pass  # already has mitre
            elif n['type'] == 'api':
                api_name = detail.get('api', '')
                for key, mitre in self.MITRE_TECHNIQUES.items():
                    if key in api_name:
                        detail['mitre'] = mitre
                        break
            if n['type'] == 'dll':
                dll_name = detail.get('dll', '').lower()
                for susp_dll, desc in self.SUSPICIOUS_DLLS.items():
                    if susp_dll in dll_name:
                        detail['suspiciousReason'] = desc
                        break
            node_details[n['id']] = detail

        return {
            'nodes': nodes,
            'edges': edges,
            'expandableNodes': expandable_nodes,
            'nodeDetails': node_details,
            'summary': {
                'totalSteps': len(nodes),
                'networkConnections': conn_count,
            },
            'timeline': [
                {'step': n['step'], 'label': n['label'], 'type': n['type']}
                for n in sorted(nodes, key=lambda x: x.get('step', 0))
            ],
        }
    def generate_correlation_graph(self, ioc_type: str, ioc_value: str, current_result: Optional[Dict] = None) -> Dict:
        """
        Query ioc_cache.db for shared entities (same malware_family, tags, overlapping IPs/domains)
        and build correlation edges between them.
        """
        db_path = os.path.join(os.path.dirname(__file__), 'ioc_cache.db')
        if not os.path.exists(db_path):
            return {'nodes': [], 'edges': [], 'correlationEdges': [], 'expandableNodes': [], 'nodeDetails': {}}

        nodes = []
        edges = []
        correlation_edges = []
        expandable_nodes = []
        node_details = {}
        seen_ids = set()

        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Seed node from current result
            seed_id = f'seed_{ioc_type}'
            nodes.append({
                'id': seed_id,
                'type': ioc_type if ioc_type in ('ip', 'domain') else 'ioc',
                'label': ioc_value[:30],
                'description': f'Seed {ioc_type.upper()}',
                'data': {ioc_type: ioc_value},
                'severity': 'high',
                'isCenter': True
            })
            expandable_nodes.append(seed_id)
            node_details[seed_id] = {ioc_type: ioc_value}
            seen_ids.add(seed_id)

            # Query related IPs
            if ioc_type == 'ip':
                # Find IPs with same malware_family or tags
                cursor.execute(
                    "SELECT * FROM ioc_ips WHERE ip = ?", (ioc_value,)
                )
                seed_row = cursor.fetchone()
                if seed_row:
                    malware_family = seed_row['malware_families'] or ''
                    tags = seed_row['tags'] or ''
                    node_details[seed_id].update({
                        'country': seed_row['country'],
                        'isp': seed_row['isp'],
                        'asn': seed_row['asn'],
                        'risk_score': seed_row['risk_score'],
                    })

                    # Find related IPs by malware family
                    if malware_family:
                        for family in malware_family.split(','):
                            family = family.strip()
                            if not family:
                                continue
                            cursor.execute(
                                "SELECT * FROM ioc_ips WHERE malware_families LIKE ? AND ip != ? LIMIT 5",
                                (f'%{family}%', ioc_value)
                            )
                            for row in cursor.fetchall():
                                nid = f'ip_{row["ip"]}'
                                if nid not in seen_ids:
                                    seen_ids.add(nid)
                                    nodes.append({
                                        'id': nid, 'type': 'ip', 'label': row['ip'],
                                        'description': f'{row["country"] or "Unknown"}',
                                        'data': {'ip': row['ip'], 'country': row['country'], 'isp': row['isp']},
                                        'severity': 'critical' if row['risk_score'] >= 70 else 'high' if row['risk_score'] >= 40 else 'medium'
                                    })
                                    expandable_nodes.append(nid)
                                    node_details[nid] = {'ip': row['ip'], 'country': row['country'], 'isp': row['isp'], 'asn': row['asn'], 'risk_score': row['risk_score']}
                                correlation_edges.append({
                                    'source': seed_id, 'target': nid,
                                    'label': f'family: {family}', 'type': 'correlation'
                                })

                    # Find related URLs pointing to this IP
                    cursor.execute(
                        "SELECT * FROM ioc_urls WHERE domain LIKE ? LIMIT 3",
                        (f'%{ioc_value}%',)
                    )
                    for row in cursor.fetchall():
                        nid = f'url_{row["id"]}'
                        if nid not in seen_ids:
                            seen_ids.add(nid)
                            nodes.append({
                                'id': nid, 'type': 'http', 'label': (row['url'] or '')[:30],
                                'description': row['domain'] or '',
                                'data': {'url': row['url'], 'domain': row['domain']},
                                'severity': 'high' if row['is_malicious'] else 'medium'
                            })
                            expandable_nodes.append(nid)
                            node_details[nid] = {'url': row['url'], 'domain': row['domain'], 'threat_type': row['threat_type']}
                        correlation_edges.append({
                            'source': seed_id, 'target': nid,
                            'label': 'hosts', 'type': 'correlation'
                        })

            elif ioc_type == 'url':
                parsed = urlparse(ioc_value)
                domain = parsed.netloc

                cursor.execute("SELECT * FROM ioc_urls WHERE url = ? OR domain = ? LIMIT 1", (ioc_value, domain))
                seed_row = cursor.fetchone()
                if seed_row:
                    malware_family = seed_row['malware_family'] or ''
                    node_details[seed_id].update({
                        'domain': seed_row['domain'],
                        'threat_type': seed_row['threat_type'],
                        'risk_score': seed_row['risk_score'],
                    })

                    # Find related URLs by malware family
                    if malware_family:
                        cursor.execute(
                            "SELECT * FROM ioc_urls WHERE malware_family LIKE ? AND url != ? LIMIT 5",
                            (f'%{malware_family}%', ioc_value)
                        )
                        for row in cursor.fetchall():
                            nid = f'url_{row["id"]}'
                            if nid not in seen_ids:
                                seen_ids.add(nid)
                                nodes.append({
                                    'id': nid, 'type': 'http', 'label': (row['url'] or '')[:30],
                                    'description': row['domain'] or '',
                                    'data': {'url': row['url'], 'domain': row['domain']},
                                    'severity': 'high' if row['is_malicious'] else 'medium'
                                })
                                expandable_nodes.append(nid)
                                node_details[nid] = {'url': row['url'], 'domain': row['domain']}
                            correlation_edges.append({
                                'source': seed_id, 'target': nid,
                                'label': f'family: {malware_family}', 'type': 'correlation'
                            })

                    # Find related IPs for this domain
                    cursor.execute(
                        "SELECT * FROM ioc_ips WHERE ip IN (SELECT ip FROM ioc_ips) LIMIT 3"
                    )

            elif ioc_type == 'hash':
                cursor.execute("SELECT * FROM ioc_hashes WHERE hash_value = ? LIMIT 1", (ioc_value,))
                seed_row = cursor.fetchone()
                if seed_row:
                    malware_family = seed_row['malware_family'] or ''
                    node_details[seed_id].update({
                        'file_name': seed_row['file_name'],
                        'file_type': seed_row['file_type'],
                        'risk_score': seed_row['risk_score'],
                    })

                    if malware_family:
                        # Find related hashes
                        cursor.execute(
                            "SELECT * FROM ioc_hashes WHERE malware_family LIKE ? AND hash_value != ? LIMIT 5",
                            (f'%{malware_family}%', ioc_value)
                        )
                        for row in cursor.fetchall():
                            nid = f'hash_{row["id"]}'
                            if nid not in seen_ids:
                                seen_ids.add(nid)
                                nodes.append({
                                    'id': nid, 'type': 'file', 'label': (row['file_name'] or row['hash_value'][:16]),
                                    'description': row['file_type'] or 'Unknown',
                                    'data': {'hash': row['hash_value'], 'file_name': row['file_name']},
                                    'severity': 'critical' if row['risk_score'] >= 70 else 'high'
                                })
                                expandable_nodes.append(nid)
                                node_details[nid] = {'hash': row['hash_value'], 'file_name': row['file_name'], 'file_type': row['file_type']}
                            correlation_edges.append({
                                'source': seed_id, 'target': nid,
                                'label': f'family: {malware_family}', 'type': 'correlation'
                            })

                        # Find related IPs from same family
                        cursor.execute(
                            "SELECT * FROM ioc_ips WHERE malware_families LIKE ? LIMIT 3",
                            (f'%{malware_family}%',)
                        )
                        for row in cursor.fetchall():
                            nid = f'ip_{row["ip"]}'
                            if nid not in seen_ids:
                                seen_ids.add(nid)
                                nodes.append({
                                    'id': nid, 'type': 'ip', 'label': row['ip'],
                                    'description': row['country'] or 'Unknown',
                                    'data': {'ip': row['ip'], 'country': row['country']},
                                    'severity': 'critical' if row['risk_score'] >= 70 else 'high'
                                })
                                expandable_nodes.append(nid)
                                node_details[nid] = {'ip': row['ip'], 'country': row['country'], 'isp': row['isp']}
                            correlation_edges.append({
                                'source': seed_id, 'target': nid,
                                'label': f'family: {malware_family}', 'type': 'correlation'
                            })

            conn.close()
        except Exception as e:
            print(f"[Warning] Correlation graph generation failed: {e}")

        return {
            'nodes': nodes,
            'edges': edges,
            'correlationEdges': correlation_edges,
            'expandableNodes': expandable_nodes,
            'nodeDetails': node_details,
            'layoutType': 'radial',
            'centerNode': seed_id if nodes else None,
            'summary': {
                'totalNodes': len(nodes),
                'correlations': len(correlation_edges),
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


def generate_correlation_graph(ioc_type: str, ioc_value: str, current_result: Optional[Dict] = None) -> Dict:
    """Convenience function for correlation graph generation"""
    return get_analyzer().generate_correlation_graph(ioc_type, ioc_value, current_result)
