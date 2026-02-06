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
        edges.append({'source': entry_node, 'target': dns_node, 'label': 'DNS Query', 'type': 'request'})

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
        edges.append({'source': prev_node, 'target': http_node, 'label': 'Connect', 'type': 'connection'})
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
                edges.append({'source': prev_node, 'target': redirect_node, 'label': f'{status_code}', 'type': 'redirect'})
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
            edges.append({'source': prev_node, 'target': final_node, 'label': '200 OK', 'type': 'response'})
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
            edges.append({'source': prev_node, 'target': render_node, 'label': 'Render', 'type': 'action'})
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
        edges.append({'source': prev_node, 'target': risk_node, 'label': 'Analysis', 'type': 'assessment'})

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
        Analyze sandbox execution and generate detailed attack flow
        Shows each step of malware execution: File → Load → API Resolution → Memory → Network → C2
        """
        self.node_id_counter = 0
        nodes = []
        edges = []

        filename = analysis.get('filename', analysis.get('file_name', 'unknown'))
        file_analysis = analysis.get('fileAnalysis', analysis.get('file_analysis', {}))
        pe_analysis = analysis.get('peAnalysis', analysis.get('pe_analysis', {}))
        process_tree = analysis.get('processTree', analysis.get('process_tree', []))
        network = analysis.get('networkConnections', analysis.get('network_connections', []))
        behaviors = analysis.get('behaviorSummary', analysis.get('behavior_summary', {}))
        iocs = analysis.get('extractedIocs', analysis.get('extracted_iocs', {}))
        risk_score = analysis.get('riskScore', analysis.get('risk_score', 0))
        execution = analysis.get('execution', {})

        # Get behavioral data from execution object (where Wine debug parsing stores it)
        # or from top-level if it's been propagated there
        filesystem = analysis.get('filesystemChanges', analysis.get('filesystem_changes', {}))
        if not filesystem.get('filesOpened') and execution:
            filesystem = execution.get('filesystemChanges', execution.get('filesystem_changes', {}))

        registry = analysis.get('registryChanges', analysis.get('registry_changes', {}))
        if not registry.get('keysOpened') and execution:
            registry = execution.get('registryChanges', execution.get('registry_changes', {}))

        # Get DLLs loaded from execution object
        dlls_from_exec = []
        if execution:
            dlls_from_exec = execution.get('dllLoads', [])

        # Get API calls and MITRE techniques from execution (enhanced Wine debug parsing)
        api_calls = analysis.get('apiCalls', [])
        if not api_calls and execution:
            api_calls = execution.get('apiCalls', [])

        mitre_techniques = analysis.get('mitreTechniques', [])
        if not mitre_techniques and execution:
            mitre_techniques = execution.get('mitreTechniques', [])

        # Get network activity (DNS queries, connections) from execution
        network_activity = analysis.get('networkActivity', {})
        if not network_activity.get('dnsQueries') and execution:
            network_activity = execution.get('networkActivity', {})

        # Extract detailed behavior data
        files_opened = filesystem.get('filesOpened', filesystem.get('files_opened', []))
        files_created = filesystem.get('filesCreated', filesystem.get('files_created', []))
        registry_opened = registry.get('keysOpened', registry.get('keys_opened', []))
        registry_modified = registry.get('keysModified', registry.get('keys_modified', []))

        step = 1

        # ===== STEP 1: File Received =====
        file_node = self._generate_node_id()
        file_type = file_analysis.get('type', 'Unknown')
        file_size = file_analysis.get('size', 0)
        nodes.append({
            'id': file_node,
            'type': 'file',
            'label': f'File Received',
            'description': f'{filename} ({self._format_size(file_size)})',
            'data': {'filename': filename, 'type': file_type, 'size': file_size},
            'step': step,
            'severity': 'info'
        })
        prev_node = file_node
        step += 1

        # ===== STEP 2: PE Header Analysis (if PE file) =====
        if pe_analysis and pe_analysis.get('isPE'):
            pe_node = self._generate_node_id()
            sections = pe_analysis.get('sections', [])
            # Handle different section formats (list of dicts or list of lists)
            suspicious_sections = []
            for s in sections:
                if isinstance(s, dict):
                    chars = s.get('characteristics', {})
                    if isinstance(chars, dict) and chars.get('execute') and chars.get('write'):
                        suspicious_sections.append(s)

            nodes.append({
                'id': pe_node,
                'type': 'analysis',
                'label': 'PE Header Analysis',
                'description': f'{len(sections)} sections, {len(suspicious_sections)} RWX',
                'data': {'sections': len(sections), 'rwxSections': len(suspicious_sections)},
                'step': step,
                'severity': 'warning' if suspicious_sections else 'info'
            })
            edges.append({'source': prev_node, 'target': pe_node, 'label': 'Parse PE', 'type': 'analysis'})
            prev_node = pe_node
            step += 1

            # ===== STEP 3: Import Analysis - Check for IAT bypass indicators =====
            imports = pe_analysis.get('imports', [])
            suspicious_imports = []
            network_imports = []
            memory_imports = []

            for imp in imports:
                dll_name = imp.get('dll', '').lower()
                funcs = imp.get('functions', [])

                for func in funcs:
                    func_lower = func.lower()
                    # Memory manipulation
                    if any(api in func for api in ['VirtualProtect', 'VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread']):
                        memory_imports.append({'api': func, 'dll': dll_name, 'technique': self.MITRE_TECHNIQUES.get(func.split('A')[0].split('W')[0], {})})
                    # API resolution (IAT bypass indicators)
                    if any(api in func for api in ['GetProcAddress', 'LoadLibrary', 'GetModuleHandle']):
                        suspicious_imports.append({'api': func, 'dll': dll_name, 'purpose': 'Dynamic API Resolution'})
                    # Network
                    if any(api in func for api in ['WSAStartup', 'connect', 'send', 'recv', 'InternetConnect', 'HttpOpenRequest']):
                        network_imports.append({'api': func, 'dll': dll_name})

            # If GetProcAddress/LoadLibrary found - IAT bypass node
            if suspicious_imports:
                iat_node = self._generate_node_id()
                nodes.append({
                    'id': iat_node,
                    'type': 'evasion',
                    'label': 'IAT Bypass Detected',
                    'description': 'Dynamic API resolution (PEB walking)',
                    'data': {'apis': [i['api'] for i in suspicious_imports[:5]], 'technique': 'T1106'},
                    'step': step,
                    'severity': 'high'
                })
                edges.append({'source': prev_node, 'target': iat_node, 'label': 'API Resolve', 'type': 'evasion'})
                prev_node = iat_node
                step += 1

        # ===== STEP 4: Execution Start =====
        exec_node = self._generate_node_id()
        nodes.append({
            'id': exec_node,
            'type': 'execution',
            'label': 'Execution Started',
            'description': f'{filename}',
            'data': {'backend': analysis.get('backend', 'sandbox')},
            'step': step,
            'severity': 'info'
        })
        edges.append({'source': prev_node, 'target': exec_node, 'label': 'Execute', 'type': 'action'})
        prev_node = exec_node
        step += 1

        # ===== STEP 5: DLL Loading (from files opened or execution dllLoads) =====
        dlls_loaded = []

        # Check files opened for DLLs
        for f in files_opened:
            f_lower = f.lower()
            for dll, purpose in self.SUSPICIOUS_DLLS.items():
                if dll.lower() in f_lower:
                    dlls_loaded.append({'dll': dll, 'purpose': purpose, 'path': f})
                    break

        # Also check dllLoads from execution (Wine debug output)
        for dll_path in dlls_from_exec:
            dll_lower = dll_path.lower()
            for dll, purpose in self.SUSPICIOUS_DLLS.items():
                if dll.lower() in dll_lower:
                    if not any(d['dll'].lower() == dll.lower() for d in dlls_loaded):
                        dlls_loaded.append({'dll': dll, 'purpose': purpose, 'path': dll_path})
                    break

        if dlls_loaded:
            dll_node = self._generate_node_id()
            dll_names = list(set([d['dll'] for d in dlls_loaded]))
            nodes.append({
                'id': dll_node,
                'type': 'dll',
                'label': 'DLL Loading',
                'description': ', '.join(dll_names[:4]),
                'data': {'dlls': dlls_loaded[:6]},
                'step': step,
                'severity': 'warning' if any('ws2_32' in d['dll'].lower() or 'wininet' in d['dll'].lower() for d in dlls_loaded) else 'info'
            })
            edges.append({'source': prev_node, 'target': dll_node, 'label': 'LoadLibrary', 'type': 'load'})
            prev_node = dll_node
            step += 1

            # Network DLL specifically (ws2_32.dll)
            network_dlls = [d for d in dlls_loaded if 'ws2_32' in d['dll'].lower() or 'mswsock' in d['dll'].lower() or 'wshtcpip' in d['dll'].lower()]
            if network_dlls:
                net_init_node = self._generate_node_id()
                nodes.append({
                    'id': net_init_node,
                    'type': 'network',
                    'label': 'Network Stack Init',
                    'description': 'WSAStartup / Socket Creation',
                    'data': {'dlls': [d['dll'] for d in network_dlls], 'technique': 'T1071'},
                    'step': step,
                    'severity': 'high'
                })
                edges.append({'source': prev_node, 'target': net_init_node, 'label': 'Initialize', 'type': 'network'})
                prev_node = net_init_node
                step += 1

        # ===== STEP 5b: API Calls with MITRE Techniques =====
        if api_calls:
            # Group API calls by tactic
            tactics = {}
            for api in api_calls:
                tactic = api.get('tactic', 'Unknown')
                if tactic not in tactics:
                    tactics[tactic] = []
                tactics[tactic].append(api)

            # Add nodes for each tactic group
            for tactic, apis in list(tactics.items())[:4]:  # Limit to 4 tactic groups
                api_node = self._generate_node_id()
                api_names = [a['api'] for a in apis[:3]]
                techniques = list(set([a.get('technique', '') for a in apis if a.get('technique')]))

                severity = 'critical' if tactic in ['Defense Evasion', 'Command and Control'] else 'high' if tactic == 'Execution' else 'warning'

                nodes.append({
                    'id': api_node,
                    'type': 'threat',
                    'label': f'{tactic}',
                    'description': ', '.join(api_names),
                    'data': {
                        'apis': [a['api'] for a in apis],
                        'techniques': techniques,
                        'tactic': tactic
                    },
                    'step': step,
                    'severity': severity
                })
                edges.append({'source': prev_node, 'target': api_node, 'label': techniques[0] if techniques else 'API Call', 'type': 'technique'})
                prev_node = api_node
                step += 1

        # ===== STEP 6: Memory Allocation (if detected) =====
        if memory_imports or (pe_analysis and pe_analysis.get('isPE')):
            mem_node = self._generate_node_id()
            nodes.append({
                'id': mem_node,
                'type': 'memory',
                'label': 'Memory Allocation',
                'description': 'PAGE_EXECUTE_READWRITE',
                'data': {'apis': [m['api'] for m in memory_imports] if memory_imports else ['VirtualAlloc'], 'technique': 'T1055'},
                'step': step,
                'severity': 'critical'
            })
            edges.append({'source': prev_node, 'target': mem_node, 'label': 'VirtualAlloc', 'type': 'memory'})
            prev_node = mem_node
            step += 1

            # Shellcode execution
            shellcode_node = self._generate_node_id()
            nodes.append({
                'id': shellcode_node,
                'type': 'shellcode',
                'label': 'Shellcode Execution',
                'description': 'Jump to allocated buffer',
                'data': {'technique': 'T1055'},
                'step': step,
                'severity': 'critical'
            })
            edges.append({'source': prev_node, 'target': shellcode_node, 'label': 'JMP/CALL', 'type': 'execution'})
            prev_node = shellcode_node
            step += 1

        # ===== STEP 7: Process Tree =====
        if process_tree:
            for proc in process_tree[:3]:
                proc_name = proc.get('name', proc.get('command', 'unknown'))
                proc_pid = proc.get('pid', '?')

                proc_node = self._generate_node_id()
                is_suspicious = any(s in proc_name.lower() for s in ['cmd', 'powershell', 'wscript', 'cscript', 'mshta', 'regsvr32'])

                nodes.append({
                    'id': proc_node,
                    'type': 'process',
                    'label': f'Process: {proc_name[:18]}',
                    'description': f'PID: {proc_pid}',
                    'data': {'name': proc_name, 'pid': proc_pid},
                    'step': step,
                    'severity': 'high' if is_suspicious else 'info'
                })
                edges.append({'source': prev_node, 'target': proc_node, 'label': 'CreateProcess', 'type': 'process'})
                prev_node = proc_node
                step += 1

                # Child processes
                for child in proc.get('children', [])[:2]:
                    child_name = child.get('name', 'unknown')
                    child_node = self._generate_node_id()
                    nodes.append({
                        'id': child_node,
                        'type': 'process',
                        'label': f'Child: {child_name[:15]}',
                        'description': f'PID: {child.get("pid", "?")}',
                        'data': {'name': child_name},
                        'step': step,
                        'severity': 'warning'
                    })
                    edges.append({'source': proc_node, 'target': child_node, 'label': 'Spawn', 'type': 'process'})

        # ===== STEP 8: Registry Activity =====
        suspicious_reg = []
        for key in registry_opened + registry_modified:
            for pattern, purpose in self.SUSPICIOUS_REGISTRY.items():
                if pattern.lower() in key.lower():
                    suspicious_reg.append({'key': key, 'purpose': purpose})
                    break

        if suspicious_reg:
            reg_node = self._generate_node_id()
            purposes = list(set([r['purpose'] for r in suspicious_reg]))
            nodes.append({
                'id': reg_node,
                'type': 'registry',
                'label': 'Registry Access',
                'description': ', '.join(purposes[:3]),
                'data': {'keys': [r['key'] for r in suspicious_reg[:5]], 'purposes': purposes},
                'step': step,
                'severity': 'warning' if 'Persistence' in str(purposes) else 'info'
            })
            edges.append({'source': prev_node, 'target': reg_node, 'label': 'RegOpenKey', 'type': 'registry'})
            prev_node = reg_node
            step += 1

        # ===== STEP 9: DNS Queries (from network activity) =====
        dns_queries = network_activity.get('dnsQueries', [])
        if dns_queries:
            dns_node = self._generate_node_id()
            nodes.append({
                'id': dns_node,
                'type': 'dns',
                'label': 'DNS Resolution',
                'description': ', '.join(dns_queries[:3]),
                'data': {'domains': dns_queries, 'technique': 'T1071'},
                'step': step,
                'severity': 'high'
            })
            edges.append({'source': prev_node, 'target': dns_node, 'label': 'gethostbyname', 'type': 'network'})
            prev_node = dns_node
            step += 1

        # ===== STEP 10: Network Connections =====
        # Merge network from original analysis and from network_activity
        all_connections = network or []
        net_connections = network_activity.get('connections', [])
        for conn in net_connections:
            if not any(c.get('ip') == conn.get('ip') and c.get('port') == conn.get('port') for c in all_connections):
                all_connections.append(conn)

        if all_connections:
            for i, conn in enumerate(all_connections[:3]):
                ip = conn.get('remoteIp', conn.get('ip', 'unknown'))
                port = conn.get('remotePort', conn.get('port', '?'))
                protocol = conn.get('protocol', 'TCP')

                conn_node = self._generate_node_id()
                nodes.append({
                    'id': conn_node,
                    'type': 'c2',
                    'label': f'C2 Connection',
                    'description': f'{ip}:{port} ({protocol})',
                    'data': {'ip': ip, 'port': port, 'protocol': protocol, 'technique': 'T1071'},
                    'step': step,
                    'severity': 'critical'
                })
                edges.append({'source': prev_node, 'target': conn_node, 'label': 'connect()', 'type': 'c2'})
                prev_node = conn_node
                step += 1

        # ===== STEP 10: IOCs Extracted =====
        ioc_ips = iocs.get('ips', [])
        ioc_domains = iocs.get('domains', [])
        ioc_urls = iocs.get('urls', [])
        total_iocs = len(ioc_ips) + len(ioc_domains) + len(ioc_urls)

        if total_iocs > 0:
            ioc_node = self._generate_node_id()
            nodes.append({
                'id': ioc_node,
                'type': 'ioc',
                'label': 'IOCs Extracted',
                'description': f'{total_iocs} indicator(s)',
                'data': {'ips': ioc_ips[:5], 'domains': ioc_domains[:5], 'urls': ioc_urls[:3]},
                'step': step,
                'severity': 'warning'
            })
            edges.append({'source': prev_node, 'target': ioc_node, 'label': 'Extract', 'type': 'analysis'})
            prev_node = ioc_node
            step += 1

        # ===== FINAL: Risk Assessment =====
        risk_node = self._generate_node_id()
        risk_severity = 'critical' if risk_score >= 70 else 'high' if risk_score >= 50 else 'medium' if risk_score >= 30 else 'low'
        nodes.append({
            'id': risk_node,
            'type': 'assessment',
            'label': f'Risk: {risk_score}/100',
            'description': analysis.get('riskLevel', risk_severity.upper()),
            'data': {'score': risk_score, 'level': risk_severity},
            'step': step,
            'severity': risk_severity
        })
        edges.append({'source': prev_node, 'target': risk_node, 'label': 'Verdict', 'type': 'assessment'})

        # Build MITRE techniques summary
        mitre_summary = []
        if mitre_techniques:
            for tech in mitre_techniques:
                mitre_summary.append({
                    'id': tech.get('id', ''),
                    'name': tech.get('name', ''),
                    'tactic': tech.get('tactic', '')
                })

        return {
            'nodes': nodes,
            'edges': edges,
            'summary': {
                'totalSteps': len(nodes),
                'processes': len(process_tree),
                'networkConnections': len(all_connections) if 'all_connections' in dir() else len(network),
                'dlls': len(dlls_loaded) if 'dlls_loaded' in dir() else 0,
                'registryKeys': len(suspicious_reg) if 'suspicious_reg' in dir() else 0,
                'dnsQueries': len(dns_queries) if 'dns_queries' in dir() else 0,
                'apiCalls': len(api_calls),
                'mitreTechniques': mitre_summary,
                'riskScore': risk_score,
                'filename': filename
            },
            'timeline': [{'step': n['step'], 'label': n['label'], 'type': n['type']} for n in sorted(nodes, key=lambda x: x['step'])]
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
