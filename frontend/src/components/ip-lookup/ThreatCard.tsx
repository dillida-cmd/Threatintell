import {
  ShieldAlert, Wifi, Server, Eye, Bot, Bug,
  AlertTriangle, CheckCircle, XCircle, Clock, FileWarning, Radio,
  Shield, Activity, Zap, Database, Lock
} from 'lucide-react';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';
import { RiskScore } from '../common/RiskScore';
import type { ThreatInfo, IpLookupResult, IpInvestigation } from '../../types';

interface ThreatCardProps {
  threatInfo: ThreatInfo;
  data: IpLookupResult;
  threatIntel: IpInvestigation | null;
}

export const ThreatCard = ({ threatInfo, data, threatIntel }: ThreatCardProps) => {
  const sources = threatIntel?.sources || {};
  const summary = threatIntel?.summary as { isMalicious?: boolean; findings?: string[] } || {};

  // Extract data from all sources
  const abuseipdb = sources.abuseipdb || {};
  const virustotal = sources.virustotal || {};
  const ipqs = sources.ipqualityscore || {};
  const alienvault = sources.alienvault_otx || {};
  const greynoise = sources.greynoise || {};
  const shodan = sources.shodan || {};
  const threatfox = sources.threatfox || {};

  // Security indicators from all sources
  const indicators = [
    { key: 'proxy', label: 'Proxy', icon: <Wifi className="h-4 w-4" />, active: ipqs.isProxy || threatInfo.is_proxy },
    { key: 'vpn', label: 'VPN', icon: <Lock className="h-4 w-4" />, active: ipqs.isVpn || threatInfo.is_vpn },
    { key: 'tor', label: 'Tor', icon: <Eye className="h-4 w-4" />, active: abuseipdb.isTor || ipqs.isTor || threatInfo.is_tor },
    { key: 'hosting', label: 'Hosting', icon: <Server className="h-4 w-4" />, active: data.security?.isHosting || threatInfo.is_hosting },
    { key: 'bot', label: 'Bot', icon: <Bot className="h-4 w-4" />, active: ipqs.isBot },
    { key: 'crawler', label: 'Crawler', icon: <Bug className="h-4 w-4" />, active: ipqs.isCrawler },
  ];

  // VirusTotal stats
  const vtMalicious = virustotal.malicious || 0;
  const vtSuspicious = virustotal.suspicious || 0;
  const vtHarmless = virustotal.harmless || 0;
  const vtTotal = vtMalicious + vtSuspicious + vtHarmless + (virustotal.undetected || 0);

  // Shodan ports and services
  const shodanPorts = shodan.ports || [];
  const shodanServices = shodan.services || [];
  const shodanVulns = shodan.vulns || [];

  // AbuseIPDB data
  const totalReports = abuseipdb.totalReports || 0;
  const recentReports = abuseipdb.recentReports || [];
  const abuseCategories = abuseipdb.categories || [];

  // AlienVault pulses
  const pulseCount = alienvault.pulseCount || 0;
  const pulses = alienvault.pulses || [];
  const validations = alienvault.validation || [];

  // GreyNoise classification
  const gnClassification = greynoise.classification || '';
  const gnName = greynoise.name || '';
  const isRiot = greynoise.riot || false;
  const isNoise = greynoise.noise || false;

  // ThreatFox data
  const threatfoxFound = threatfox.found || false;
  const threatfoxData = threatfox.data || [];

  // Category name mapping for AbuseIPDB
  const categoryNames: Record<number, string> = {
    1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Orders', 4: 'DDoS Attack',
    5: 'FTP Brute-Force', 6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP',
    9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam', 12: 'Blog Spam',
    13: 'VPN IP', 14: 'Port Scan', 15: 'Hacking', 16: 'SQL Injection',
    17: 'Spoofing', 18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
    21: 'Web App Attack', 22: 'SSH', 23: 'IoT Targeted'
  };

  return (
    <Card title="Threat Intelligence" icon={<ShieldAlert className="h-5 w-5" />}>
      <div className="space-y-6">
        {/* Risk Score and Summary */}
        <div className="flex flex-col md:flex-row items-start gap-6">
          <RiskScore score={threatInfo.risk_score} size="lg" />

          <div className="flex-1 w-full">
            <div className="mb-4 flex flex-wrap items-center gap-2">
              <Badge variant={summary.isMalicious ? 'danger' : threatInfo.risk_score > 30 ? 'warning' : 'safe'}>
                {summary.isMalicious ? 'Malicious' : threatInfo.risk_score > 30 ? 'Suspicious' : 'Clean'}
              </Badge>
              {totalReports > 0 && (
                <Badge variant="warning">{totalReports} Abuse Reports</Badge>
              )}
              {vtMalicious > 0 && (
                <Badge variant="danger">{vtMalicious}/{vtTotal} Detections</Badge>
              )}
              {pulseCount > 0 && (
                <Badge variant="warning">{pulseCount} Threat Pulses</Badge>
              )}
              {isRiot && (
                <Badge variant="safe">Known Safe Service</Badge>
              )}
              {abuseipdb.isWhitelisted && (
                <Badge variant="safe">Whitelisted</Badge>
              )}
            </div>

            {/* Security Indicators Grid */}
            <div className="grid grid-cols-3 md:grid-cols-6 gap-2">
              {indicators.map((indicator) => (
                <div
                  key={indicator.key}
                  className={`flex items-center gap-1.5 p-2 rounded-lg text-xs
                    ${indicator.active ? 'bg-red-500/20 text-red-400' : 'bg-white/5 text-gray-500'}`}
                >
                  {indicator.icon}
                  <span className="font-medium">{indicator.label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* GreyNoise Info */}
        {(gnClassification || gnName) && (
          <div className="p-3 bg-white/5 rounded-lg">
            <div className="flex items-center gap-2 mb-2">
              <Radio className="h-4 w-4 text-primary" />
              <span className="text-sm font-medium text-white">Internet Scanner Classification</span>
            </div>
            <div className="flex flex-wrap gap-2">
              {gnClassification && (
                <Badge variant={gnClassification === 'benign' ? 'safe' : gnClassification === 'malicious' ? 'danger' : 'warning'}>
                  {gnClassification.charAt(0).toUpperCase() + gnClassification.slice(1)}
                </Badge>
              )}
              {gnName && <span className="text-gray-300 text-sm">{gnName}</span>}
              {isNoise && <Badge variant="warning">Active Scanner</Badge>}
            </div>
          </div>
        )}

        {/* VirusTotal Analysis */}
        {vtTotal > 0 && (
          <div className="p-3 bg-white/5 rounded-lg">
            <div className="flex items-center gap-2 mb-3">
              <Shield className="h-4 w-4 text-primary" />
              <span className="text-sm font-medium text-white">Antivirus Analysis ({vtTotal} engines)</span>
            </div>
            <div className="grid grid-cols-4 gap-2 text-center">
              <div className="p-2 bg-red-500/20 rounded">
                <div className="text-lg font-bold text-red-400">{vtMalicious}</div>
                <div className="text-xs text-gray-400">Malicious</div>
              </div>
              <div className="p-2 bg-orange-500/20 rounded">
                <div className="text-lg font-bold text-orange-400">{vtSuspicious}</div>
                <div className="text-xs text-gray-400">Suspicious</div>
              </div>
              <div className="p-2 bg-green-500/20 rounded">
                <div className="text-lg font-bold text-green-400">{vtHarmless}</div>
                <div className="text-xs text-gray-400">Clean</div>
              </div>
              <div className="p-2 bg-gray-500/20 rounded">
                <div className="text-lg font-bold text-gray-400">{virustotal.undetected || 0}</div>
                <div className="text-xs text-gray-400">Undetected</div>
              </div>
            </div>
            {virustotal.reputation !== undefined && (
              <div className="mt-2 text-sm text-gray-400">
                Community Reputation Score: <span className={virustotal.reputation >= 0 ? 'text-green-400' : 'text-red-400'}>{virustotal.reputation}</span>
              </div>
            )}
          </div>
        )}

        {/* Abuse Categories */}
        {abuseCategories.length > 0 && (
          <div className="p-3 bg-white/5 rounded-lg">
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle className="h-4 w-4 text-warning" />
              <span className="text-sm font-medium text-white">Reported Abuse Categories</span>
            </div>
            <div className="flex flex-wrap gap-2">
              {abuseCategories.map((cat: number, idx: number) => (
                <Badge key={idx} variant="danger">
                  {categoryNames[cat] || `Category ${cat}`}
                </Badge>
              ))}
            </div>
          </div>
        )}

        {/* Recent Abuse Reports */}
        {recentReports.length > 0 && (
          <div className="p-3 bg-white/5 rounded-lg">
            <div className="flex items-center gap-2 mb-2">
              <FileWarning className="h-4 w-4 text-warning" />
              <span className="text-sm font-medium text-white">Recent Reports ({totalReports} total)</span>
            </div>
            <div className="space-y-2 max-h-40 overflow-y-auto">
              {recentReports.slice(0, 5).map((report: any, idx: number) => (
                <div key={idx} className="text-sm p-2 bg-white/5 rounded">
                  <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
                    <Clock className="h-3 w-3" />
                    {new Date(report.reportedAt).toLocaleString()}
                  </div>
                  {report.comment && (
                    <p className="text-gray-300 text-xs line-clamp-2">{report.comment}</p>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ThreatFox Malware Data */}
        {threatfoxFound && threatfoxData.length > 0 && (
          <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
            <div className="flex items-center gap-2 mb-2">
              <XCircle className="h-4 w-4 text-red-400" />
              <span className="text-sm font-medium text-red-400">Known Malware Indicator</span>
            </div>
            <div className="space-y-2">
              {threatfoxData.map((item: any, idx: number) => (
                <div key={idx} className="text-sm">
                  <Badge variant="danger">{item.malwarePrintable || item.malware}</Badge>
                  <span className="text-gray-400 ml-2">{item.threatType}</span>
                  {item.confidence && (
                    <span className="text-gray-500 ml-2">Confidence: {item.confidence}%</span>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Shodan Open Ports */}
        {shodanPorts.length > 0 && (
          <div className="p-3 bg-white/5 rounded-lg">
            <div className="flex items-center gap-2 mb-2">
              <Database className="h-4 w-4 text-primary" />
              <span className="text-sm font-medium text-white">Open Ports ({shodanPorts.length})</span>
            </div>
            <div className="flex flex-wrap gap-1">
              {shodanPorts.map((port: number, idx: number) => (
                <span key={idx} className="px-2 py-0.5 bg-primary/20 text-primary text-xs rounded">
                  {port}
                </span>
              ))}
            </div>
            {shodanVulns.length > 0 && (
              <div className="mt-2">
                <span className="text-xs text-red-400">Vulnerabilities: </span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {shodanVulns.map((vuln: string, idx: number) => (
                    <Badge key={idx} variant="danger">{vuln}</Badge>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Shodan Services */}
        {shodanServices.length > 0 && (
          <div className="p-3 bg-white/5 rounded-lg">
            <div className="flex items-center gap-2 mb-2">
              <Activity className="h-4 w-4 text-primary" />
              <span className="text-sm font-medium text-white">Running Services</span>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
              {shodanServices.slice(0, 9).map((svc: any, idx: number) => (
                <div key={idx} className="text-xs p-2 bg-white/5 rounded">
                  <span className="text-primary font-medium">{svc.port}/{svc.transport || 'tcp'}</span>
                  {svc.product && <span className="text-gray-400 ml-1">- {svc.product}</span>}
                  {svc.version && <span className="text-gray-500 ml-1">v{svc.version}</span>}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* AlienVault Threat Pulses */}
        {pulses.length > 0 && (
          <div className="p-3 bg-white/5 rounded-lg">
            <div className="flex items-center gap-2 mb-2">
              <Zap className="h-4 w-4 text-warning" />
              <span className="text-sm font-medium text-white">Threat Intelligence Pulses</span>
            </div>
            <div className="space-y-2 max-h-40 overflow-y-auto">
              {pulses.slice(0, 5).map((pulse: any, idx: number) => (
                <div key={idx} className="text-sm p-2 bg-white/5 rounded">
                  <div className="text-gray-300 font-medium text-xs">{pulse.name}</div>
                  {pulse.tags && pulse.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-1">
                      {pulse.tags.slice(0, 5).map((tag: string, tidx: number) => (
                        <span key={tidx} className="px-1.5 py-0.5 bg-warning/20 text-warning text-xs rounded">
                          {tag}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Validation/Whitelist Info */}
        {validations.length > 0 && (
          <div className="p-3 bg-white/5 rounded-lg">
            <div className="flex items-center gap-2 mb-2">
              <CheckCircle className="h-4 w-4 text-green-400" />
              <span className="text-sm font-medium text-white">Validations</span>
            </div>
            <div className="space-y-1">
              {validations.map((v: any, idx: number) => (
                <div key={idx} className="text-xs text-gray-400">
                  {v.message || v.name}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Network Info Summary */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-3 border-t border-white/10">
          <div className="text-center">
            <div className="text-xs text-gray-500 mb-1">ISP</div>
            <div className="text-sm text-gray-300 truncate">{abuseipdb.isp || ipqs.isp || shodan.isp || '-'}</div>
          </div>
          <div className="text-center">
            <div className="text-xs text-gray-500 mb-1">ASN</div>
            <div className="text-sm text-gray-300">{virustotal.asn ? `AS${virustotal.asn}` : shodan.asn || '-'}</div>
          </div>
          <div className="text-center">
            <div className="text-xs text-gray-500 mb-1">Country</div>
            <div className="text-sm text-gray-300">{abuseipdb.countryCode || ipqs.country || virustotal.country || '-'}</div>
          </div>
          <div className="text-center">
            <div className="text-xs text-gray-500 mb-1">Usage</div>
            <div className="text-sm text-gray-300 truncate">{abuseipdb.usageType || ipqs.connectionType || '-'}</div>
          </div>
        </div>

        {/* Findings Summary */}
        {summary.findings && summary.findings.length > 0 && (
          <div className="text-xs text-gray-500 pt-2 border-t border-white/10">
            {summary.findings.join(' | ')}
          </div>
        )}
      </div>
    </Card>
  );
};
