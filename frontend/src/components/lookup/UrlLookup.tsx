import { useState } from 'react';
import {
  Link, Search, AlertTriangle, CheckCircle, Shield, XCircle,
  Tag, FileWarning, Zap, Globe
} from 'lucide-react';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';
import { Button } from '../common/Button';
import { Input } from '../common/Input';
import { Spinner } from '../common/Spinner';
import { RiskScore } from '../common/RiskScore';

interface UrlLookupResult {
  url: string;
  investigatedAt: string;
  sources: Record<string, any>;
  summary: {
    isMalicious: boolean;
    totalSources: number;
    maliciousSources: number;
    riskScore: number;
    findings: string[];
  };
}

export const UrlLookup = () => {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState<UrlLookupResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleLookup = async () => {
    if (!url.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch('/api/threat-intel/investigate/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim() }),
      });

      const data = await response.json();

      if (data.error) {
        setError(data.error);
      } else {
        setResult(data);
      }
    } catch (err) {
      setError('Failed to investigate URL');
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleLookup();
    }
  };

  // Extract data from sources
  const sources = result?.sources || {};
  const virustotal = sources.virustotal || {};
  const urlhaus = sources.urlhaus || {};
  const alienvault = sources.alienvault_otx || {};

  // VirusTotal stats
  const vtMalicious = virustotal.malicious || 0;
  const vtSuspicious = virustotal.suspicious || 0;
  const vtHarmless = virustotal.harmless || 0;
  const vtTotal = vtMalicious + vtSuspicious + vtHarmless + (virustotal.undetected || 0);
  const vtCategories = virustotal.categories || {};

  // URLhaus data
  const urlhausThreat = urlhaus.threat;
  const urlhausStatus = urlhaus.urlStatus;
  const urlhausTags = urlhaus.tags || [];
  const urlhausPayloads = urlhaus.payloads || [];

  // AlienVault data
  const pulseCount = alienvault.pulseCount || 0;
  const pulses = alienvault.pulses || [];
  const validations = alienvault.validation || [];

  return (
    <div className="space-y-6">
      {/* Search Box */}
      <Card title="URL Threat Lookup" icon={<Link className="h-5 w-5" />}>
        <div className="flex gap-3">
          <div className="flex-1">
            <Input
              placeholder="Enter URL to investigate (e.g., https://example.com)"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyPress={handleKeyPress}
            />
          </div>
          <Button onClick={handleLookup} disabled={loading || !url.trim()}>
            {loading ? <Spinner size="sm" /> : <Search className="h-4 w-4" />}
            <span className="ml-2">Investigate</span>
          </Button>
        </div>
      </Card>

      {/* Error */}
      {error && (
        <Card className="border-danger/30">
          <div className="flex items-center gap-2 text-danger">
            <AlertTriangle className="h-5 w-5" />
            <span>{error}</span>
          </div>
        </Card>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-6 animate-slide-up">
          {/* Summary Card */}
          <Card title="Threat Analysis" icon={<Shield className="h-5 w-5" />}>
            <div className="space-y-6">
              {/* Risk Score and URL */}
              <div className="flex flex-col md:flex-row items-start gap-6">
                <RiskScore score={result.summary.riskScore} size="lg" />

                <div className="flex-1 w-full">
                  <div className="mb-3 p-2 bg-black/40 rounded">
                    <code className="text-primary text-sm break-all">{result.url}</code>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 mb-4">
                    {result.summary.isMalicious ? (
                      <Badge variant="danger" className="flex items-center gap-1">
                        <XCircle className="h-3 w-3" />
                        Malicious
                      </Badge>
                    ) : (
                      <Badge variant="safe" className="flex items-center gap-1">
                        <CheckCircle className="h-3 w-3" />
                        Clean
                      </Badge>
                    )}
                    {vtMalicious > 0 && (
                      <Badge variant="danger">{vtMalicious}/{vtTotal} Detections</Badge>
                    )}
                    {urlhausThreat && (
                      <Badge variant="danger">{urlhausThreat}</Badge>
                    )}
                    {pulseCount > 0 && (
                      <Badge variant="warning">{pulseCount} Threat Pulses</Badge>
                    )}
                  </div>

                  {/* Final URL if different */}
                  {virustotal.finalUrl && virustotal.finalUrl !== result.url && (
                    <div className="text-sm text-gray-400 mb-2">
                      <span className="text-gray-500">Redirects to: </span>
                      <span className="text-warning">{virustotal.finalUrl}</span>
                    </div>
                  )}

                  {/* Page Title */}
                  {virustotal.title && (
                    <div className="text-sm text-gray-300">
                      <Globe className="h-3 w-3 inline mr-1" />
                      {virustotal.title}
                    </div>
                  )}
                </div>
              </div>

              {/* VirusTotal Analysis */}
              {vtTotal > 0 && (
                <div className="p-3 bg-white/5 rounded-lg">
                  <div className="flex items-center gap-2 mb-3">
                    <Shield className="h-4 w-4 text-primary" />
                    <span className="text-sm font-medium text-white">Security Vendor Analysis ({vtTotal} engines)</span>
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
                      Community Reputation: <span className={virustotal.reputation >= 0 ? 'text-green-400' : 'text-red-400'}>{virustotal.reputation}</span>
                    </div>
                  )}
                </div>
              )}

              {/* URL Categories */}
              {Object.keys(vtCategories).length > 0 && (
                <div className="p-3 bg-white/5 rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    <Tag className="h-4 w-4 text-primary" />
                    <span className="text-sm font-medium text-white">URL Categories</span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(vtCategories).map(([, category], idx) => (
                      <Badge key={idx} variant={
                        String(category).toLowerCase().includes('malware') ||
                        String(category).toLowerCase().includes('phishing') ||
                        String(category).toLowerCase().includes('infection')
                          ? 'danger' : 'info'
                      }>
                        {String(category)}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* URLhaus Threat Info */}
              {urlhausThreat && (
                <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    <XCircle className="h-4 w-4 text-red-400" />
                    <span className="text-sm font-medium text-red-400">Known Malicious URL</span>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                    <div>
                      <span className="text-xs text-gray-500">Threat Type</span>
                      <div className="text-sm text-red-400 font-medium">{urlhausThreat}</div>
                    </div>
                    {urlhausStatus && (
                      <div>
                        <span className="text-xs text-gray-500">Status</span>
                        <div className="text-sm text-white">{urlhausStatus}</div>
                      </div>
                    )}
                    {urlhaus.dateAdded && (
                      <div>
                        <span className="text-xs text-gray-500">First Seen</span>
                        <div className="text-sm text-gray-300">{new Date(urlhaus.dateAdded).toLocaleDateString()}</div>
                      </div>
                    )}
                  </div>
                  {urlhausTags.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {urlhausTags.map((tag: string, idx: number) => (
                        <Badge key={idx} variant="danger">{tag}</Badge>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Malware Payloads */}
              {urlhausPayloads.length > 0 && (
                <div className="p-3 bg-white/5 rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    <FileWarning className="h-4 w-4 text-danger" />
                    <span className="text-sm font-medium text-white">Associated Malware Payloads</span>
                  </div>
                  <div className="space-y-2">
                    {urlhausPayloads.map((payload: any, idx: number) => (
                      <div key={idx} className="p-2 bg-black/40 rounded flex items-center justify-between">
                        <div>
                          <span className="text-sm text-red-400">{payload.filename || 'Unknown'}</span>
                          <span className="text-xs text-gray-500 ml-2">({payload.fileType})</span>
                        </div>
                        {payload.signature && (
                          <Badge variant="danger">{payload.signature}</Badge>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Threat Intelligence Pulses */}
              {pulses.length > 0 && (
                <div className="p-3 bg-white/5 rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    <Zap className="h-4 w-4 text-warning" />
                    <span className="text-sm font-medium text-white">Threat Intelligence Pulses ({pulseCount})</span>
                  </div>
                  <div className="space-y-2 max-h-40 overflow-y-auto">
                    {pulses.slice(0, 5).map((pulse: any, idx: number) => (
                      <div key={idx} className="p-2 bg-black/40 rounded">
                        <div className="text-sm text-gray-300">{pulse.name}</div>
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

              {/* Validations */}
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

              {/* Domain Info */}
              {alienvault.domain && (
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3 pt-3 border-t border-white/10">
                  <div className="text-center">
                    <div className="text-xs text-gray-500 mb-1">Domain</div>
                    <div className="text-sm text-gray-300">{alienvault.domain}</div>
                  </div>
                  {virustotal.lastAnalysisDate && (
                    <div className="text-center">
                      <div className="text-xs text-gray-500 mb-1">Last Analyzed</div>
                      <div className="text-sm text-gray-300">
                        {new Date(virustotal.lastAnalysisDate * 1000).toLocaleDateString()}
                      </div>
                    </div>
                  )}
                  {result.investigatedAt && (
                    <div className="text-center">
                      <div className="text-xs text-gray-500 mb-1">Investigated</div>
                      <div className="text-sm text-gray-300">
                        {new Date(result.investigatedAt).toLocaleString()}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </Card>
        </div>
      )}
    </div>
  );
};
