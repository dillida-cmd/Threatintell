import { useState } from 'react';
import {
  Hash, Search, AlertTriangle, CheckCircle, Shield, XCircle,
  FileText, Tag, Zap, FileWarning, Link, Clock
} from 'lucide-react';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';
import { Button } from '../common/Button';
import { Input } from '../common/Input';
import { Spinner } from '../common/Spinner';
import { RiskScore } from '../common/RiskScore';

interface HashLookupResult {
  hash: string;
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

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

export const HashLookup = () => {
  const [hash, setHash] = useState('');
  const [result, setResult] = useState<HashLookupResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const getHashType = (h: string): string => {
    const len = h.length;
    if (len === 32) return 'MD5';
    if (len === 40) return 'SHA1';
    if (len === 64) return 'SHA256';
    return 'Unknown';
  };

  const isValidHash = (h: string): boolean => {
    const trimmed = h.trim().toLowerCase();
    return /^[a-f0-9]{32}$/.test(trimmed) ||
           /^[a-f0-9]{40}$/.test(trimmed) ||
           /^[a-f0-9]{64}$/.test(trimmed);
  };

  const handleLookup = async () => {
    const trimmedHash = hash.trim().toLowerCase();
    if (!trimmedHash || !isValidHash(trimmedHash)) {
      setError('Please enter a valid MD5, SHA1, or SHA256 hash');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch('/api/threat-intel/investigate/hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash: trimmedHash }),
      });

      const data = await response.json();

      if (data.error) {
        setError(data.error);
      } else {
        setResult(data);
      }
    } catch (err) {
      setError('Failed to investigate hash');
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
  const vtTags = virustotal.tags || [];

  // URLhaus data
  const urlhausSignature = urlhaus.signature;
  const urlhausUrls = urlhaus.urls || [];
  const urlhausUrlCount = urlhaus.urlCount || 0;

  // AlienVault data
  const pulseCount = alienvault.pulseCount || 0;
  const pulses = alienvault.pulses || [];

  // File info (from any source)
  const fileName = virustotal.fileName || urlhaus.fileName || 'Unknown';
  const fileType = virustotal.fileType || urlhaus.fileType || alienvault.fileType;
  const fileSize = virustotal.fileSize || urlhaus.fileSize || alienvault.fileSize;

  return (
    <div className="space-y-6">
      {/* Search Box */}
      <Card title="File Hash Lookup" icon={<Hash className="h-5 w-5" />}>
        <div className="flex gap-3">
          <div className="flex-1">
            <Input
              placeholder="Enter MD5, SHA1, or SHA256 hash"
              value={hash}
              onChange={(e) => setHash(e.target.value)}
              onKeyPress={handleKeyPress}
              className="font-mono"
            />
          </div>
          <Button onClick={handleLookup} disabled={loading || !hash.trim()}>
            {loading ? <Spinner size="sm" /> : <Search className="h-4 w-4" />}
            <span className="ml-2">Investigate</span>
          </Button>
        </div>
        <div className="flex items-center gap-4 mt-2">
          {hash.trim() && isValidHash(hash.trim()) && (
            <Badge variant="info">{getHashType(hash.trim())}</Badge>
          )}
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
          <Card title="File Analysis" icon={<Shield className="h-5 w-5" />}>
            <div className="space-y-6">
              {/* Risk Score and Hash */}
              <div className="flex flex-col md:flex-row items-start gap-6">
                <RiskScore score={result.summary.riskScore} size="lg" />

                <div className="flex-1 w-full">
                  <div className="mb-3">
                    <div className="flex items-center gap-2 mb-2">
                      <Badge variant="info">{getHashType(result.hash)}</Badge>
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
                      {pulseCount > 0 && (
                        <Badge variant="warning">{pulseCount} Threat Pulses</Badge>
                      )}
                    </div>
                    <code className="text-primary text-sm break-all font-mono block p-2 bg-black/40 rounded">
                      {result.hash}
                    </code>
                  </div>

                  {/* File Info */}
                  {(fileName || fileType || fileSize) && (
                    <div className="p-3 bg-white/5 rounded-lg mb-4">
                      <div className="flex items-center gap-2 mb-2">
                        <FileText className="h-4 w-4 text-primary" />
                        <span className="text-sm font-medium text-white">{fileName}</span>
                      </div>
                      <div className="flex gap-4 text-sm">
                        {fileType && (
                          <span className="text-gray-400">Type: <span className="text-white">{fileType}</span></span>
                        )}
                        {fileSize && (
                          <span className="text-gray-400">Size: <span className="text-white">{formatBytes(fileSize)}</span></span>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Malware Signature */}
                  {urlhausSignature && (
                    <div className="flex items-center gap-2 mb-2">
                      <FileWarning className="h-4 w-4 text-red-400" />
                      <span className="text-sm text-gray-400">Malware Family:</span>
                      <Badge variant="danger">{urlhausSignature}</Badge>
                    </div>
                  )}
                </div>
              </div>

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
                      Community Reputation: <span className={virustotal.reputation >= 0 ? 'text-green-400' : 'text-red-400'}>{virustotal.reputation}</span>
                    </div>
                  )}
                </div>
              )}

              {/* File Tags */}
              {vtTags.length > 0 && (
                <div className="p-3 bg-white/5 rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    <Tag className="h-4 w-4 text-primary" />
                    <span className="text-sm font-medium text-white">File Tags</span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {vtTags.map((tag: string, idx: number) => (
                      <Badge key={idx} variant={
                        tag.includes('malware') || tag.includes('ransomware') || tag.includes('trojan')
                          ? 'danger'
                          : tag.includes('suspicious') || tag.includes('detect')
                            ? 'warning'
                            : 'info'
                      }>
                        {tag}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* Distribution URLs */}
              {urlhausUrlCount > 0 && (
                <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    <Link className="h-4 w-4 text-red-400" />
                    <span className="text-sm font-medium text-red-400">Distribution URLs ({urlhausUrlCount})</span>
                  </div>
                  {urlhausUrls.length > 0 && (
                    <div className="space-y-2 max-h-32 overflow-y-auto">
                      {urlhausUrls.slice(0, 5).map((urlInfo: any, idx: number) => (
                        <div key={idx} className="p-2 bg-black/40 rounded text-xs">
                          <code className="text-red-400 break-all">{urlInfo.url}</code>
                          <div className="flex items-center gap-2 mt-1 text-gray-500">
                            <span className={urlInfo.status === 'online' ? 'text-red-400' : 'text-gray-500'}>
                              {urlInfo.status}
                            </span>
                            {urlInfo.dateAdded && (
                              <>
                                <Clock className="h-3 w-3" />
                                <span>{new Date(urlInfo.dateAdded).toLocaleDateString()}</span>
                              </>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
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
                            {pulse.tags.slice(0, 8).map((tag: string, tidx: number) => (
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

              {/* Investigation Timestamp */}
              <div className="grid grid-cols-2 gap-3 pt-3 border-t border-white/10">
                {virustotal.lastAnalysisDate && (
                  <div className="text-center">
                    <div className="text-xs text-gray-500 mb-1">Last Analysis</div>
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
            </div>
          </Card>
        </div>
      )}
    </div>
  );
};
