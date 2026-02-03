import { Shield, Globe, Hash, AlertTriangle, CheckCircle, ExternalLink } from 'lucide-react';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';
import { RiskScore } from '../common/RiskScore';
import type { IocInvestigation } from '../../types';

interface IocInvestigationCardProps {
  investigation: IocInvestigation;
}

export const IocInvestigationCard = ({ investigation }: IocInvestigationCardProps) => {
  const { summary, ips, urls, hashes } = investigation;
  const hasMalicious = summary.maliciousIOCs > 0;

  return (
    <Card
      title="Threat Intelligence Investigation"
      icon={<Shield className="h-5 w-5" />}
      className={hasMalicious ? 'border-danger/30' : ''}
    >
      {/* Summary */}
      <div className="flex flex-col md:flex-row items-center gap-6 mb-6">
        <RiskScore score={summary.overallRiskScore} size="lg" />
        <div className="flex-1 w-full">
          <div className="grid grid-cols-3 gap-4">
            <div className="p-3 bg-black/40 rounded-lg text-center">
              <p className="text-2xl font-bold text-white">{summary.totalIOCs}</p>
              <p className="text-gray-400 text-xs">IOCs Checked</p>
            </div>
            <div className="p-3 bg-black/40 rounded-lg text-center">
              <p className={`text-2xl font-bold ${hasMalicious ? 'text-danger' : 'text-success'}`}>
                {summary.maliciousIOCs}
              </p>
              <p className="text-gray-400 text-xs">Malicious</p>
            </div>
            <div className="p-3 bg-black/40 rounded-lg text-center">
              <p className="text-2xl font-bold text-white">
                {(ips?.length || 0) + (urls?.length || 0) + (hashes?.length || 0)}
              </p>
              <p className="text-gray-400 text-xs">Sources Used</p>
            </div>
          </div>
        </div>
      </div>

      {/* IP Results */}
      {ips && ips.length > 0 && (
        <div className="mb-4">
          <h4 className="text-gray-400 text-sm mb-2 flex items-center gap-2">
            <Globe className="h-4 w-4" />
            IP Address Investigation ({ips.length})
          </h4>
          <div className="space-y-2">
            {ips.map((ipResult, idx) => (
              <IocResultItem
                key={idx}
                value={ipResult.ip}
                isMalicious={ipResult.summary.isMalicious}
                riskScore={ipResult.summary.riskScore}
                findings={ipResult.summary.findings}
                sources={ipResult.sources}
              />
            ))}
          </div>
        </div>
      )}

      {/* URL Results */}
      {urls && urls.length > 0 && (
        <div className="mb-4">
          <h4 className="text-gray-400 text-sm mb-2 flex items-center gap-2">
            <ExternalLink className="h-4 w-4" />
            URL Investigation ({urls.length})
          </h4>
          <div className="space-y-2">
            {urls.map((urlResult, idx) => (
              <IocResultItem
                key={idx}
                value={urlResult.url}
                isMalicious={urlResult.summary.isMalicious}
                riskScore={urlResult.summary.riskScore}
                findings={urlResult.summary.findings}
                sources={urlResult.sources}
              />
            ))}
          </div>
        </div>
      )}

      {/* Hash Results */}
      {hashes && hashes.length > 0 && (
        <div className="mb-4">
          <h4 className="text-gray-400 text-sm mb-2 flex items-center gap-2">
            <Hash className="h-4 w-4" />
            File Hash Investigation ({hashes.length})
          </h4>
          <div className="space-y-2">
            {hashes.map((hashResult, idx) => (
              <IocResultItem
                key={idx}
                value={hashResult.hash}
                isMalicious={hashResult.summary.isMalicious}
                riskScore={hashResult.summary.riskScore}
                findings={hashResult.summary.findings}
                sources={hashResult.sources}
              />
            ))}
          </div>
        </div>
      )}

      {/* No IOCs message */}
      {(!ips || ips.length === 0) && (!urls || urls.length === 0) && (!hashes || hashes.length === 0) && (
        <div className="text-center py-4 text-gray-400">
          No IOCs were investigated
        </div>
      )}
    </Card>
  );
};

interface IocResultItemProps {
  value: string;
  isMalicious: boolean;
  riskScore: number;
  findings: string[];
  sources: Record<string, any>;
}

const IocResultItem = ({ value, isMalicious, riskScore, findings, sources }: IocResultItemProps) => (
  <div className={`p-3 rounded-lg ${isMalicious ? 'bg-danger/10 border border-danger/30' : 'bg-black/40'}`}>
    <div className="flex items-center justify-between mb-2">
      <div className="flex items-center gap-2">
        {isMalicious ? (
          <AlertTriangle className="h-4 w-4 text-danger" />
        ) : (
          <CheckCircle className="h-4 w-4 text-success" />
        )}
        <code className={`text-sm ${isMalicious ? 'text-danger' : 'text-white'} break-all`}>
          {value.length > 60 ? value.substring(0, 60) + '...' : value}
        </code>
      </div>
      <div className="flex items-center gap-2">
        {riskScore > 0 && (
          <Badge variant={riskScore > 70 ? 'danger' : riskScore > 30 ? 'warning' : 'safe'}>
            Risk: {riskScore}
          </Badge>
        )}
        <Badge variant={isMalicious ? 'danger' : 'safe'}>
          {isMalicious ? 'Malicious' : 'Clean'}
        </Badge>
      </div>
    </div>

    {/* Findings */}
    {findings && findings.length > 0 && (
      <div className="mt-2 space-y-1">
        {findings.map((finding, idx) => (
          <div key={idx} className="text-xs text-warning flex items-center gap-1">
            <AlertTriangle className="h-3 w-3" />
            {finding}
          </div>
        ))}
      </div>
    )}

    {/* Source details */}
    {sources && Object.keys(sources).length > 0 && (
      <div className="mt-2 flex flex-wrap gap-1">
        {Object.keys(sources).map((source) => (
          <span key={source} className="text-xs bg-black/40 px-2 py-0.5 rounded text-gray-400">
            {source}
          </span>
        ))}
      </div>
    )}
  </div>
);
