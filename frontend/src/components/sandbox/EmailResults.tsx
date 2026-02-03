import { Mail, User, Users, Calendar, Paperclip, Link, Shield, Globe, AlertTriangle, Route } from 'lucide-react';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';
import { RiskScore } from '../common/RiskScore';
import { formatBytes } from '../../utils/formatters';
import type { EmailResults as EmailResultsType } from '../../types';

interface EmailResultsProps {
  results: EmailResultsType;
}

export const EmailResults = ({ results }: EmailResultsProps) => {
  // Handle both nested headers and flat structure
  const headers = results.headers || {};
  const subject = headers.subject || results.subject || '';
  const from = headers.from || results.from || '';
  const to = headers.to || results.to || '';
  const cc = results.cc || '';
  const date = headers.date || results.date || '';

  // Authentication results (backend uses 'authentication', not 'security_indicators')
  const auth = results.authentication || results.security_indicators || {};

  // Risk score and phishing indicators
  const riskScore = results.riskScore ?? results.risk_score ?? 0;
  const phishingIndicators = results.phishingIndicators || results.phishing_indicators || [];

  return (
    <div className="space-y-6 animate-slide-up">
      {/* Risk Score Overview */}
      {(riskScore > 0 || phishingIndicators.length > 0) && (
        <Card title="Risk Assessment" icon={<AlertTriangle className="h-5 w-5" />}>
          <div className="flex flex-col md:flex-row items-center gap-6">
            <RiskScore score={riskScore} size="lg" />
            {phishingIndicators.length > 0 && (
              <div className="flex-1 w-full">
                <p className="text-gray-400 text-sm mb-2">Warning Indicators:</p>
                <div className="space-y-1">
                  {phishingIndicators.map((indicator: any, idx: number) => (
                    <div
                      key={idx}
                      className="flex items-center gap-2 p-2 bg-red-500/10 rounded-lg text-red-400 text-sm"
                    >
                      <AlertTriangle className="h-4 w-4 flex-shrink-0" />
                      {typeof indicator === 'string' ? indicator : indicator.description || indicator.reason}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Card>
      )}

      {/* Email Header Info */}
      <Card title="Email Details" icon={<Mail className="h-5 w-5" />}>
        <div className="space-y-3">
          {subject && (
            <InfoRow label="Subject" value={subject} icon={<Mail className="h-4 w-4" />} />
          )}
          {from && (
            <InfoRow label="From" value={from} icon={<User className="h-4 w-4" />} />
          )}
          {to && (
            <InfoRow label="To" value={Array.isArray(to) ? to.join(', ') : to} icon={<Users className="h-4 w-4" />} />
          )}
          {cc && (
            <InfoRow label="CC" value={Array.isArray(cc) ? cc.join(', ') : cc} icon={<Users className="h-4 w-4" />} />
          )}
          {date && (
            <InfoRow label="Date" value={date} icon={<Calendar className="h-4 w-4" />} />
          )}
          {results.senderDomain && (
            <InfoRow label="Sender Domain" value={results.senderDomain} icon={<Globe className="h-4 w-4" />} />
          )}
        </div>
      </Card>

      {/* Security Indicators / Authentication */}
      {auth && (Object.keys(auth).length > 0) && (
        <Card title="Email Authentication" icon={<Shield className="h-5 w-5" />}>
          <div className="grid sm:grid-cols-3 gap-4">
            {auth.spf && (
              <SecurityBadge label="SPF" result={auth.spf} />
            )}
            {auth.dkim && (
              <SecurityBadge label="DKIM" result={auth.dkim} />
            )}
            {auth.dmarc && (
              <SecurityBadge label="DMARC" result={auth.dmarc} />
            )}
          </div>
        </Card>
      )}

      {/* Routing Path / IPs */}
      {results.routingIps && results.routingIps.length > 0 && (
        <Card title="Email Routing" icon={<Route className="h-5 w-5" />}>
          <div className="space-y-2">
            {results.routingIps.map((routing: any, index: number) => (
              <div
                key={index}
                className="p-3 bg-background-darker/50 rounded-lg"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-primary font-mono text-sm">{routing.ip}</span>
                  {routing.threat?.abuseScore > 0 && (
                    <Badge variant="danger">Risk: {routing.threat.abuseScore}%</Badge>
                  )}
                </div>
                {routing.info && (
                  <div className="text-gray-400 text-xs">
                    {routing.info.isp || routing.info.org} {routing.info.country && `• ${routing.info.country}`}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Attachments */}
      {results.attachments && results.attachments.length > 0 && (
        <Card title={`Attachments (${results.attachmentCount || results.attachments.length})`} icon={<Paperclip className="h-5 w-5" />}>
          <div className="space-y-2">
            {results.attachments.map((attachment: any, index: number) => {
              const isSuspicious = attachment.suspicious || attachment.is_suspicious;
              return (
                <div
                  key={index}
                  className={`flex items-center justify-between p-3 rounded-lg ${isSuspicious ? 'bg-red-500/10 border border-red-500/30' : 'bg-background-darker/50'}`}
                >
                  <div className="flex items-center gap-3">
                    <Paperclip className={`h-4 w-4 ${isSuspicious ? 'text-red-400' : 'text-gray-400'}`} />
                    <span className={`text-sm ${isSuspicious ? 'text-red-400' : 'text-white'}`}>{attachment.filename}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <Badge variant={isSuspicious ? 'danger' : 'neutral'}>{attachment.content_type || attachment.contentType}</Badge>
                    <span className="text-gray-400 text-sm">{formatBytes(attachment.size)}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </Card>
      )}

      {/* URLs Found */}
      {results.urls && results.urls.length > 0 && (
        <Card title={`URLs Extracted (${results.urlCount || results.urls.length})`} icon={<Link className="h-5 w-5" />}>
          <div className="space-y-2 max-h-60 overflow-y-auto">
            {results.urls.map((url: string, index: number) => (
              <div
                key={index}
                className="flex items-center gap-2 p-2 bg-background-darker/50 rounded-lg"
              >
                <Globe className="h-4 w-4 text-gray-400 flex-shrink-0" />
                <code className="text-primary text-xs break-all">{url}</code>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Enriched URLs with threat info */}
      {results.enrichedUrls && results.enrichedUrls.length > 0 && (
        <Card title="URL Analysis" icon={<Link className="h-5 w-5" />}>
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {results.enrichedUrls.map((urlInfo: any, index: number) => (
              <div
                key={index}
                className={`p-3 rounded-lg ${urlInfo.suspicious ? 'bg-red-500/10 border border-red-500/30' : 'bg-background-darker/50'}`}
              >
                <code className={`text-xs break-all ${urlInfo.suspicious ? 'text-red-400' : 'text-primary'}`}>
                  {urlInfo.url}
                </code>
                <div className="flex items-center gap-2 mt-2 text-xs text-gray-400">
                  {urlInfo.domain && <span>{urlInfo.domain}</span>}
                  {urlInfo.suspicious && (
                    <Badge variant="danger">Suspicious</Badge>
                  )}
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* QR Codes found in email */}
      {results.qrCodes && results.qrCodes.length > 0 && (
        <Card title={`QR Codes Found (${results.qrCodeCount || results.qrCodes.length})`} icon={<AlertTriangle className="h-5 w-5 text-warning" />}>
          <div className="space-y-2">
            {results.qrCodes.map((qr: any, index: number) => (
              <div
                key={index}
                className={`p-3 rounded-lg ${qr.risk_indicators?.length > 0 ? 'bg-red-500/10 border border-red-500/30' : 'bg-background-darker/50'}`}
              >
                <code className="text-primary text-xs break-all">{qr.raw_data || qr.data}</code>
                {qr.urls && qr.urls.length > 0 && (
                  <div className="mt-2">
                    {qr.urls.map((url: string, idx: number) => (
                      <div key={idx} className="text-xs text-gray-400">{url}</div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
};

interface InfoRowProps {
  label: string;
  value: string;
  icon: React.ReactNode;
}

const InfoRow = ({ label, value, icon }: InfoRowProps) => (
  <div className="flex items-start gap-3">
    <span className="text-gray-400 mt-0.5">{icon}</span>
    <div className="flex-1 min-w-0">
      <span className="text-gray-400 text-sm block">{label}</span>
      <span className="text-white text-sm break-all">{value}</span>
    </div>
  </div>
);

interface SecurityBadgeProps {
  label: string;
  result: any;
}

const SecurityBadge = ({ label, result }: SecurityBadgeProps) => {
  // Handle both string and object formats
  const value = typeof result === 'string' ? result : (result?.result || result?.status || 'unknown');
  const details = typeof result === 'object' ? result?.details : null;

  const isPass = value.toLowerCase().includes('pass');
  const isFail = value.toLowerCase().includes('fail') || value.toLowerCase().includes('none');

  return (
    <div className="p-3 bg-background-darker/50 rounded-lg">
      <div className="flex items-center justify-between mb-1">
        <span className="text-gray-400 text-sm">{label}</span>
        <Badge variant={isPass ? 'safe' : isFail ? 'danger' : 'warning'}>
          {value}
        </Badge>
      </div>
      {details && (
        <p className="text-gray-500 text-xs truncate">{details}</p>
      )}
    </div>
  );
};
