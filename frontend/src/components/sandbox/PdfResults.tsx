import { FileText, User, Calendar, FileCode, Link, AlertTriangle, Info, Download, QrCode, ExternalLink } from 'lucide-react';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';
import { RiskScore } from '../common/RiskScore';
import type { PdfResults as PdfResultsType } from '../../types';

interface PdfResultsProps {
  results: PdfResultsType;
}

export const PdfResults = ({ results }: PdfResultsProps) => {
  // Handle both snake_case and camelCase from backend
  const metadata = results.metadata || {};
  const hasJavaScript = results.hasJavaScript ?? results.has_javascript ?? false;
  const hasEmbeddedFiles = results.hasEmbeddedFiles ?? results.has_embedded_files ?? false;
  const hasForms = results.hasForms ?? results.has_forms ?? false;
  const hasExternalRefs = results.hasExternalRefs ?? results.has_external_refs ?? false;
  const pageCount = results.pageCount ?? results.page_count ?? 0;
  const riskScore = results.riskScore ?? results.risk_score ?? 0;
  const riskLevel = results.riskLevel ?? results.risk_level ?? 'Low';

  const hasSecurityConcerns = hasJavaScript || hasEmbeddedFiles || hasExternalRefs;

  return (
    <div className="space-y-6 animate-slide-up">
      {/* Risk Score Overview */}
      {riskScore > 0 && (
        <Card title="Risk Assessment" icon={<AlertTriangle className="h-5 w-5" />}>
          <div className="flex flex-col md:flex-row items-center gap-6">
            <RiskScore score={riskScore} size="lg" />
            <div className="flex-1 w-full">
              <Badge variant={riskLevel === 'Critical' || riskLevel === 'High' ? 'danger' : riskLevel === 'Medium' ? 'warning' : 'safe'}>
                {riskLevel} Risk
              </Badge>
            </div>
          </div>
        </Card>
      )}

      {/* Document Info */}
      <Card title="Document Details" icon={<FileText className="h-5 w-5" />}>
        <div className="space-y-3">
          {metadata.title && <InfoRow label="Title" value={metadata.title} />}
          {metadata.author && (
            <InfoRow label="Author" value={metadata.author} icon={<User className="h-4 w-4" />} />
          )}
          {metadata.creator && <InfoRow label="Creator" value={metadata.creator} />}
          {metadata.producer && <InfoRow label="Producer" value={metadata.producer} />}
          {pageCount > 0 && (
            <InfoRow label="Pages" value={pageCount.toString()} />
          )}
          {metadata.creationDate && (
            <InfoRow
              label="Created"
              value={metadata.creationDate}
              icon={<Calendar className="h-4 w-4" />}
            />
          )}
          {metadata.modDate && (
            <InfoRow
              label="Modified"
              value={metadata.modDate}
              icon={<Calendar className="h-4 w-4" />}
            />
          )}
        </div>
      </Card>

      {/* Security Analysis */}
      <Card
        title="Security Analysis"
        icon={<FileCode className="h-5 w-5" />}
        className={hasSecurityConcerns ? 'border-warning/30' : ''}
      >
        <div className="grid sm:grid-cols-2 gap-4">
          <SecurityIndicator
            label="JavaScript"
            active={hasJavaScript}
            warning={hasJavaScript}
          />
          <SecurityIndicator
            label="Embedded Files"
            active={hasEmbeddedFiles}
            warning={hasEmbeddedFiles}
          />
          <SecurityIndicator
            label="External References"
            active={hasExternalRefs}
            warning={hasExternalRefs}
          />
          <SecurityIndicator
            label="Forms"
            active={hasForms}
            warning={false}
          />
        </div>
      </Card>

      {/* JavaScript Findings */}
      {results.javascript && results.javascript.length > 0 && (
        <Card
          title="JavaScript Detected"
          icon={<AlertTriangle className="h-5 w-5 text-danger" />}
          className="border-danger/30"
        >
          <div className="space-y-2">
            {results.javascript.map((js: string, index: number) => (
              <div
                key={index}
                className="flex items-center gap-2 p-2 bg-danger/10 rounded-lg text-danger"
              >
                <AlertTriangle className="h-4 w-4 flex-shrink-0" />
                <span className="text-sm">{js}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* External References */}
      {results.externalReferences && results.externalReferences.length > 0 && (
        <Card
          title="External References"
          icon={<ExternalLink className="h-5 w-5 text-warning" />}
          className="border-warning/30"
        >
          <div className="space-y-2">
            {results.externalReferences.map((ref: any, index: number) => (
              <div
                key={index}
                className="p-2 bg-warning/10 rounded-lg"
              >
                <span className="text-warning text-sm">{typeof ref === 'string' ? ref : ref.path || ref.url}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Process Triggers */}
      {results.processTriggers && results.processTriggers.length > 0 && (
        <Card
          title="Process/Shell Triggers"
          icon={<AlertTriangle className="h-5 w-5 text-danger" />}
          className="border-danger/30"
        >
          <div className="space-y-2">
            {results.processTriggers.map((trigger: any, index: number) => (
              <div
                key={index}
                className="p-3 bg-danger/10 rounded-lg"
              >
                <div className="text-danger text-sm font-medium">{trigger.type}</div>
                {trigger.command && (
                  <code className="text-xs text-gray-400 block mt-1">{trigger.command}</code>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Download URLs */}
      {results.downloadUrls && results.downloadUrls.length > 0 && (
        <Card title="Download URLs Detected" icon={<Download className="h-5 w-5 text-warning" />}>
          <div className="space-y-2">
            {results.downloadUrls.map((dl: any, index: number) => (
              <div
                key={index}
                className={`p-2 rounded-lg ${dl.is_high_risk ? 'bg-danger/10 border border-danger/30' : 'bg-background-darker/50'}`}
              >
                <code className={`text-xs break-all ${dl.is_high_risk ? 'text-danger' : 'text-primary'}`}>
                  {dl.url}
                </code>
                {dl.extension && (
                  <Badge variant={dl.is_high_risk ? 'danger' : 'neutral'} className="ml-2">
                    {dl.extension}
                  </Badge>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* QR Codes */}
      {results.qrCodes && results.qrCodes.length > 0 && (
        <Card title={`QR Codes Found (${results.qrCodeCount || results.qrCodes.length})`} icon={<QrCode className="h-5 w-5 text-warning" />}>
          <div className="space-y-2">
            {results.qrCodes.map((qr: any, index: number) => (
              <div
                key={index}
                className={`p-3 rounded-lg ${qr.risk_level === 'high' || qr.risk_level === 'critical' ? 'bg-danger/10 border border-danger/30' : 'bg-background-darker/50'}`}
              >
                <code className="text-primary text-xs break-all">{qr.raw_data || qr.data}</code>
                {qr.urls && qr.urls.length > 0 && (
                  <div className="mt-2 space-y-1">
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

      {/* URLs Found */}
      {results.urls && results.urls.length > 0 && (
        <Card title={`URLs Extracted (${results.urlCount || results.urls.length})`} icon={<Link className="h-5 w-5" />}>
          <div className="space-y-2 max-h-60 overflow-y-auto">
            {results.urls.map((url: string, index: number) => (
              <div
                key={index}
                className="flex items-center gap-2 p-2 bg-background-darker/50 rounded-lg"
              >
                <Link className="h-4 w-4 text-gray-400 flex-shrink-0" />
                <code className="text-primary text-xs break-all">{url}</code>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Metadata */}
      {metadata && Object.keys(metadata).length > 0 && (
        <Card title="Metadata" icon={<Info className="h-5 w-5" />}>
          <div className="space-y-2">
            {Object.entries(metadata).map(([key, value]) => (
              value && (
                <div key={key} className="flex items-start justify-between gap-4 py-1">
                  <span className="text-gray-400 text-sm capitalize">{key}</span>
                  <span className="text-white text-sm text-right break-all">{String(value)}</span>
                </div>
              )
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
  icon?: React.ReactNode;
}

const InfoRow = ({ label, value, icon }: InfoRowProps) => (
  <div className="flex items-start justify-between gap-4">
    <span className="text-gray-400 text-sm flex items-center gap-1.5">
      {icon}
      {label}
    </span>
    <span className="text-white text-sm text-right">{value}</span>
  </div>
);

interface SecurityIndicatorProps {
  label: string;
  active?: boolean;
  warning: boolean;
}

const SecurityIndicator = ({ label, active, warning }: SecurityIndicatorProps) => (
  <div className="flex items-center justify-between p-3 bg-background-darker/50 rounded-lg">
    <span className="text-gray-400 text-sm">{label}</span>
    <Badge variant={active ? (warning ? 'warning' : 'info') : 'safe'}>
      {active ? 'Yes' : 'No'}
    </Badge>
  </div>
);
