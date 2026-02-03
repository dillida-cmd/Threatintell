import { FileSpreadsheet, Code, Link, AlertTriangle, Package, Download, Globe, Terminal } from 'lucide-react';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';
import { RiskScore } from '../common/RiskScore';
import type { OfficeResults as OfficeResultsType } from '../../types';

interface OfficeResultsProps {
  results: OfficeResultsType;
}

export const OfficeResults = ({ results }: OfficeResultsProps) => {
  // Handle both camelCase and snake_case
  const hasMacros = results.hasMacros ?? results.has_macros ?? false;
  const macros = results.macros || [];
  const autoExecution = results.autoExecution || results.auto_execution || [];
  const suspiciousPatterns = results.suspiciousPatterns || results.suspicious_patterns || [];
  const embeddedObjects = results.embeddedObjects || results.embedded_objects || [];
  const externalReferences = results.externalReferences || results.external_references || results.external_links || [];
  const urls = results.urls || [];
  const httpRequests = results.httpRequests || results.http_requests || [];
  const processTriggers = results.processTriggers || results.process_triggers || [];
  const downloadTargets = results.downloadTargets || results.download_targets || [];
  const riskScore = results.riskScore ?? results.risk_score ?? 0;
  const riskLevel = results.riskLevel ?? results.risk_level ?? 'Low';

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
      <Card title="Document Details" icon={<FileSpreadsheet className="h-5 w-5" />}>
        <div className="space-y-3">
          {results.filename && (
            <InfoRow label="Filename" value={results.filename} />
          )}
          <InfoRow label="File Type" value={results.type || 'Office Document'} />
        </div>
      </Card>

      {/* Macro Analysis */}
      <Card
        title="Macro Analysis"
        icon={<Code className="h-5 w-5" />}
        className={hasMacros ? 'border-warning/30' : ''}
      >
        <div className="space-y-4">
          <div className="flex items-center justify-between p-3 bg-background-darker/50 rounded-lg">
            <span className="text-gray-400 text-sm">Contains Macros</span>
            <Badge variant={hasMacros ? 'warning' : 'safe'}>
              {hasMacros ? 'Yes' : 'No'}
            </Badge>
          </div>

          {hasMacros && (
            <>
              {/* Auto-execution triggers */}
              {autoExecution.length > 0 && (
                <div className="space-y-2">
                  <span className="text-gray-400 text-sm">Auto-Execution Triggers</span>
                  <div className="space-y-1">
                    {autoExecution.map((trigger: any, index: number) => (
                      <div
                        key={index}
                        className="flex items-center gap-2 p-2 bg-danger/10 rounded-lg text-danger"
                      >
                        <AlertTriangle className="h-4 w-4 flex-shrink-0" />
                        <span className="text-sm">{trigger.trigger}</span>
                        {trigger.location && (
                          <span className="text-xs text-gray-500">in {trigger.location}</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Suspicious patterns */}
              {suspiciousPatterns.length > 0 && (
                <div className="space-y-2">
                  <span className="text-gray-400 text-sm">Suspicious Patterns</span>
                  <div className="space-y-1">
                    {suspiciousPatterns.map((pattern: any, index: number) => (
                      <div
                        key={index}
                        className="p-2 bg-danger/10 rounded-lg"
                      >
                        <div className="flex items-center gap-2 text-danger text-sm">
                          <Badge variant="danger">{pattern.type}</Badge>
                          <span>{pattern.keyword}</span>
                        </div>
                        {pattern.description && (
                          <p className="text-xs text-gray-400 mt-1">{pattern.description}</p>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Macros list */}
              {macros.length > 0 && (
                <div className="space-y-2">
                  <span className="text-gray-400 text-sm">Macro Modules ({macros.length})</span>
                  <div className="space-y-2">
                    {macros.map((macro: any, index: number) => (
                      <div key={index} className="p-3 bg-background-darker/50 rounded-lg">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-white text-sm font-medium">{macro.filename}</span>
                          <span className="text-gray-500 text-xs">{macro.codeLength} chars</span>
                        </div>
                        {macro.codePreview && (
                          <pre className="text-xs text-gray-400 overflow-x-auto max-h-32 whitespace-pre-wrap">
                            {macro.codePreview.substring(0, 500)}...
                          </pre>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </Card>

      {/* Process Triggers */}
      {processTriggers.length > 0 && (
        <Card
          title="Process Execution"
          icon={<Terminal className="h-5 w-5 text-danger" />}
          className="border-danger/30"
        >
          <div className="space-y-2">
            {processTriggers.map((trigger: any, index: number) => (
              <div
                key={index}
                className="p-3 bg-danger/10 rounded-lg"
              >
                <div className="flex items-center gap-2 text-danger text-sm">
                  <AlertTriangle className="h-4 w-4" />
                  <span className="font-medium">{trigger.type}</span>
                </div>
                {trigger.location && (
                  <p className="text-xs text-gray-400 mt-1">Found in: {trigger.location}</p>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* HTTP Requests */}
      {httpRequests.length > 0 && (
        <Card
          title="Network Requests"
          icon={<Globe className="h-5 w-5 text-warning" />}
          className="border-warning/30"
        >
          <div className="space-y-2">
            {httpRequests.map((req: any, index: number) => (
              <div
                key={index}
                className="p-2 bg-warning/10 rounded-lg"
              >
                <div className="text-warning text-sm">{req.pattern}</div>
                {req.location && (
                  <p className="text-xs text-gray-400">in {req.location}</p>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Download Targets */}
      {downloadTargets.length > 0 && (
        <Card
          title="File Download Operations"
          icon={<Download className="h-5 w-5 text-warning" />}
        >
          <div className="space-y-2">
            {downloadTargets.map((target: any, index: number) => (
              <div
                key={index}
                className="p-2 bg-warning/10 rounded-lg"
              >
                <div className="text-warning text-sm">{target.pattern}</div>
                {target.location && (
                  <p className="text-xs text-gray-400">in {target.location}</p>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* External References */}
      {externalReferences.length > 0 && (
        <Card title="External References" icon={<Link className="h-5 w-5" />}>
          <div className="space-y-2 max-h-60 overflow-y-auto">
            {externalReferences.map((ref: any, index: number) => (
              <div
                key={index}
                className="flex items-center gap-2 p-2 bg-background-darker/50 rounded-lg"
              >
                <Link className="h-4 w-4 text-gray-400 flex-shrink-0" />
                <code className="text-primary text-xs break-all">{typeof ref === 'string' ? ref : ref.url || ref.reference}</code>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* URLs Found */}
      {urls.length > 0 && (
        <Card title={`URLs Extracted (${urls.length})`} icon={<Link className="h-5 w-5" />}>
          <div className="space-y-2 max-h-60 overflow-y-auto">
            {urls.map((url: string, index: number) => (
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

      {/* Embedded Objects */}
      {embeddedObjects.length > 0 && (
        <Card
          title="Embedded Objects"
          icon={<Package className="h-5 w-5" />}
          className="border-warning/30"
        >
          <div className="space-y-2">
            {embeddedObjects.map((obj: any, index: number) => (
              <div
                key={index}
                className="flex items-center gap-2 p-2 bg-warning/10 rounded-lg text-warning"
              >
                <AlertTriangle className="h-4 w-4 flex-shrink-0" />
                <span className="text-sm">{typeof obj === 'string' ? obj : obj.description || obj.type}</span>
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
}

const InfoRow = ({ label, value }: InfoRowProps) => (
  <div className="flex items-start justify-between gap-4">
    <span className="text-gray-400 text-sm">{label}</span>
    <span className="text-white text-sm text-right">{value}</span>
  </div>
);
