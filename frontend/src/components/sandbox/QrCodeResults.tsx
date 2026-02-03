import { QrCode, Link, AlertTriangle, CheckCircle, Globe } from 'lucide-react';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';
import type { QrCodeResults as QrCodeResultsType } from '../../types';

interface QrCodeResultsProps {
  results: QrCodeResultsType;
}

export const QrCodeResults = ({ results }: QrCodeResultsProps) => {
  const qrCodes = results.qr_codes || results.qrCodes || [];
  const totalCodes = results.total_codes || results.totalCodes || qrCodes.length;

  const suspiciousCodes = qrCodes.filter(
    (qr) => qr.risk_indicators && qr.risk_indicators.length > 0
  );

  const hasUrls = qrCodes.filter((qr) => qr.urls && qr.urls.length > 0).length;

  return (
    <div className="space-y-6 animate-slide-up">
      {/* Summary */}
      <Card title="QR Code Analysis" icon={<QrCode className="h-5 w-5" />}>
        <div className="grid sm:grid-cols-3 gap-4">
          <div className="p-4 bg-black/40 rounded-lg text-center">
            <p className="text-3xl font-bold text-primary">{totalCodes}</p>
            <p className="text-gray-400 text-sm">QR Codes Found</p>
          </div>
          <div className="p-4 bg-black/40 rounded-lg text-center">
            <p className="text-3xl font-bold text-success">
              {hasUrls}
            </p>
            <p className="text-gray-400 text-sm">Contains URLs</p>
          </div>
          <div className="p-4 bg-black/40 rounded-lg text-center">
            <p className={`text-3xl font-bold ${suspiciousCodes.length > 0 ? 'text-red-400' : 'text-success'}`}>
              {suspiciousCodes.length}
            </p>
            <p className="text-gray-400 text-sm">Suspicious</p>
          </div>
        </div>
      </Card>

      {/* Individual QR Codes */}
      {qrCodes.map((qr, index) => {
        const hasSuspicious = qr.risk_indicators && qr.risk_indicators.length > 0;
        const hasUrl = qr.urls && qr.urls.length > 0;

        return (
          <Card
            key={index}
            title={`QR Code ${index + 1}`}
            icon={hasSuspicious ? (
              <AlertTriangle className="h-5 w-5 text-red-400" />
            ) : (
              <CheckCircle className="h-5 w-5 text-success" />
            )}
            className={hasSuspicious ? 'border-red-500/30' : ''}
          >
            <div className="space-y-4">
              {/* Data Type */}
              <div className="flex items-center justify-between">
                <span className="text-gray-400 text-sm">Type</span>
                <Badge variant={hasUrl ? 'info' : 'neutral'}>
                  {qr.data_type || qr.type || 'Text'}
                </Badge>
              </div>

              {/* Content */}
              <div className="space-y-2">
                <span className="text-gray-400 text-sm">Content</span>
                <div className="p-3 bg-black/60 rounded-lg">
                  {hasUrl ? (
                    <div className="flex items-center gap-2">
                      <Link className="h-4 w-4 text-primary flex-shrink-0" />
                      <code className="text-primary text-sm break-all">{qr.raw_data || qr.data}</code>
                    </div>
                  ) : (
                    <code className="text-white text-sm break-all">{qr.raw_data || qr.data}</code>
                  )}
                </div>
              </div>

              {/* URLs found */}
              {qr.urls && qr.urls.length > 0 && (
                <div className="space-y-2">
                  <span className="text-gray-400 text-sm flex items-center gap-1.5">
                    <Globe className="h-4 w-4" />
                    URLs Found
                  </span>
                  <div className="space-y-1">
                    {qr.urls.map((url, idx) => (
                      <div key={idx} className="p-2 bg-black/40 rounded text-primary text-xs break-all">
                        {url}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Risk Indicators */}
              {qr.risk_indicators && qr.risk_indicators.length > 0 && (
                <div className="space-y-2">
                  <span className="text-gray-400 text-sm">Warning Reasons</span>
                  <div className="space-y-1">
                    {qr.risk_indicators.map((indicator, idx) => (
                      <div
                        key={idx}
                        className="flex items-center gap-2 p-2 bg-red-500/10 rounded-lg text-red-400 text-sm"
                      >
                        <AlertTriangle className="h-4 w-4 flex-shrink-0" />
                        {indicator.description}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Position Info */}
              {qr.rect && (
                <div className="flex items-center justify-between text-xs text-gray-500">
                  <span>Position</span>
                  <span className="font-mono">
                    x:{qr.rect.left} y:{qr.rect.top} ({qr.rect.width}×{qr.rect.height})
                  </span>
                </div>
              )}
            </div>
          </Card>
        );
      })}

      {/* No QR Codes Found */}
      {qrCodes.length === 0 && (
        <Card>
          <div className="text-center py-8">
            <QrCode className="h-12 w-12 text-gray-500 mx-auto mb-3" />
            <p className="text-gray-400">No QR codes detected in this image</p>
          </div>
        </Card>
      )}
    </div>
  );
};
