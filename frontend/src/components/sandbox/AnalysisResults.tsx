import { EmailResults } from './EmailResults';
import { PdfResults } from './PdfResults';
import { OfficeResults } from './OfficeResults';
import { QrCodeResults } from './QrCodeResults';
import { IocInvestigationCard } from './IocInvestigationCard';
import { EntryRefCard } from './EntryRefCard';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';
import { FileText, Calendar } from 'lucide-react';
import { formatBytes, formatDate } from '../../utils/formatters';
import type {
  AnalysisResults as AnalysisResultsType,
  EmailResults as EmailResultsType,
  PdfResults as PdfResultsType,
  OfficeResults as OfficeResultsType,
  QrCodeResults as QrCodeResultsType
} from '../../types';

interface AnalysisResultsProps {
  results: AnalysisResultsType;
  entryRef: string;
}

export const AnalysisResults = ({ results, entryRef }: AnalysisResultsProps) => {
  const fileType = results.file_type || results.fileType || 'unknown';
  const filename = results.filename || results.fileName || 'Unknown file';
  const fileSize = results.file_size || results.fileSize || 0;
  const analyzedAt = results.analyzed_at || results.analyzedAt || new Date().toISOString();

  const renderTypeSpecificResults = () => {
    switch (fileType) {
      case 'email':
        return <EmailResults results={results as EmailResultsType} />;
      case 'pdf':
        return <PdfResults results={results as PdfResultsType} />;
      case 'office':
        return <OfficeResults results={results as OfficeResultsType} />;
      case 'qrcode':
        return <QrCodeResults results={results as QrCodeResultsType} />;
      default:
        return null;
    }
  };

  const fileTypeLabels: Record<string, string> = {
    email: 'Email',
    pdf: 'PDF Document',
    office: 'Office Document',
    qrcode: 'QR Code Image',
  };

  return (
    <div className="space-y-6">
      {/* Entry Reference Card */}
      <EntryRefCard entryRef={entryRef} />

      {/* File Info Summary */}
      <Card title="File Information" icon={<FileText className="h-5 w-5" />}>
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <InfoItem label="Filename" value={filename} />
          <InfoItem
            label="Type"
            value={
              <Badge variant="info">
                {fileTypeLabels[fileType] || fileType}
              </Badge>
            }
          />
          <InfoItem label="Size" value={formatBytes(fileSize)} />
          <InfoItem
            label="Analyzed"
            value={formatDate(analyzedAt)}
            icon={<Calendar className="h-4 w-4 text-gray-500" />}
          />
        </div>
      </Card>

      {/* Type-Specific Results */}
      {renderTypeSpecificResults()}

      {/* IOC Investigation Results */}
      {results.iocInvestigation && (
        <IocInvestigationCard investigation={results.iocInvestigation} />
      )}
    </div>
  );
};

interface InfoItemProps {
  label: string;
  value: React.ReactNode;
  icon?: React.ReactNode;
}

const InfoItem = ({ label, value, icon }: InfoItemProps) => (
  <div className="p-3 bg-black/40 rounded-lg">
    <p className="text-gray-400 text-xs mb-1 flex items-center gap-1">
      {icon}
      {label}
    </p>
    {typeof value === 'string' ? (
      <p className="text-white text-sm truncate" title={value}>
        {value}
      </p>
    ) : (
      value
    )}
  </div>
);
