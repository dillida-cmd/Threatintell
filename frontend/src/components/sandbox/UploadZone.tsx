import { useState, useCallback } from 'react';
import { Upload, File, X, Mail, FileText, Table, QrCode } from 'lucide-react';
import { Button } from '../common/Button';
import { Input } from '../common/Input';
import { validateFile, detectFileType, FILE_TYPE_CONFIG } from '../../utils/validators';
import { formatBytes } from '../../utils/formatters';
import type { FileType } from '../../types';

interface UploadZoneProps {
  onAnalyze: (type: FileType, file: File, secretKey: string) => void;
  loading: boolean;
}

const fileTypeIcons: Record<FileType, React.ReactNode> = {
  email: <Mail className="h-5 w-5" />,
  pdf: <FileText className="h-5 w-5" />,
  office: <Table className="h-5 w-5" />,
  qrcode: <QrCode className="h-5 w-5" />,
};

export const UploadZone = ({ onAnalyze, loading }: UploadZoneProps) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [selectedType, setSelectedType] = useState<FileType | null>(null);
  const [secretKey, setSecretKey] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  const handleFileSelect = useCallback((file: File) => {
    setError(null);
    const detectedType = detectFileType(file);

    if (!detectedType) {
      setError('Unsupported file type');
      return;
    }

    const validation = validateFile(file, detectedType);
    if (!validation.valid) {
      setError(validation.error || 'Invalid file');
      return;
    }

    setSelectedFile(file);
    setSelectedType(detectedType);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);

      const file = e.dataTransfer.files[0];
      if (file) {
        handleFileSelect(file);
      }
    },
    [handleFileSelect]
  );

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      handleFileSelect(file);
    }
  };

  const handleClear = () => {
    setSelectedFile(null);
    setSelectedType(null);
    setError(null);
  };

  const handleSubmit = () => {
    if (!selectedFile || !selectedType) return;
    onAnalyze(selectedType, selectedFile, secretKey);
  };

  return (
    <div className="space-y-4">
      {/* Drop Zone */}
      <div
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        className={`
          relative border-2 border-dashed rounded-xl p-8
          transition-all duration-200 cursor-pointer
          ${isDragging ? 'border-primary bg-red-500/10' : 'border-red-500/30 hover:border-red-500/50'}
          ${selectedFile ? 'bg-black/40' : ''}
        `}
      >
        <input
          type="file"
          onChange={handleInputChange}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
          accept={Object.values(FILE_TYPE_CONFIG)
            .flatMap((c) => c.extensions)
            .join(',')}
        />

        {selectedFile ? (
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-red-500/20 rounded-lg text-primary">
                {selectedType && fileTypeIcons[selectedType]}
              </div>
              <div>
                <p className="text-white font-medium">{selectedFile.name}</p>
                <p className="text-gray-400 text-sm">
                  {formatBytes(selectedFile.size)} • {selectedType && FILE_TYPE_CONFIG[selectedType].label}
                </p>
              </div>
            </div>
            <button
              onClick={(e) => {
                e.stopPropagation();
                handleClear();
              }}
              className="p-1 hover:bg-red-500/20 rounded-lg transition-colors"
            >
              <X className="h-5 w-5 text-gray-400" />
            </button>
          </div>
        ) : (
          <div className="text-center">
            <Upload className="h-10 w-10 text-red-400 mx-auto mb-3" />
            <p className="text-white mb-1">
              Drop a file here or <span className="text-primary">browse</span>
            </p>
            <p className="text-gray-500 text-sm">
              Supports: Email (.eml, .msg), PDF, Office docs, Images (QR codes)
            </p>
          </div>
        )}
      </div>

      {error && (
        <p className="text-red-400 text-sm">{error}</p>
      )}

      {/* File Type Selector */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {(Object.keys(FILE_TYPE_CONFIG) as FileType[]).map((type) => (
          <button
            key={type}
            onClick={() => setSelectedType(type)}
            className={`
              flex items-center justify-center gap-2 p-3 rounded-lg
              border transition-all duration-200
              ${
                selectedType === type
                  ? 'border-primary bg-red-500/20 text-primary'
                  : 'border-red-500/20 text-gray-400 hover:border-red-500/40 hover:text-white'
              }
            `}
          >
            {fileTypeIcons[type]}
            <span className="text-sm font-medium">{FILE_TYPE_CONFIG[type].label}</span>
          </button>
        ))}
      </div>

      {/* Secret Key Input */}
      <Input
        label="Secret Key (for retrieval)"
        type="password"
        placeholder="Enter a secret key to protect your results"
        value={secretKey}
        onChange={(e) => setSecretKey(e.target.value)}
      />

      {/* Submit Button */}
      <Button
        onClick={handleSubmit}
        disabled={!selectedFile || !selectedType}
        loading={loading}
        className="w-full"
        size="lg"
        icon={<File className="h-5 w-5" />}
      >
        Analyze File
      </Button>
    </div>
  );
};
