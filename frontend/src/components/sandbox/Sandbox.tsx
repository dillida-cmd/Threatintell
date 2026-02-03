import { useState } from 'react';
import { AlertCircle, Upload, Search } from 'lucide-react';
import { Card } from '../common/Card';
import { LoadingOverlay } from '../common/Spinner';
import { UploadZone } from './UploadZone';
import { RetrieveForm } from './RetrieveForm';
import { AnalysisResults } from './AnalysisResults';
import { useFileAnalysis } from '../../hooks/useFileAnalysis';

type SandboxMode = 'upload' | 'retrieve';

export const Sandbox = () => {
  const [mode, setMode] = useState<SandboxMode>('upload');
  const { entryRef, results, loading, error, analyze, retrieve, clear } = useFileAnalysis();

  const handleNewAnalysis = () => {
    clear();
    setMode('upload');
  };

  return (
    <div className="space-y-6">
      {/* Mode Selector */}
      {!results && (
        <div className="flex gap-2 mb-4">
          <button
            onClick={() => setMode('upload')}
            className={`
              flex items-center gap-2 px-4 py-2 rounded-lg
              font-medium text-sm transition-all duration-200
              ${
                mode === 'upload'
                  ? 'bg-red-500/20 text-primary border border-red-500/40'
                  : 'bg-black/40 text-gray-400 border border-red-500/20 hover:text-white'
              }
            `}
          >
            <Upload className="h-4 w-4" />
            Upload File
          </button>
          <button
            onClick={() => setMode('retrieve')}
            className={`
              flex items-center gap-2 px-4 py-2 rounded-lg
              font-medium text-sm transition-all duration-200
              ${
                mode === 'retrieve'
                  ? 'bg-red-500/20 text-primary border border-red-500/40'
                  : 'bg-black/40 text-gray-400 border border-red-500/20 hover:text-white'
              }
            `}
          >
            <Search className="h-4 w-4" />
            Retrieve Results
          </button>
        </div>
      )}

      {/* Upload or Retrieve Form */}
      {!results && !loading && (
        <Card>
          {mode === 'upload' ? (
            <UploadZone onAnalyze={analyze} loading={loading} />
          ) : (
            <RetrieveForm onRetrieve={retrieve} loading={loading} />
          )}
        </Card>
      )}

      {/* Loading State */}
      {loading && (
        <LoadingOverlay
          message={mode === 'upload' ? 'Analyzing file...' : 'Retrieving results...'}
        />
      )}

      {/* Error Display */}
      {error && (
        <div className="flex items-center gap-3 p-4 bg-red-500/20 border border-red-500/40 rounded-xl text-red-400">
          <AlertCircle className="h-5 w-5 flex-shrink-0" />
          <p>{error}</p>
        </div>
      )}

      {/* Results Display */}
      {results && entryRef && (
        <>
          <div className="flex justify-end">
            <button
              onClick={handleNewAnalysis}
              className="text-primary hover:underline text-sm"
            >
              ← Start New Analysis
            </button>
          </div>
          <AnalysisResults results={results} entryRef={entryRef} />
        </>
      )}
    </div>
  );
};
