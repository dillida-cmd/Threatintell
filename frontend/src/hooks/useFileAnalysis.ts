import { useState, useCallback } from 'react';
import { analyzeFile, retrieveResults } from '../api/client';
import type { FileType, AnalysisResults } from '../types';

interface UseFileAnalysisResult {
  entryRef: string | null;
  results: AnalysisResults | null;
  loading: boolean;
  error: string | null;
  analyze: (type: FileType, file: File, secretKey: string) => Promise<void>;
  retrieve: (entryRef: string, secretKey: string) => Promise<void>;
  clear: () => void;
}

export const useFileAnalysis = (): UseFileAnalysisResult => {
  const [entryRef, setEntryRef] = useState<string | null>(null);
  const [results, setResults] = useState<AnalysisResults | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const analyze = useCallback(async (type: FileType, file: File, secretKey: string) => {
    setLoading(true);
    setError(null);
    setResults(null);
    try {
      const response = await analyzeFile(type, file, secretKey);
      // Handle both camelCase and snake_case
      const ref = response.entryRef || response.entry_ref;
      if (response.success && ref) {
        setEntryRef(ref);
        // Automatically retrieve results after analysis
        const retrieveResponse = await retrieveResults(ref, secretKey);
        if (retrieveResponse.success && retrieveResponse.results) {
          // Merge top-level metadata into results for component access
          const mergedResults = {
            ...retrieveResponse.results,
            // Include metadata from response
            file_type: retrieveResponse.fileType || retrieveResponse.file_type || retrieveResponse.results.type,
            fileType: retrieveResponse.fileType || retrieveResponse.file_type || retrieveResponse.results.type,
            filename: retrieveResponse.filename || retrieveResponse.results.filename || file.name,
            fileName: retrieveResponse.filename || retrieveResponse.results.filename || file.name,
            file_size: retrieveResponse.fileSize || retrieveResponse.file_size || file.size,
            fileSize: retrieveResponse.fileSize || retrieveResponse.file_size || file.size,
            analyzed_at: retrieveResponse.analyzedAt || retrieveResponse.analyzed_at || new Date().toISOString(),
            analyzedAt: retrieveResponse.analyzedAt || retrieveResponse.analyzed_at || new Date().toISOString(),
          };
          setResults(mergedResults as AnalysisResults);
        }
      } else {
        throw new Error(response.error || 'Analysis failed');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
      setEntryRef(null);
    } finally {
      setLoading(false);
    }
  }, []);

  const retrieve = useCallback(async (ref: string, secretKey: string) => {
    setLoading(true);
    setError(null);
    try {
      const response = await retrieveResults(ref, secretKey);
      if (response.success && response.results) {
        setEntryRef(ref);
        // Merge top-level metadata into results for component access
        const mergedResults = {
          ...response.results,
          file_type: response.fileType || response.file_type || response.results.type,
          fileType: response.fileType || response.file_type || response.results.type,
          filename: response.filename || response.results.filename,
          fileName: response.filename || response.results.filename,
          file_size: response.fileSize || response.file_size,
          fileSize: response.fileSize || response.file_size,
          analyzed_at: response.analyzedAt || response.analyzed_at,
          analyzedAt: response.analyzedAt || response.analyzed_at,
        };
        setResults(mergedResults as AnalysisResults);
      } else {
        throw new Error(response.error || 'Failed to retrieve results');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Retrieval failed');
    } finally {
      setLoading(false);
    }
  }, []);

  const clear = useCallback(() => {
    setEntryRef(null);
    setResults(null);
    setError(null);
  }, []);

  return { entryRef, results, loading, error, analyze, retrieve, clear };
};
