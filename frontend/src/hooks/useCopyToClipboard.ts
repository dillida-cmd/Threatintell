import { useState, useCallback } from 'react';

interface UseCopyToClipboardResult {
  copied: boolean;
  copy: (text: string) => Promise<void>;
}

export const useCopyToClipboard = (timeout = 2000): UseCopyToClipboardResult => {
  const [copied, setCopied] = useState(false);

  const copy = useCallback(async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), timeout);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  }, [timeout]);

  return { copied, copy };
};
