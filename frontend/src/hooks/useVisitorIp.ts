import { useState, useEffect } from 'react';
import { getVisitorIp } from '../api/client';

interface UseVisitorIpResult {
  ip: string | null;
  loading: boolean;
  error: string | null;
  refetch: () => void;
}

export const useVisitorIp = (): UseVisitorIpResult => {
  const [ip, setIp] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchIp = async () => {
    setLoading(true);
    setError(null);
    try {
      const visitorIp = await getVisitorIp();
      setIp(visitorIp);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to get IP');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIp();
  }, []);

  return { ip, loading, error, refetch: fetchIp };
};
