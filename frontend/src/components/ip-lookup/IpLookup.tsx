import { useEffect } from 'react';
import { AlertCircle } from 'lucide-react';
import { SearchBox } from './SearchBox';
import { IpResults } from './IpResults';
import { Card } from '../common/Card';
import { LoadingOverlay } from '../common/Spinner';
import { useVisitorIp } from '../../hooks/useVisitorIp';
import { useIpLookup } from '../../hooks/useIpLookup';

export const IpLookup = () => {
  const { ip: visitorIp } = useVisitorIp();
  const { result, threatInfo, threatIntel, loading, error, lookup } = useIpLookup();

  // Auto-lookup visitor IP on mount
  useEffect(() => {
    lookup();
  }, [lookup]);

  return (
    <div className="space-y-6">
      <Card>
        <SearchBox
          visitorIp={visitorIp}
          loading={loading}
          onSearch={lookup}
        />
      </Card>

      {loading && <LoadingOverlay message="Looking up IP address..." />}

      {error && (
        <div className="flex items-center gap-3 p-4 bg-red-500/20 border border-red-500/40 rounded-xl text-red-400">
          <AlertCircle className="h-5 w-5 flex-shrink-0" />
          <p>{error}</p>
        </div>
      )}

      {!loading && result && threatInfo && (
        <IpResults result={result} threatInfo={threatInfo} threatIntel={threatIntel} />
      )}
    </div>
  );
};
