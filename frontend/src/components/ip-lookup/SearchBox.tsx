import { useState } from 'react';
import { Search, RefreshCw } from 'lucide-react';
import { Button } from '../common/Button';
import { Input } from '../common/Input';
import { isValidIpAddress } from '../../utils/validators';

interface SearchBoxProps {
  visitorIp: string | null;
  loading: boolean;
  onSearch: (ip?: string) => void;
}

export const SearchBox = ({ visitorIp, loading, onSearch }: SearchBoxProps) => {
  const [ipInput, setIpInput] = useState('');
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const ip = ipInput.trim();
    if (ip && !isValidIpAddress(ip)) {
      setError('Please enter a valid IP address');
      return;
    }

    onSearch(ip || undefined);
  };

  const handleLookupMyIp = () => {
    setIpInput('');
    setError(null);
    onSearch();
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="flex-1">
          <Input
            type="text"
            placeholder="Enter IP address (leave empty for your IP)"
            value={ipInput}
            onChange={(e) => {
              setIpInput(e.target.value);
              setError(null);
            }}
            icon={<Search className="h-4 w-4" />}
            error={error || undefined}
          />
        </div>
        <div className="flex gap-2">
          <Button type="submit" loading={loading}>
            Lookup
          </Button>
          <Button
            type="button"
            variant="secondary"
            onClick={handleLookupMyIp}
            disabled={loading}
            icon={<RefreshCw className="h-4 w-4" />}
          >
            My IP
          </Button>
        </div>
      </div>

      {visitorIp && (
        <p className="text-sm text-gray-500">
          Your IP: <span className="text-primary font-mono">{visitorIp}</span>
        </p>
      )}
    </form>
  );
};
