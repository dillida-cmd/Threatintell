import { useState } from 'react';
import { Key, Search } from 'lucide-react';
import { Button } from '../common/Button';
import { Input } from '../common/Input';

interface RetrieveFormProps {
  onRetrieve: (entryRef: string, secretKey: string) => void;
  loading: boolean;
}

export const RetrieveForm = ({ onRetrieve, loading }: RetrieveFormProps) => {
  const [entryRef, setEntryRef] = useState('');
  const [secretKey, setSecretKey] = useState('');
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!entryRef.trim()) {
      setError('Please enter an entry reference');
      return;
    }

    onRetrieve(entryRef.trim(), secretKey);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <Input
        label="Entry Reference"
        type="text"
        placeholder="Enter your entry reference"
        value={entryRef}
        onChange={(e) => {
          setEntryRef(e.target.value);
          setError(null);
        }}
        icon={<Key className="h-4 w-4" />}
        error={error || undefined}
      />

      <Input
        label="Secret Key"
        type="password"
        placeholder="Enter your secret key"
        value={secretKey}
        onChange={(e) => setSecretKey(e.target.value)}
      />

      <Button
        type="submit"
        loading={loading}
        className="w-full"
        icon={<Search className="h-4 w-4" />}
      >
        Retrieve Results
      </Button>
    </form>
  );
};
