import { Copy, Check, Key } from 'lucide-react';
import { Card } from '../common/Card';
import { useCopyToClipboard } from '../../hooks/useCopyToClipboard';

interface EntryRefCardProps {
  entryRef: string;
}

export const EntryRefCard = ({ entryRef }: EntryRefCardProps) => {
  const { copied, copy } = useCopyToClipboard();

  return (
    <Card
      title="Analysis Complete"
      icon={<Key className="h-5 w-5" />}
      className="bg-success/10 border-success/30"
    >
      <div className="space-y-3">
        <p className="text-gray-300 text-sm">
          Save this entry reference to retrieve your results later:
        </p>
        <div className="flex items-center gap-2">
          <code className="flex-1 bg-background-darker px-4 py-2 rounded-lg font-mono text-primary text-sm overflow-x-auto">
            {entryRef}
          </code>
          <button
            onClick={() => copy(entryRef)}
            className={`
              p-2 rounded-lg transition-colors
              ${copied ? 'bg-success text-white' : 'bg-white/10 text-gray-400 hover:bg-white/20'}
            `}
            title={copied ? 'Copied!' : 'Copy to clipboard'}
          >
            {copied ? <Check className="h-5 w-5" /> : <Copy className="h-5 w-5" />}
          </button>
        </div>
      </div>
    </Card>
  );
};
