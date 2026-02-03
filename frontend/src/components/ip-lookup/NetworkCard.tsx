import { Network, Server, Globe } from 'lucide-react';
import { Card } from '../common/Card';
import type { IpLookupResult } from '../../types';

interface NetworkCardProps {
  data: IpLookupResult;
}

export const NetworkCard = ({ data }: NetworkCardProps) => {
  const network = data.network || {};

  return (
    <Card title="Network" icon={<Network className="h-5 w-5" />}>
      <div className="space-y-3">
        <InfoRow
          label="IP Address"
          value={data.ip}
          icon={<Globe className="h-4 w-4 text-gray-500" />}
          mono
        />
        {network.hostname && (
          <InfoRow
            label="Hostname"
            value={network.hostname}
            icon={<Server className="h-4 w-4 text-gray-500" />}
            mono
          />
        )}
        {network.isp && <InfoRow label="ISP" value={network.isp} />}
        {network.organization && <InfoRow label="Organization" value={network.organization} />}
        {network.asn && <InfoRow label="ASN" value={network.asn} mono />}
        {network.asName && <InfoRow label="AS Name" value={network.asName} />}
      </div>
    </Card>
  );
};

interface InfoRowProps {
  label: string;
  value: string;
  icon?: React.ReactNode;
  mono?: boolean;
}

const InfoRow = ({ label, value, icon, mono }: InfoRowProps) => (
  <div className="flex items-start justify-between gap-4">
    <span className="text-gray-400 text-sm flex items-center gap-1.5">
      {icon}
      {label}
    </span>
    <span className={`text-white text-sm text-right break-all ${mono ? 'font-mono text-xs' : ''}`}>
      {value}
    </span>
  </div>
);
