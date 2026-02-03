import { MapPin, Building, Clock } from 'lucide-react';
import { Card } from '../common/Card';
import type { IpLookupResult } from '../../types';

interface LocationCardProps {
  data: IpLookupResult;
}

export const LocationCard = ({ data }: LocationCardProps) => {
  const location = data.location || {};
  const locationParts = [location.city, location.region, location.country]
    .filter(Boolean)
    .join(', ');

  return (
    <Card title="Location" icon={<MapPin className="h-5 w-5" />}>
      <div className="space-y-3">
        <InfoRow label="Address" value={locationParts || 'Unknown'} />
        {location.zipCode && <InfoRow label="Postal Code" value={location.zipCode} />}
        {location.timezone && (
          <InfoRow
            label="Timezone"
            value={location.timezone}
            icon={<Clock className="h-4 w-4 text-gray-500" />}
          />
        )}
        {location.latitude && location.longitude && (
          <InfoRow
            label="Coordinates"
            value={`${location.latitude}, ${location.longitude}`}
            mono
          />
        )}
        {data.network?.organization && (
          <InfoRow
            label="Organization"
            value={data.network.organization}
            icon={<Building className="h-4 w-4 text-gray-500" />}
          />
        )}
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
    <span className={`text-white text-sm text-right ${mono ? 'font-mono' : ''}`}>
      {value}
    </span>
  </div>
);
