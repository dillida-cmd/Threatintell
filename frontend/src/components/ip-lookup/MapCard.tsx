import { Map } from 'lucide-react';
import { Card } from '../common/Card';

interface MapCardProps {
  latitude: number;
  longitude: number;
  city?: string;
  country?: string;
}

export const MapCard = ({ latitude, longitude, city, country }: MapCardProps) => {
  const locationLabel = [city, country].filter(Boolean).join(', ') || 'Unknown Location';
  const coordinates = `${latitude}, ${longitude}`;

  // Using OpenStreetMap static image
  const mapUrl = `https://www.openstreetmap.org/export/embed.html?bbox=${longitude - 0.1},${latitude - 0.1},${longitude + 0.1},${latitude + 0.1}&layer=mapnik&marker=${latitude},${longitude}`;

  return (
    <Card title="Map" icon={<Map className="h-5 w-5" />} className="col-span-full">
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-gray-400 text-sm">Location</span>
          <span className="text-white text-sm">{locationLabel}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-gray-400 text-sm">Coordinates</span>
          <span className="text-white text-sm font-mono">{coordinates}</span>
        </div>
        <div className="relative rounded-lg overflow-hidden h-64 bg-black border border-red-500/20">
          <iframe
            title="Location Map"
            src={mapUrl}
            className="w-full h-full border-0"
            loading="lazy"
          />
        </div>
        <a
          href={`https://www.openstreetmap.org/?mlat=${latitude}&mlon=${longitude}#map=12/${latitude}/${longitude}`}
          target="_blank"
          rel="noopener noreferrer"
          className="text-primary hover:underline text-sm inline-block"
        >
          Open in OpenStreetMap →
        </a>
      </div>
    </Card>
  );
};
