import { LocationCard } from './LocationCard';
import { NetworkCard } from './NetworkCard';
import { ThreatCard } from './ThreatCard';
import { MapCard } from './MapCard';
import type { IpLookupResult, ThreatInfo, IpInvestigation } from '../../types';

interface IpResultsProps {
  result: IpLookupResult;
  threatInfo: ThreatInfo;
  threatIntel: IpInvestigation | null;
}

export const IpResults = ({ result, threatInfo, threatIntel }: IpResultsProps) => {
  const location = result.location || {};
  const hasCoordinates = location.latitude !== undefined && location.longitude !== undefined;

  return (
    <div className="space-y-6 animate-slide-up">
      {/* Threat Intelligence - Full Width */}
      <ThreatCard threatInfo={threatInfo} data={result} threatIntel={threatIntel} />

      {/* Info Cards Grid */}
      <div className="grid md:grid-cols-2 gap-6">
        <LocationCard data={result} />
        <NetworkCard data={result} />
      </div>

      {/* Map - Full Width */}
      {hasCoordinates && (
        <MapCard
          latitude={location.latitude!}
          longitude={location.longitude!}
          city={location.city}
          country={location.country}
        />
      )}
    </div>
  );
};
