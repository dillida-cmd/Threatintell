import { useState, useCallback } from 'react';
import { lookupIp, investigateIp } from '../api/client';
import type { IpLookupResult, ThreatInfo, IpInvestigation } from '../types';

interface UseIpLookupResult {
  result: IpLookupResult | null;
  threatInfo: ThreatInfo | null;
  threatIntel: IpInvestigation | null;
  loading: boolean;
  error: string | null;
  lookup: (ip?: string) => Promise<void>;
  clear: () => void;
}

export const useIpLookup = (): UseIpLookupResult => {
  const [result, setResult] = useState<IpLookupResult | null>(null);
  const [threatInfo, setThreatInfo] = useState<ThreatInfo | null>(null);
  const [threatIntel, setThreatIntel] = useState<IpInvestigation | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const calculateThreatInfo = (data: IpLookupResult, intel: IpInvestigation | null): ThreatInfo => {
    const security = data.security || {};
    const threat = data.threat || {};

    // Use threat intel risk score if available
    let riskScore = intel?.summary?.riskScore ?? threat.abuseScore ?? 0;

    // If no intel score, calculate from basic data
    if (!intel?.summary?.riskScore) {
      if (security.isProxy) riskScore += 30;
      if (security.isHosting) riskScore += 15;
      if (security.isMobile) riskScore += 5;
      if (threat.totalReports && threat.totalReports > 0) {
        riskScore += Math.min(threat.totalReports * 5, 30);
      }
    }

    // Extract flags from threat intel sources
    const sources = intel?.sources || {};
    const abuseipdb = sources.abuseipdb || {};
    const ipqs = sources.ipqualityscore || {};

    riskScore = Math.min(riskScore, 100);

    return {
      is_threat: riskScore > 30 || intel?.summary?.isMalicious || (threat.totalReports || 0) > 0,
      is_vpn: ipqs.isVpn || false,
      is_proxy: ipqs.isProxy || security.isProxy || false,
      is_tor: abuseipdb.isTor || ipqs.isTor || false,
      is_hosting: security.isHosting || false,
      risk_score: riskScore,
    };
  };

  const lookup = useCallback(async (ip?: string) => {
    setLoading(true);
    setError(null);
    try {
      // Fetch basic IP info
      const data = await lookupIp(ip);
      setResult(data);

      // Fetch detailed threat intelligence
      let intel: IpInvestigation | null = null;
      try {
        intel = await investigateIp(ip || data.ip);
        setThreatIntel(intel);
      } catch (intelErr) {
        console.warn('Threat intel fetch failed:', intelErr);
        setThreatIntel(null);
      }

      setThreatInfo(calculateThreatInfo(data, intel));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Lookup failed');
      setResult(null);
      setThreatInfo(null);
      setThreatIntel(null);
    } finally {
      setLoading(false);
    }
  }, []);

  const clear = useCallback(() => {
    setResult(null);
    setThreatInfo(null);
    setThreatIntel(null);
    setError(null);
  }, []);

  return { result, threatInfo, threatIntel, loading, error, lookup, clear };
};
