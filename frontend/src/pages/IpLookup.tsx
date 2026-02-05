import { useState } from 'react'
import { Search, Globe, MapPin, Server, Shield, AlertTriangle, Wifi, Eye, Bot } from 'lucide-react'
import { lookupIp } from '../api/client'
import RiskGauge from '../components/RiskGauge'
import LoadingSpinner from '../components/LoadingSpinner'
import { defangIp, defangDomain } from '../utils/defang'

export default function IpLookup() {
  const [ip, setIp] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [results, setResults] = useState<any>(null)

  const handleLookup = async () => {
    if (!ip.trim()) return
    setLoading(true)
    setError(null)
    setResults(null)

    try {
      const data = await lookupIp(ip.trim())
      setResults(data)
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to lookup IP address')
    } finally {
      setLoading(false)
    }
  }

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleLookup()
  }

  const threat = results?.threat || {}
  const basic = results?.basic || {}
  const sources = threat.sources || {}
  const summary = threat.summary || {}
  const riskScore = summary.riskScore || 0

  return (
    <div className="space-y-6">
      {/* Search Card */}
      <div className="card">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 bg-primary-600/20 rounded-lg">
            <Globe className="h-6 w-6 text-primary-500" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">IP Address Lookup</h2>
            <p className="text-gray-400 text-sm">Analyze IP addresses for threat intelligence</p>
          </div>
        </div>

        <div className="flex gap-3">
          <input
            type="text"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Enter IP address (e.g., 8.8.8.8)"
            className="input flex-1"
          />
          <button
            onClick={handleLookup}
            disabled={loading || !ip.trim()}
            className="btn btn-primary"
          >
            <Search className="h-5 w-5" />
            <span>Investigate</span>
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="card card-danger">
          <div className="flex items-center gap-3 text-red-400">
            <AlertTriangle className="h-5 w-5" />
            <span>{error}</span>
          </div>
        </div>
      )}

      {/* Loading */}
      {loading && <LoadingSpinner message="Analyzing IP address..." />}

      {/* Results */}
      {results && !loading && (
        <div className="space-y-6">
          {/* Risk Score and Summary */}
          <div className="grid md:grid-cols-3 gap-6">
            {/* Risk Gauge */}
            <div className="card flex items-center justify-center">
              <RiskGauge score={riskScore} size="lg" />
            </div>

            {/* Quick Info */}
            <div className="card md:col-span-2">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Shield className="h-5 w-5 text-primary-500" />
                Threat Summary
              </h3>

              {/* Status Badges */}
              <div className="flex flex-wrap gap-2 mb-4">
                {summary.isMalicious ? (
                  <span className="badge badge-danger">MALICIOUS</span>
                ) : (
                  <span className="badge badge-success">CLEAN</span>
                )}
                {sources.abuseipdb?.totalReports > 0 && (
                  <span className="badge badge-warning">{sources.abuseipdb.totalReports} Abuse Reports</span>
                )}
                {sources.virustotal?.malicious > 0 && (
                  <span className="badge badge-danger">
                    {sources.virustotal.malicious}/{sources.virustotal.malicious + sources.virustotal.harmless + sources.virustotal.suspicious + (sources.virustotal.undetected || 0)} Detections
                  </span>
                )}
              </div>

              {/* AI Verdict */}
              {summary.verdict && (
                <div className={`p-4 rounded-lg mb-4 ${
                  summary.isMalicious
                    ? 'bg-red-500/10 border border-red-500/30'
                    : 'bg-green-500/10 border border-green-500/30'
                }`}>
                  <p className={`text-sm leading-relaxed ${
                    summary.isMalicious ? 'text-red-300' : 'text-green-300'
                  }`}>
                    {summary.verdict}
                  </p>
                </div>
              )}

              {/* Security Indicators */}
              <div className="grid grid-cols-3 md:grid-cols-6 gap-2">
                {[
                  { label: 'VPN', active: sources.ipqualityscore?.isVpn, icon: Shield },
                  { label: 'Proxy', active: sources.ipqualityscore?.isProxy, icon: Wifi },
                  { label: 'Tor', active: sources.ipqualityscore?.isTor || sources.abuseipdb?.isTor, icon: Eye },
                  { label: 'Bot', active: sources.ipqualityscore?.isBot, icon: Bot },
                  { label: 'Hosting', active: basic.security?.isHosting, icon: Server },
                  { label: 'Crawler', active: sources.ipqualityscore?.isCrawler, icon: Globe },
                ].map((item) => (
                  <div
                    key={item.label}
                    className={`flex items-center gap-2 p-2 rounded-lg text-xs font-medium ${
                      item.active
                        ? 'bg-red-900/30 text-red-400 border border-red-700/50'
                        : 'bg-dark-500 text-gray-500 border border-dark-300'
                    }`}
                  >
                    <item.icon className="h-3 w-3" />
                    {item.label}
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Location & Network */}
          <div className="grid md:grid-cols-2 gap-6">
            {/* Location */}
            {basic.location && (
              <div className="card">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <MapPin className="h-5 w-5 text-primary-500" />
                  Location
                </h3>
                <div className="space-y-3">
                  <InfoRow label="Country" value={`${basic.location.country || '-'} ${basic.location.countryCode || ''}`} />
                  <InfoRow label="City" value={basic.location.city} />
                  <InfoRow label="Region" value={basic.location.region} />
                  <InfoRow label="Timezone" value={basic.location.timezone} />
                </div>
              </div>
            )}

            {/* Network */}
            {basic.network && (
              <div className="card">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <Server className="h-5 w-5 text-primary-500" />
                  Network
                </h3>
                <div className="space-y-3">
                  <InfoRow label="ISP" value={basic.network.isp} />
                  <InfoRow label="ASN" value={basic.network.asn} />
                  <InfoRow label="Organization" value={basic.network.org} />
                  <InfoRow label="Domain" value={basic.domain} />
                </div>
              </div>
            )}
          </div>

          {/* Security Vendor Analysis */}
          {sources.virustotal && (
            <div className="card">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Shield className="h-5 w-5 text-primary-500" />
                Security Vendor Analysis
              </h3>
              <div className="grid grid-cols-4 gap-4 mb-4">
                <StatBox label="Malicious" value={sources.virustotal.malicious || 0} color="red" />
                <StatBox label="Suspicious" value={sources.virustotal.suspicious || 0} color="orange" />
                <StatBox label="Clean" value={sources.virustotal.harmless || 0} color="green" />
                <StatBox label="Undetected" value={sources.virustotal.undetected || 0} color="gray" />
              </div>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div className="p-3 bg-dark-500 rounded-lg">
                  <span className="text-gray-400">AS Owner:</span>
                  <span className="text-white ml-2">{sources.virustotal.asOwner || '-'}</span>
                </div>
                <div className="p-3 bg-dark-500 rounded-lg">
                  <span className="text-gray-400">Reputation:</span>
                  <span className="text-white ml-2">{sources.virustotal.reputation || 0}</span>
                </div>
              </div>
            </div>
          )}

          {/* Abuse & Fraud Scores */}
          {(sources.abuseipdb || sources.ipqualityscore) && (
            <div className="card">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-primary-500" />
                Abuse & Fraud Analysis
              </h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                {sources.abuseipdb && (
                  <>
                    <div className={`p-4 rounded-xl text-center ${sources.abuseipdb.abuseScore > 50 ? 'bg-red-500/20 text-red-400' : sources.abuseipdb.abuseScore > 20 ? 'bg-orange-500/20 text-orange-400' : 'bg-green-500/20 text-green-400'}`}>
                      <div className="text-3xl font-bold">{sources.abuseipdb.abuseScore || 0}%</div>
                      <div className="text-xs text-gray-400">Abuse Score</div>
                    </div>
                    <div className="p-4 rounded-xl bg-dark-500 text-center">
                      <div className="text-3xl font-bold text-white">{sources.abuseipdb.totalReports || 0}</div>
                      <div className="text-xs text-gray-400">Abuse Reports</div>
                    </div>
                  </>
                )}
                {sources.ipqualityscore && (
                  <>
                    <div className={`p-4 rounded-xl text-center ${sources.ipqualityscore.fraudScore > 75 ? 'bg-red-500/20' : sources.ipqualityscore.fraudScore > 50 ? 'bg-orange-500/20' : 'bg-green-500/20'}`}>
                      <div className={`text-3xl font-bold ${sources.ipqualityscore.fraudScore > 75 ? 'text-red-400' : sources.ipqualityscore.fraudScore > 50 ? 'text-orange-400' : 'text-green-400'}`}>
                        {sources.ipqualityscore.fraudScore || 0}
                      </div>
                      <div className="text-xs text-gray-400">Fraud Score</div>
                    </div>
                    <div className="p-4 rounded-xl bg-dark-500 text-center">
                      <div className="text-lg font-bold text-white">{sources.abuseipdb?.usageType || sources.ipqualityscore?.organization || '-'}</div>
                      <div className="text-xs text-gray-400">Usage Type</div>
                    </div>
                  </>
                )}
              </div>

              {sources.abuseipdb?.isWhitelisted && (
                <div className="p-2 bg-green-500/10 border border-green-500/30 rounded-lg text-green-400 text-sm mb-4">
                  ✓ Whitelisted IP
                </div>
              )}

              {sources.abuseipdb?.recentReports?.length > 0 && (
                <div>
                  <h4 className="text-gray-400 font-semibold text-sm mb-2">Recent Abuse Reports</h4>
                  <div className="space-y-2 max-h-40 overflow-y-auto">
                    {sources.abuseipdb.recentReports.slice(0, 5).map((report: any, i: number) => (
                      <div key={i} className="p-3 bg-dark-500 rounded-lg text-sm">
                        <div className="flex justify-between items-start">
                          <span className="text-gray-400 text-xs">{new Date(report.reportedAt).toLocaleDateString()}</span>
                        </div>
                        {report.comment && <p className="text-gray-300 mt-1">{report.comment}</p>}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Threat Intelligence */}
          {(sources.alienvault_otx || sources.threatfox) && (
            <div className={`card ${sources.threatfox?.found ? 'glow-red' : ''}`}>
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Globe className="h-5 w-5 text-primary-500" />
                Threat Intelligence
              </h3>

              {sources.threatfox?.found && (
                <div className="p-4 rounded-lg bg-red-500/20 text-red-400 mb-4">
                  <span className="font-semibold">Known Malware Threat</span>
                  {sources.threatfox.malwareFamily && (
                    <span className="ml-2">- {sources.threatfox.malwareFamily}</span>
                  )}
                </div>
              )}

              <div className="grid grid-cols-3 gap-4 mb-4">
                <div className="p-4 rounded-xl bg-dark-500 text-center">
                  <div className="text-3xl font-bold text-white">{sources.alienvault_otx?.pulseCount || 0}</div>
                  <div className="text-xs text-gray-400">Threat Pulses</div>
                </div>
                <div className="p-4 rounded-xl bg-dark-500 text-center">
                  <div className="text-3xl font-bold text-white">{sources.alienvault_otx?.reputation || 0}</div>
                  <div className="text-xs text-gray-400">Reputation</div>
                </div>
                <div className="p-4 rounded-xl bg-dark-500 text-center">
                  <div className="text-white font-medium text-sm">{sources.alienvault_otx?.asn || sources.virustotal?.asn || '-'}</div>
                  <div className="text-xs text-gray-400">ASN</div>
                </div>
              </div>

              {sources.alienvault_otx?.validation?.length > 0 && (
                <div className="space-y-2">
                  {sources.alienvault_otx.validation.map((v: any, i: number) => (
                    <div key={i} className={`p-2 rounded-lg text-sm ${v.source === 'whitelist' || v.source === 'false_positive' ? 'bg-green-500/10 text-green-400' : 'bg-yellow-500/10 text-yellow-400'}`}>
                      {v.message}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Infrastructure */}
          {sources.shodan && (
            <div className="card">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Server className="h-5 w-5 text-primary-500" />
                Infrastructure
              </h3>

              {sources.shodan.hostnames?.length > 0 && (
                <div className="mb-4">
                  <h4 className="text-gray-400 text-sm font-semibold mb-2">Hostnames <span className="text-xs text-gray-500 font-normal">(defanged)</span></h4>
                  <div className="flex flex-wrap gap-2">
                    {sources.shodan.hostnames.map((hostname: string, i: number) => (
                      <span key={i} className="badge badge-info select-all" title="Defanged hostname">{defangDomain(hostname)}</span>
                    ))}
                  </div>
                </div>
              )}

              {sources.shodan.ports?.length > 0 && (
                <div className="mb-4">
                  <h4 className="text-gray-400 text-sm font-semibold mb-2">Open Ports ({sources.shodan.ports.length})</h4>
                  <div className="flex flex-wrap gap-2">
                    {sources.shodan.ports.map((port: number) => (
                      <span key={port} className="badge badge-warning">{port}</span>
                    ))}
                  </div>
                </div>
              )}

              {sources.shodan.services?.length > 0 && (
                <div className="mb-4">
                  <h4 className="text-gray-400 text-sm font-semibold mb-2">Services</h4>
                  <div className="space-y-2">
                    {sources.shodan.services.map((svc: any, i: number) => (
                      <div key={i} className="flex items-center gap-3 p-2 bg-dark-500 rounded-lg text-sm">
                        <span className="badge badge-info">{svc.port}/{svc.transport}</span>
                        {svc.product && <span className="text-white">{svc.product} {svc.version || ''}</span>}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {sources.shodan.vulns?.length > 0 && (
                <div>
                  <h4 className="text-red-400 font-semibold mb-2">Vulnerabilities</h4>
                  <div className="flex flex-wrap gap-2">
                    {sources.shodan.vulns.map((vuln: string) => (
                      <span key={vuln} className="badge badge-danger">{vuln}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function InfoRow({ label, value }: { label: string; value: string | undefined }) {
  return (
    <div className="flex justify-between items-center py-2 border-b border-dark-300 last:border-0">
      <span className="text-gray-400 text-sm">{label}</span>
      <span className="text-white font-medium">{value || '-'}</span>
    </div>
  )
}

function StatBox({ label, value, color }: { label: string; value: number; color: string }) {
  const colors: Record<string, string> = {
    red: 'from-red-500/20 to-red-900/20 border-red-500/30 text-red-400',
    orange: 'from-orange-500/20 to-orange-900/20 border-orange-500/30 text-orange-400',
    green: 'from-green-500/20 to-green-900/20 border-green-500/30 text-green-400',
    gray: 'from-gray-500/20 to-gray-900/20 border-gray-500/30 text-gray-400',
  }

  return (
    <div className={`p-4 rounded-xl bg-gradient-to-br border text-center ${colors[color]}`}>
      <div className="text-3xl font-bold">{value}</div>
      <div className="text-xs text-gray-400 mt-1">{label}</div>
    </div>
  )
}
