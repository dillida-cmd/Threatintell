import { useState, lazy, Suspense } from 'react'
import { Search, Link, Shield, AlertTriangle, Camera, ExternalLink, Globe, X, ZoomIn, Server, Mail, Clock, CheckCircle, XCircle, Database, ShieldCheck, ShieldX } from 'lucide-react'
import { lookupUrl } from '../api/client'
import RiskGauge from '../components/RiskGauge'
import LoadingSpinner from '../components/LoadingSpinner'
import AIValidation from '../components/AIValidation'
import { defangUrl, defangIp, defangDomain } from '../utils/defang'

// Lazy load the attack flow diagram
const AttackFlowDiagram = lazy(() => import('../components/AttackFlowDiagram'))

// Screenshot zoom modal component
function ScreenshotModal({ src, alt, onClose }: { src: string; alt: string; onClose: () => void }) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/90 p-4"
      onClick={onClose}
    >
      <button
        className="absolute top-4 right-4 p-2 bg-dark-500 rounded-full text-white hover:bg-dark-400 transition-colors"
        onClick={onClose}
      >
        <X className="h-6 w-6" />
      </button>
      <img
        src={src}
        alt={alt}
        className="max-w-full max-h-[90vh] object-contain rounded-lg"
        onClick={(e) => e.stopPropagation()}
      />
    </div>
  )
}

// Clickable screenshot thumbnail
function ScreenshotThumbnail({ src, alt }: { src: string; alt: string }) {
  const [zoomed, setZoomed] = useState(false)

  return (
    <>
      <div
        className="relative cursor-pointer group"
        onClick={() => setZoomed(true)}
      >
        <div className="absolute inset-0 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity bg-black/50 rounded-lg z-10">
          <ZoomIn className="h-8 w-8 text-white" />
        </div>
        <img
          src={src}
          alt={alt}
          className="w-full max-h-80 object-contain rounded-lg border border-dark-300 transition-transform group-hover:scale-[1.01]"
        />
      </div>
      {zoomed && (
        <ScreenshotModal src={src} alt={alt} onClose={() => setZoomed(false)} />
      )}
    </>
  )
}

export default function UrlLookup() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [threatResults, setThreatResults] = useState<any>(null)
  const [analysisResults, setAnalysisResults] = useState<any>(null)
  const [threatError, setThreatError] = useState<string | null>(null)
  const [analysisError, setAnalysisError] = useState<string | null>(null)

  const handleLookup = async () => {
    if (!url.trim()) return
    setLoading(true)
    setError(null)
    setThreatResults(null)
    setAnalysisResults(null)
    setThreatError(null)
    setAnalysisError(null)

    try {
      const data = await lookupUrl(url.trim())
      setThreatResults(data.threat)
      setAnalysisResults(data.analysis)
      if (data.threatError) setThreatError(data.threatError)
      if (data.analysisError) setAnalysisError(data.analysisError)
      // If both failed, show a general error
      if (!data.threat && !data.analysis) {
        setError('Both threat intel and URL analysis failed. Please try again.')
      }
    } catch (err: any) {
      setError(err.message || 'Failed to investigate URL')
    } finally {
      setLoading(false)
    }
  }

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleLookup()
  }

  const hasResults = threatResults || analysisResults

  // Compute combined risk score (use highest from either source)
  const threatScore = threatResults?.aiValidation?.validatedScore ?? threatResults?.summary?.riskScore ?? null
  const analysisScore = analysisResults?.analysis?.riskScore ?? analysisResults?.riskScore ?? null
  const combinedScore = threatScore !== null && analysisScore !== null
    ? Math.max(threatScore, analysisScore)
    : threatScore ?? analysisScore ?? 0

  return (
    <div className="space-y-6">
      {/* Header Card */}
      <div className="card">
        <div className="flex items-center gap-3 mb-6">
          <div className="p-2 bg-primary-600/20 rounded-lg">
            <Link className="h-6 w-6 text-primary-500" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">URL Lookup</h2>
            <p className="text-gray-400 text-sm">Investigate URLs with threat intel, screenshots, and IOC extraction</p>
          </div>
        </div>

        {/* Input */}
        <div className="flex gap-3">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Enter URL (e.g., https://example.com)"
            className="input flex-1"
          />
          <button
            onClick={handleLookup}
            disabled={loading || !url.trim()}
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
      {loading && (
        <LoadingSpinner message="Investigating URL..." />
      )}

      {/* Combined Results */}
      {hasResults && !loading && (
        <>
          {/* Combined Risk Score Header */}
          <div className="grid md:grid-cols-3 gap-6">
            <div className="card flex items-center justify-center">
              <RiskGauge score={combinedScore} size="lg" />
            </div>
            <div className="card md:col-span-2">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Shield className="h-5 w-5 text-primary-500" />
                URL Investigation
              </h3>
              <code className="block p-3 bg-dark-500 rounded-lg text-orange-400 text-sm break-all mb-4 select-all" title="Defanged URL - safe to copy">
                {defangUrl(url)}
              </code>
              <div className="flex flex-wrap gap-2">
                {threatScore !== null && (
                  <span className="badge badge-info">Threat Score: {threatScore}</span>
                )}
                {analysisScore !== null && (
                  <span className="badge badge-info">Analysis Score: {analysisScore}</span>
                )}
                {threatResults?.summary?.isMalicious && (
                  <span className="badge badge-danger">MALICIOUS</span>
                )}
                {threatResults?.sources?.virustotal?.malicious > 0 && (
                  <span className="badge badge-warning">{threatResults.sources.virustotal.malicious} Detection{threatResults.sources.virustotal.malicious > 1 ? 's' : ''}</span>
                )}
                {threatResults?.sources?.urlhaus?.threat && (
                  <span className="badge badge-danger">{threatResults.sources.urlhaus.threat}</span>
                )}
              </div>
            </div>
          </div>

          {/* Partial failure warnings */}
          {threatError && (
            <div className="card border border-yellow-500/30 bg-yellow-500/5">
              <div className="flex items-center gap-3 text-yellow-400">
                <AlertTriangle className="h-5 w-5" />
                <span>Threat intel lookup failed: {threatError}</span>
              </div>
            </div>
          )}
          {analysisError && (
            <div className="card border border-yellow-500/30 bg-yellow-500/5">
              <div className="flex items-center gap-3 text-yellow-400">
                <AlertTriangle className="h-5 w-5" />
                <span>URL analysis failed: {analysisError}</span>
              </div>
            </div>
          )}

          {/* Threat Intel Results (without its own risk header) */}
          {threatResults && <ThreatResultsBody results={threatResults} />}

          {/* Analysis Results (without its own risk header) */}
          {analysisResults && <AnalysisResultsBody results={analysisResults} />}

          {/* Attack Flow Diagram - render once from whichever source has it */}
          {(threatResults?.attackFlow || analysisResults?.attackFlow || analysisResults?.analysis?.finalUrl) && (
            <Suspense fallback={<div className="card"><LoadingSpinner message="Loading flow diagram..." /></div>}>
              <AttackFlowDiagram
                attackFlow={threatResults?.attackFlow || analysisResults?.attackFlow}
                analysis={analysisResults?.analysis || analysisResults}
              />
            </Suspense>
          )}
        </>
      )}
    </div>
  )
}

// Body-only variant for combined view (no risk score header)
function ThreatResultsBody({ results }: { results: any }) {
  const summary = results.summary || {}
  const sources = results.sources || {}
  const aiValidation = results.aiValidation || {}
  const hasAiValidation = results.aiValidation && typeof aiValidation.validatedScore === 'number'
  const isMalicious = hasAiValidation ? aiValidation.validatedMalicious : summary.isMalicious
  const recommendation = hasAiValidation ? aiValidation.recommendation : null

  return (
    <div className="space-y-6">
      {/* AI Recommendation / Verdict */}
      {(recommendation || summary.verdict) && (
        <div className={`card ${
          isMalicious
            ? 'bg-red-500/10 border border-red-500/30'
            : 'bg-green-500/10 border border-green-500/30'
        }`}>
          <p className={`text-sm leading-relaxed ${
            isMalicious ? 'text-red-300' : 'text-green-300'
          }`}>
            {recommendation || summary.verdict}
          </p>
        </div>
      )}

      {/* AI Risk Validation Details */}
      {results.aiValidation && (
        <AIValidation validation={results.aiValidation} />
      )}

      {/* VirusTotal */}
      {sources.virustotal && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-4">Security Vendor Analysis</h3>
          <div className="grid grid-cols-4 gap-4">
            <StatBox label="Malicious" value={sources.virustotal.malicious || 0} color="red" />
            <StatBox label="Suspicious" value={sources.virustotal.suspicious || 0} color="orange" />
            <StatBox label="Clean" value={sources.virustotal.harmless || 0} color="green" />
            <StatBox label="Undetected" value={sources.virustotal.undetected || 0} color="gray" />
          </div>

          {sources.virustotal.categories && Object.keys(sources.virustotal.categories).length > 0 && (
            <div className="mt-4">
              <h4 className="text-gray-400 text-sm font-semibold mb-2">Categories</h4>
              <div className="flex flex-wrap gap-2">
                {Object.values(sources.virustotal.categories).map((cat: any, i) => (
                  <span key={i} className="badge badge-info">{String(cat)}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Malware Database Check */}
      {sources.urlhaus && (sources.urlhaus.found || sources.urlhaus.threat) && (
        <div className="card glow-red">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2 text-red-400">
            <AlertTriangle className="h-5 w-5" />
            Known Malicious URL
          </h3>
          <div className="grid md:grid-cols-3 gap-4">
            <div>
              <span className="text-gray-400 text-xs">Threat Type</span>
              <p className="text-red-400 font-semibold">{sources.urlhaus.threat || 'Malware'}</p>
            </div>
            {sources.urlhaus.urlStatus && (
              <div>
                <span className="text-gray-400 text-xs">Status</span>
                <p className="text-white font-semibold">{sources.urlhaus.urlStatus}</p>
              </div>
            )}
          </div>
          {sources.urlhaus.tags?.length > 0 && (
            <div className="mt-4 flex flex-wrap gap-2">
              {sources.urlhaus.tags.map((tag: string, i: number) => (
                <span key={i} className="badge badge-danger">{tag}</span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Threat Intelligence */}
      {sources.alienvault_otx && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Globe className="h-5 w-5 text-primary-500" />
            Threat Intelligence
          </h3>

          <div className="grid grid-cols-2 gap-4 mb-4">
            <div className={`p-4 rounded-xl text-center ${sources.alienvault_otx.pulseCount > 10 ? 'bg-orange-500/20' : 'bg-dark-500'}`}>
              <div className={`text-3xl font-bold ${sources.alienvault_otx.pulseCount > 10 ? 'text-orange-400' : 'text-white'}`}>
                {sources.alienvault_otx.pulseCount || 0}
              </div>
              <div className="text-xs text-gray-400">Threat Reports</div>
            </div>
            <div className="p-4 rounded-xl bg-dark-500 text-center">
              <div className="text-white font-medium">{sources.alienvault_otx.domain || '-'}</div>
              <div className="text-xs text-gray-400">Domain</div>
            </div>
          </div>

          {sources.alienvault_otx.validation?.length > 0 && (
            <div className="mb-4 space-y-2">
              {sources.alienvault_otx.validation.map((v: any, i: number) => (
                <div key={i} className={`p-2 rounded-lg text-sm ${v.source === 'whitelist' || v.source === 'akamai' || v.source === 'majestic' ? 'bg-green-500/10 text-green-400' : 'bg-yellow-500/10 text-yellow-400'}`}>
                  {v.message}
                </div>
              ))}
            </div>
          )}

          {sources.alienvault_otx.pulses?.length > 0 && (
            <div>
              <h4 className="text-orange-400 text-sm font-semibold mb-2">Related Threat Reports</h4>
              <div className="space-y-2 max-h-60 overflow-y-auto">
                {sources.alienvault_otx.pulses.slice(0, 5).map((pulse: any, i: number) => (
                  <div key={i} className="p-3 bg-dark-500 rounded-lg">
                    <div className="text-white font-medium text-sm">{pulse.name}</div>
                    <div className="text-gray-400 text-xs mt-1 line-clamp-2">{pulse.description}</div>
                    {pulse.tags?.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-2">
                        {pulse.tags.slice(0, 5).map((tag: string, j: number) => (
                          <span key={j} className="badge badge-warning text-xs">{tag}</span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* DNS Intelligence */}
      {results.dns && !results.dns.error && results.dns.records && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Server className="h-5 w-5 text-primary-500" />
            DNS Intelligence
          </h3>

          {/* DNS Records */}
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
            {/* A Records */}
            {results.dns.records?.A?.length > 0 && (
              <div className="p-3 bg-dark-500 rounded-lg">
                <h4 className="text-cyan-400 text-sm font-semibold mb-2">A Records (IPv4)</h4>
                <div className="space-y-1">
                  {results.dns.records.A.map((ip: string, i: number) => (
                    <code key={i} className="block text-xs text-gray-300">{defangIp(ip)}</code>
                  ))}
                </div>
              </div>
            )}

            {/* AAAA Records */}
            {results.dns.records?.AAAA?.length > 0 && (
              <div className="p-3 bg-dark-500 rounded-lg">
                <h4 className="text-cyan-400 text-sm font-semibold mb-2">AAAA Records (IPv6)</h4>
                <div className="space-y-1">
                  {results.dns.records.AAAA.map((ip: string, i: number) => (
                    <code key={i} className="block text-xs text-gray-300 break-all">{defangIp(ip)}</code>
                  ))}
                </div>
              </div>
            )}

            {/* MX Records */}
            {results.dns.records?.MX?.length > 0 && (
              <div className="p-3 bg-dark-500 rounded-lg">
                <h4 className="text-purple-400 text-sm font-semibold mb-2 flex items-center gap-1">
                  <Mail className="h-3 w-3" /> MX Records
                </h4>
                <div className="space-y-1">
                  {results.dns.records.MX.map((mx: any, i: number) => (
                    <div key={i} className="text-xs">
                      <span className="text-gray-500">[{mx.priority}]</span>{' '}
                      <code className="text-gray-300">{defangDomain(mx.host)}</code>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* NS Records */}
            {results.dns.records?.NS?.length > 0 && (
              <div className="p-3 bg-dark-500 rounded-lg">
                <h4 className="text-blue-400 text-sm font-semibold mb-2">Name Servers</h4>
                <div className="space-y-1">
                  {results.dns.records.NS.map((ns: string, i: number) => (
                    <code key={i} className="block text-xs text-gray-300">{defangDomain(ns)}</code>
                  ))}
                </div>
              </div>
            )}

            {/* TXT Records */}
            {results.dns.records?.TXT?.length > 0 && (
              <div className="p-3 bg-dark-500 rounded-lg md:col-span-2">
                <h4 className="text-yellow-400 text-sm font-semibold mb-2">TXT Records</h4>
                <div className="space-y-1 max-h-32 overflow-y-auto">
                  {results.dns.records.TXT.map((txt: string, i: number) => (
                    <code key={i} className="block text-xs text-gray-300 break-all">{txt}</code>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Email Security Section */}
          {results.dns.emailSecurity && (
            <div className="border-t border-dark-300 pt-4">
              <h4 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-green-500" />
                Email Security
              </h4>

              <div className="grid md:grid-cols-3 gap-4">
                {/* SPF */}
                <div className={`p-3 rounded-lg ${results.dns.emailSecurity.spf?.valid ? 'bg-green-500/10 border border-green-500/30' : 'bg-red-500/10 border border-red-500/30'}`}>
                  <div className="flex items-center gap-2 mb-2">
                    {results.dns.emailSecurity.spf?.valid ? (
                      <CheckCircle className="h-4 w-4 text-green-500" />
                    ) : (
                      <XCircle className="h-4 w-4 text-red-500" />
                    )}
                    <h5 className="font-semibold text-sm">SPF Record</h5>
                  </div>
                  {results.dns.emailSecurity.spf?.valid ? (
                    <div className="text-xs">
                      <div className="text-gray-400 mb-1">Policy: <span className={`font-medium ${results.dns.emailSecurity.spf.details?.all === 'fail' ? 'text-green-400' : results.dns.emailSecurity.spf.details?.all === 'softfail' ? 'text-yellow-400' : 'text-red-400'}`}>
                        {results.dns.emailSecurity.spf.details?.all || 'unknown'}
                      </span></div>
                      {results.dns.emailSecurity.spf.details?.includes?.length > 0 && (
                        <div className="text-gray-500">Includes: {results.dns.emailSecurity.spf.details.includes.slice(0, 3).join(', ')}</div>
                      )}
                    </div>
                  ) : (
                    <p className="text-xs text-red-400">No SPF record found</p>
                  )}
                </div>

                {/* DMARC */}
                <div className={`p-3 rounded-lg ${results.dns.emailSecurity.dmarc?.valid ? 'bg-green-500/10 border border-green-500/30' : 'bg-red-500/10 border border-red-500/30'}`}>
                  <div className="flex items-center gap-2 mb-2">
                    {results.dns.emailSecurity.dmarc?.valid ? (
                      <CheckCircle className="h-4 w-4 text-green-500" />
                    ) : (
                      <XCircle className="h-4 w-4 text-red-500" />
                    )}
                    <h5 className="font-semibold text-sm">DMARC Record</h5>
                  </div>
                  {results.dns.emailSecurity.dmarc?.valid ? (
                    <div className="text-xs">
                      <div className="text-gray-400 mb-1">Policy: <span className={`font-medium ${results.dns.emailSecurity.dmarc.details?.policy === 'reject' ? 'text-green-400' : results.dns.emailSecurity.dmarc.details?.policy === 'quarantine' ? 'text-yellow-400' : 'text-red-400'}`}>
                        {results.dns.emailSecurity.dmarc.details?.policy || 'none'}
                      </span></div>
                      {results.dns.emailSecurity.dmarc.details?.rua && (
                        <div className="text-gray-500 truncate">Reports: {results.dns.emailSecurity.dmarc.details.rua}</div>
                      )}
                    </div>
                  ) : (
                    <p className="text-xs text-red-400">No DMARC record found</p>
                  )}
                </div>

                {/* DKIM */}
                <div className={`p-3 rounded-lg ${Array.isArray(results.dns.emailSecurity.dkim) && results.dns.emailSecurity.dkim.length > 0 ? 'bg-green-500/10 border border-green-500/30' : 'bg-yellow-500/10 border border-yellow-500/30'}`}>
                  <div className="flex items-center gap-2 mb-2">
                    {Array.isArray(results.dns.emailSecurity.dkim) && results.dns.emailSecurity.dkim.length > 0 ? (
                      <CheckCircle className="h-4 w-4 text-green-500" />
                    ) : (
                      <AlertTriangle className="h-4 w-4 text-yellow-500" />
                    )}
                    <h5 className="font-semibold text-sm">DKIM Records</h5>
                  </div>
                  {Array.isArray(results.dns.emailSecurity.dkim) && results.dns.emailSecurity.dkim.length > 0 ? (
                    <div className="text-xs">
                      <div className="text-gray-400">Found {results.dns.emailSecurity.dkim.length} selector(s):</div>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {results.dns.emailSecurity.dkim.map((d: any, i: number) => (
                          <span key={i} className="badge badge-success text-xs">{d.selector}</span>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <p className="text-xs text-yellow-400">No common DKIM selectors found</p>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Blocklist Status */}
          {results.dns.blocklists?.length > 0 && (
            <div className="border-t border-dark-300 pt-4 mt-4">
              <h4 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Database className="h-5 w-5 text-orange-500" />
                Blocklist Status
              </h4>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                {results.dns.blocklists.map((bl: any, i: number) => (
                  <div key={i} className={`p-2 rounded-lg flex items-center gap-2 ${bl.listed ? 'bg-red-500/20 border border-red-500/30' : 'bg-green-500/10 border border-green-500/30'}`}>
                    {bl.listed ? (
                      <ShieldX className="h-4 w-4 text-red-500 flex-shrink-0" />
                    ) : (
                      <ShieldCheck className="h-4 w-4 text-green-500 flex-shrink-0" />
                    )}
                    <span className={`text-xs ${bl.listed ? 'text-red-400' : 'text-green-400'}`}>{bl.blocklist}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* WHOIS Information */}
      {results.whois && !results.whois.error && (results.whois.registrar || results.whois.domainAge || results.whois.creationDate) && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Globe className="h-5 w-5 text-primary-500" />
            Domain WHOIS
          </h3>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4">
            {results.whois.registrar && (
              <div className="p-3 bg-dark-500 rounded-lg">
                <div className="text-gray-400 text-xs mb-1">Registrar</div>
                <div className="text-white text-sm font-medium truncate">{results.whois.registrar}</div>
              </div>
            )}

            {results.whois.domainAge && (
              <div className={`p-3 rounded-lg ${results.whois.domainAge.days < 30 ? 'bg-red-500/20' : results.whois.domainAge.days < 365 ? 'bg-yellow-500/20' : 'bg-dark-500'}`}>
                <div className="text-gray-400 text-xs mb-1 flex items-center gap-1">
                  <Clock className="h-3 w-3" /> Domain Age
                </div>
                <div className={`text-sm font-medium ${results.whois.domainAge.days < 30 ? 'text-red-400' : results.whois.domainAge.days < 365 ? 'text-yellow-400' : 'text-white'}`}>
                  {results.whois.domainAge.years} years ({results.whois.domainAge.days} days)
                </div>
              </div>
            )}

            {results.whois.creationDate && (
              <div className="p-3 bg-dark-500 rounded-lg">
                <div className="text-gray-400 text-xs mb-1">Created</div>
                <div className="text-white text-sm">{new Date(results.whois.creationDate).toLocaleDateString()}</div>
              </div>
            )}

            {results.whois.expirationDate && (
              <div className="p-3 bg-dark-500 rounded-lg">
                <div className="text-gray-400 text-xs mb-1">Expires</div>
                <div className="text-white text-sm">{new Date(results.whois.expirationDate).toLocaleDateString()}</div>
              </div>
            )}

            {results.whois.org && (
              <div className="p-3 bg-dark-500 rounded-lg">
                <div className="text-gray-400 text-xs mb-1">Organization</div>
                <div className="text-white text-sm truncate">{results.whois.org}</div>
              </div>
            )}

            {results.whois.country && (
              <div className="p-3 bg-dark-500 rounded-lg">
                <div className="text-gray-400 text-xs mb-1">Country</div>
                <div className="text-white text-sm">{results.whois.country}</div>
              </div>
            )}

            {results.whois.nameServers?.length > 0 && (
              <div className="p-3 bg-dark-500 rounded-lg md:col-span-2">
                <div className="text-gray-400 text-xs mb-1">Name Servers</div>
                <div className="flex flex-wrap gap-1">
                  {results.whois.nameServers.slice(0, 4).map((ns: string, i: number) => (
                    <span key={i} className="badge badge-info text-xs">{defangDomain(ns?.toLowerCase())}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

    </div>
  )
}

// Body-only variant for combined view (no risk score header)
function AnalysisResultsBody({ results }: { results: any }) {
  const analysis = results.analysis || results
  const redirectChain = analysis.redirectChain || []
  const screenshots = analysis.screenshots || []
  const iocs = analysis.extractedIocs || analysis.iocs || {}

  return (
    <div className="space-y-6">
      {/* Redirect Chain with Screenshots */}
      {(redirectChain.length > 0 || screenshots.length > 0) && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-6 flex items-center gap-2">
            <ExternalLink className="h-5 w-5 text-primary-500" />
            Redirect Chain & Screenshots
          </h3>

          <div className="space-y-6">
            {/* Original URL */}
            <RedirectStep
              step={0}
              url={analysis.url}
              screenshot={screenshots[0]}
              isFirst
            />

            {/* Redirect chain */}
            {redirectChain.map((redirect: any, i: number) => (
              <RedirectStep
                key={i}
                step={i + 1}
                url={redirect.redirectTo || redirect.url}
                status={redirect.statusCode}
                screenshot={screenshots[i + 1]}
              />
            ))}

            {/* Final page if different */}
            {analysis.finalUrl && analysis.finalUrl !== analysis.url && !redirectChain.find((r: any) => r.redirectTo === analysis.finalUrl) && (
              <RedirectStep
                step={redirectChain.length + 1}
                url={analysis.finalUrl}
                screenshot={analysis.screenshot}
                isFinal
              />
            )}
          </div>
        </div>
      )}

      {/* Final Screenshot */}
      {analysis.screenshot && screenshots.length === 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Camera className="h-5 w-5 text-primary-500" />
            Page Screenshot
          </h3>
          <ScreenshotThumbnail
            src={`data:image/png;base64,${analysis.screenshot}`}
            alt="Page screenshot"
          />
        </div>
      )}

      {/* Extracted IOCs */}
      {(iocs.ips?.length > 0 || iocs.domains?.length > 0 || iocs.urls?.length > 0) && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Globe className="h-5 w-5 text-primary-500" />
            Extracted IOCs
          </h3>

          {iocs.ips?.length > 0 && (
            <div className="mb-4">
              <h4 className="text-gray-400 text-sm font-semibold mb-2">IP Addresses ({iocs.ips.length}) <span className="text-xs text-gray-500 font-normal">(defanged)</span></h4>
              <div className="flex flex-wrap gap-2">
                {iocs.ips.map((ip: string, i: number) => (
                  <span key={i} className="badge badge-warning select-all" title="Defanged IP">{defangIp(ip)}</span>
                ))}
              </div>
            </div>
          )}

          {iocs.domains?.length > 0 && (
            <div className="mb-4">
              <h4 className="text-gray-400 text-sm font-semibold mb-2">Domains ({iocs.domains.length}) <span className="text-xs text-gray-500 font-normal">(defanged)</span></h4>
              <div className="flex flex-wrap gap-2">
                {iocs.domains.map((domain: string, i: number) => (
                  <span key={i} className="badge badge-info select-all" title="Defanged domain">{defangDomain(domain)}</span>
                ))}
              </div>
            </div>
          )}

          {iocs.urls?.length > 0 && (
            <div>
              <h4 className="text-gray-400 text-sm font-semibold mb-2">URLs ({iocs.urls.length}) <span className="text-xs text-gray-500 font-normal">(defanged)</span></h4>
              <div className="space-y-2 max-h-40 overflow-y-auto">
                {iocs.urls.slice(0, 20).map((url: string, i: number) => (
                  <code key={i} className="block p-2 bg-dark-500 rounded text-orange-400 text-xs break-all select-all" title="Defanged URL">
                    {defangUrl(url)}
                  </code>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

    </div>
  )
}

function RedirectStep({
  step,
  url,
  status,
  screenshot,
  isFirst,
  isFinal,
}: {
  step: number
  url: string
  status?: number
  screenshot?: string
  isFirst?: boolean
  isFinal?: boolean
}) {
  return (
    <div className="relative">
      {/* Connector line */}
      {!isFirst && (
        <div className="absolute left-6 -top-6 w-0.5 h-6 bg-gradient-to-b from-primary-500/50 to-primary-500"></div>
      )}

      <div className="flex gap-4">
        {/* Step indicator */}
        <div className={`flex-shrink-0 w-12 h-12 rounded-full flex items-center justify-center text-sm font-bold ${
          isFinal
            ? 'bg-green-500/20 text-green-400 border-2 border-green-500/50'
            : 'bg-primary-500/20 text-primary-400 border-2 border-primary-500/50'
        }`}>
          {isFinal ? '✓' : step + 1}
        </div>

        {/* Content */}
        <div className="flex-1 card bg-dark-500">
          <div className="flex items-center gap-2 mb-2">
            {isFirst && <span className="badge badge-info">Original</span>}
            {isFinal && <span className="badge badge-success">Final</span>}
            {status && (
              <span className={`badge ${status < 400 ? 'badge-success' : 'badge-danger'}`}>
                {status}
              </span>
            )}
          </div>

          <code className="block p-2 bg-dark-600 rounded text-orange-400 text-sm break-all mb-4 select-all" title="Defanged URL - safe to copy">
            {defangUrl(url)}
          </code>

          {screenshot && (
            <div>
              <p className="text-gray-400 text-xs mb-2">Screenshot (click to zoom):</p>
              <ScreenshotThumbnail
                src={`data:image/png;base64,${screenshot}`}
                alt={`Step ${step + 1} screenshot`}
              />
            </div>
          )}
        </div>
      </div>
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
