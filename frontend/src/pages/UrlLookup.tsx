import { useState } from 'react'
import { Search, Link, Shield, AlertTriangle, Camera, ExternalLink, Globe, ArrowRight, X, ZoomIn } from 'lucide-react'
import { lookupUrlThreat, analyzeUrl } from '../api/client'
import RiskGauge from '../components/RiskGauge'
import LoadingSpinner from '../components/LoadingSpinner'
import { defangUrl, defangIp, defangDomain } from '../utils/defang'

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

type Tab = 'threat' | 'analysis'

export default function UrlLookup() {
  const [activeTab, setActiveTab] = useState<Tab>('threat')
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [results, setResults] = useState<any>(null)

  const handleLookup = async () => {
    if (!url.trim()) return
    setLoading(true)
    setError(null)
    setResults(null)

    try {
      let data
      if (activeTab === 'threat') {
        data = await lookupUrlThreat(url.trim())
      } else {
        data = await analyzeUrl(url.trim())
      }
      setResults(data)
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to analyze URL')
    } finally {
      setLoading(false)
    }
  }

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleLookup()
  }

  const clearResults = () => {
    setResults(null)
    setError(null)
  }

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
            <p className="text-gray-400 text-sm">Analyze URLs for threats and capture screenshots</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 mb-6 p-1 bg-dark-500 rounded-xl">
          <button
            onClick={() => { setActiveTab('threat'); clearResults() }}
            className={`flex-1 flex items-center justify-center gap-2 py-3 px-4 rounded-lg font-medium transition-all ${
              activeTab === 'threat'
                ? 'bg-primary-600 text-white shadow-lg'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            <Shield className="h-4 w-4" />
            Threat Intel
          </button>
          <button
            onClick={() => { setActiveTab('analysis'); clearResults() }}
            className={`flex-1 flex items-center justify-center gap-2 py-3 px-4 rounded-lg font-medium transition-all ${
              activeTab === 'analysis'
                ? 'bg-primary-600 text-white shadow-lg'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            <Camera className="h-4 w-4" />
            URL Analysis
          </button>
        </div>

        {/* Description */}
        <p className="text-gray-400 text-sm mb-4">
          {activeTab === 'threat'
            ? 'Check URL reputation against VirusTotal, URLhaus, and AlienVault OTX.'
            : 'Analyze URL with screenshots of each redirect step and IOC extraction.'}
        </p>

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
            <span>{activeTab === 'threat' ? 'Check' : 'Analyze'}</span>
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
        <LoadingSpinner
          message={activeTab === 'threat' ? 'Checking threat databases...' : 'Analyzing URL and capturing screenshots...'}
        />
      )}

      {/* Results */}
      {results && !loading && (
        activeTab === 'threat' ? (
          <ThreatResults results={results} />
        ) : (
          <AnalysisResults results={results} />
        )
      )}
    </div>
  )
}

function ThreatResults({ results }: { results: any }) {
  const summary = results.summary || {}
  const sources = results.sources || {}
  const riskScore = summary.riskScore || 0

  return (
    <div className="space-y-6">
      {/* Risk Score and URL */}
      <div className="grid md:grid-cols-3 gap-6">
        <div className="card flex items-center justify-center">
          <RiskGauge score={riskScore} size="lg" />
        </div>

        <div className="card md:col-span-2">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Link className="h-5 w-5 text-primary-500" />
            URL Analysis
          </h3>
          <code className="block p-3 bg-dark-500 rounded-lg text-orange-400 text-sm break-all mb-4 select-all" title="Defanged URL - safe to copy">
            {defangUrl(results.url)}
          </code>
          <div className="flex flex-wrap gap-2">
            {summary.isMalicious ? (
              <span className="badge badge-danger">MALICIOUS</span>
            ) : (
              <span className="badge badge-success">CLEAN</span>
            )}
            {sources.virustotal?.malicious > 0 && (
              <span className="badge badge-danger">{sources.virustotal.malicious} Detections</span>
            )}
            {sources.urlhaus?.threat && (
              <span className="badge badge-danger">{sources.urlhaus.threat}</span>
            )}
          </div>
        </div>
      </div>

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
    </div>
  )
}

function AnalysisResults({ results }: { results: any }) {
  const analysis = results.analysis || results
  const riskScore = analysis.riskScore || 0
  const redirectChain = analysis.redirectChain || []
  const screenshots = analysis.screenshots || []
  const iocs = analysis.extractedIocs || analysis.iocs || {}

  return (
    <div className="space-y-6">
      {/* Risk Score and Summary */}
      <div className="grid md:grid-cols-3 gap-6">
        <div className="card flex items-center justify-center">
          <RiskGauge score={riskScore} size="lg" />
        </div>

        <div className="card md:col-span-2">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Camera className="h-5 w-5 text-primary-500" />
            Analysis Results
          </h3>
          <code className="block p-3 bg-dark-500 rounded-lg text-orange-400 text-sm break-all mb-4 select-all" title="Defanged URL">
            {defangUrl(analysis.url)}
          </code>
          <div className="flex flex-wrap gap-2">
            <span className={`badge ${riskScore >= 50 ? 'badge-danger' : riskScore >= 20 ? 'badge-warning' : 'badge-success'}`}>
              {analysis.riskLevel || 'Unknown'} Risk
            </span>
            {analysis.finalUrl && analysis.finalUrl !== analysis.url && (
              <span className="badge badge-warning">Redirects Detected</span>
            )}
            {redirectChain.length > 0 && (
              <span className="badge badge-info">{redirectChain.length} Redirects</span>
            )}
          </div>
        </div>
      </div>

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
