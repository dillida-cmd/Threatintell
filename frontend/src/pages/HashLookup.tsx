import { useState } from 'react'
import { Search, Hash, Shield, AlertTriangle, FileText, Tag } from 'lucide-react'
import { lookupHash } from '../api/client'
import RiskGauge from '../components/RiskGauge'
import LoadingSpinner from '../components/LoadingSpinner'
import AIValidation from '../components/AIValidation'

export default function HashLookup() {
  const [hash, setHash] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [results, setResults] = useState<any>(null)

  const handleLookup = async () => {
    if (!hash.trim()) return
    setLoading(true)
    setError(null)
    setResults(null)

    try {
      const data = await lookupHash(hash.trim())
      setResults(data)
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to lookup hash')
    } finally {
      setLoading(false)
    }
  }

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleLookup()
  }

  const summary = results?.summary || {}
  const sources = results?.sources || {}
  const aiValidation = results?.aiValidation || {}

  // Use AI-validated score if available
  const hasAiValidation = results?.aiValidation && typeof aiValidation.validatedScore === 'number'
  const riskScore = hasAiValidation ? aiValidation.validatedScore : (summary.riskScore || 0)
  const isMalicious = hasAiValidation ? aiValidation.validatedMalicious : summary.isMalicious
  const recommendation = hasAiValidation ? aiValidation.recommendation : null

  return (
    <div className="space-y-6">
      {/* Search Card */}
      <div className="card">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 bg-primary-600/20 rounded-lg">
            <Hash className="h-6 w-6 text-primary-500" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">File Hash Lookup</h2>
            <p className="text-gray-400 text-sm">Check if a file hash is known to be malicious</p>
          </div>
        </div>

        <div className="flex gap-3">
          <input
            type="text"
            value={hash}
            onChange={(e) => setHash(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Enter MD5, SHA1, or SHA256 hash"
            className="input flex-1 font-mono"
          />
          <button
            onClick={handleLookup}
            disabled={loading || !hash.trim()}
            className="btn btn-primary"
          >
            <Search className="h-5 w-5" />
            <span>Lookup</span>
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
      {loading && <LoadingSpinner message="Checking hash databases..." />}

      {/* Results */}
      {results && !loading && (
        <div className="space-y-6">
          {/* Risk Score and Hash Info */}
          <div className="grid md:grid-cols-3 gap-6">
            <div className="card flex items-center justify-center">
              <RiskGauge score={riskScore} size="lg" />
            </div>

            <div className="card md:col-span-2">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Hash className="h-5 w-5 text-primary-500" />
                Hash Analysis
              </h3>
              <code className="block p-3 bg-dark-500 rounded-lg text-primary-400 text-sm break-all font-mono mb-4">
                {results.hash}
              </code>
              <div className="flex flex-wrap gap-2 mb-4">
                {isMalicious ? (
                  <span className="badge badge-danger">MALICIOUS</span>
                ) : (
                  <span className="badge badge-success">CLEAN</span>
                )}
                {sources.virustotal?.malicious > 0 && (
                  <span className="badge badge-warning">
                    {sources.virustotal.malicious} Detection{sources.virustotal.malicious > 1 ? 's' : ''}
                  </span>
                )}
                {hasAiValidation && aiValidation.confidence && (
                  <span className="badge badge-info">AI Confidence: {aiValidation.confidence}%</span>
                )}
              </div>

              {/* AI Recommendation (primary) or Original Verdict (fallback) */}
              {(recommendation || summary.verdict) && (
                <div className={`p-4 rounded-lg ${
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
            </div>
          </div>

          {/* AI Risk Validation */}
          {results.aiValidation && (
            <AIValidation validation={results.aiValidation} />
          )}

          {/* Security Vendor Analysis */}
          {sources.virustotal && (
            <div className="card">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Shield className="h-5 w-5 text-primary-500" />
                Security Vendor Analysis
              </h3>

              <div className="grid grid-cols-4 gap-4 mb-6">
                <StatBox label="Malicious" value={sources.virustotal.malicious || 0} color="red" />
                <StatBox label="Suspicious" value={sources.virustotal.suspicious || 0} color="orange" />
                <StatBox label="Clean" value={sources.virustotal.harmless || 0} color="green" />
                <StatBox label="Undetected" value={sources.virustotal.undetected || 0} color="gray" />
              </div>

              {/* File Info */}
              {(sources.virustotal.fileName || sources.virustotal.fileSize) && (
                <div className="grid md:grid-cols-3 gap-4 p-4 bg-dark-500 rounded-lg mb-4">
                  {sources.virustotal.fileName && (
                    <div>
                      <span className="text-gray-400 text-xs flex items-center gap-1">
                        <FileText className="h-3 w-3" /> File Name
                      </span>
                      <p className="text-white font-medium">{sources.virustotal.fileName}</p>
                    </div>
                  )}
                  {sources.virustotal.fileSize && (
                    <div>
                      <span className="text-gray-400 text-xs">File Size</span>
                      <p className="text-white font-medium">{formatBytes(sources.virustotal.fileSize)}</p>
                    </div>
                  )}
                  {sources.virustotal.fileType && (
                    <div>
                      <span className="text-gray-400 text-xs">File Type</span>
                      <p className="text-white font-medium">{sources.virustotal.fileType}</p>
                    </div>
                  )}
                </div>
              )}

              {/* Tags */}
              {sources.virustotal.tags?.length > 0 && (
                <div>
                  <h4 className="text-gray-400 text-sm font-semibold mb-2 flex items-center gap-1">
                    <Tag className="h-3 w-3" /> Tags
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {sources.virustotal.tags.map((tag: string, i: number) => (
                      <span key={i} className="badge badge-info">{tag}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Known Malware */}
          {sources.malwarebazaar?.found && (
            <div className="card glow-red">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2 text-red-400">
                <AlertTriangle className="h-5 w-5" />
                Known Malware
              </h3>
              <div className="grid md:grid-cols-3 gap-4">
                {sources.malwarebazaar.signature && (
                  <div>
                    <span className="text-gray-400 text-xs">Signature</span>
                    <p className="text-red-400 font-semibold">{sources.malwarebazaar.signature}</p>
                  </div>
                )}
                {sources.malwarebazaar.fileType && (
                  <div>
                    <span className="text-gray-400 text-xs">File Type</span>
                    <p className="text-white font-semibold">{sources.malwarebazaar.fileType}</p>
                  </div>
                )}
                {sources.malwarebazaar.firstSeen && (
                  <div>
                    <span className="text-gray-400 text-xs">First Seen</span>
                    <p className="text-white font-semibold">{sources.malwarebazaar.firstSeen}</p>
                  </div>
                )}
              </div>
              {sources.malwarebazaar.tags?.length > 0 && (
                <div className="mt-4 flex flex-wrap gap-2">
                  {sources.malwarebazaar.tags.map((tag: string, i: number) => (
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
                <FileText className="h-5 w-5 text-primary-500" />
                Threat Intelligence
              </h3>

              <div className="grid grid-cols-3 gap-4 mb-4">
                <div className={`p-4 rounded-xl text-center ${sources.alienvault_otx.pulseCount > 10 ? 'bg-orange-500/20' : 'bg-dark-500'}`}>
                  <div className={`text-3xl font-bold ${sources.alienvault_otx.pulseCount > 10 ? 'text-orange-400' : 'text-white'}`}>
                    {sources.alienvault_otx.pulseCount || 0}
                  </div>
                  <div className="text-xs text-gray-400">Threat Reports</div>
                </div>
                {sources.alienvault_otx.fileType && (
                  <div className="p-4 rounded-xl bg-dark-500 text-center">
                    <div className="text-white font-medium">{sources.alienvault_otx.fileType}</div>
                    <div className="text-xs text-gray-400">File Type</div>
                  </div>
                )}
                {sources.alienvault_otx.fileSize && (
                  <div className="p-4 rounded-xl bg-dark-500 text-center">
                    <div className="text-white font-medium">{formatBytes(sources.alienvault_otx.fileSize)}</div>
                    <div className="text-xs text-gray-400">File Size</div>
                  </div>
                )}
              </div>

              {sources.alienvault_otx.pulses?.length > 0 && (
                <div>
                  <h4 className="text-orange-400 text-sm font-semibold mb-2">Related Threat Pulses ({sources.alienvault_otx.pulses.length})</h4>
                  <div className="space-y-2 max-h-60 overflow-y-auto">
                    {sources.alienvault_otx.pulses.slice(0, 5).map((pulse: any, i: number) => (
                      <div key={i} className="p-3 bg-dark-500 rounded-lg">
                        <div className="text-white font-medium text-sm">{pulse.name}</div>
                        {pulse.description && (
                          <div className="text-gray-400 text-xs mt-1 line-clamp-2">{pulse.description}</div>
                        )}
                        {pulse.tags?.length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-2">
                            {pulse.tags.slice(0, 6).map((tag: string, j: number) => (
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
      )}
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

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}
