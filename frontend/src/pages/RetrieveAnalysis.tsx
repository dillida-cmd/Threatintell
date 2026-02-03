import { useState } from 'react'
import { Search, AlertTriangle, CheckCircle, Clock, FileText, Download } from 'lucide-react'
import { downloadPdfReport, retrieveAnalysis } from '../api/client'

interface RetrievedResult {
  success: boolean
  type: string
  entryRef: string
  riskScore: number
  riskLevel: string
  storedAt: string
  expiresAt: string
  [key: string]: any
}

function RetrieveAnalysis() {
  const [entryRef, setEntryRef] = useState('')
  const [secretKey, setSecretKey] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<RetrievedResult | null>(null)
  const [downloading, setDownloading] = useState(false)

  const handleRetrieve = async () => {
    if (!entryRef.trim()) {
      setError('Please enter an entry reference')
      return
    }
    if (!secretKey.trim()) {
      setError('Please enter the secret key')
      return
    }

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const data = await retrieveAnalysis(entryRef, secretKey)

      if (!data.success) {
        throw new Error(data.error || 'Failed to retrieve analysis')
      }

      setResult(data)
    } catch (err: any) {
      const errorMsg = err?.response?.data?.error || err?.message || 'Failed to retrieve analysis'
      setError(errorMsg)
    } finally {
      setLoading(false)
    }
  }

  const handleDownloadPdf = async () => {
    if (!result?.entryRef) return
    setDownloading(true)
    try {
      await downloadPdfReport(result.entryRef, secretKey)
    } catch (err) {
      setError('Failed to download PDF report')
    } finally {
      setDownloading(false)
    }
  }

  const getRiskColor = (level: string) => {
    switch (level?.toLowerCase()) {
      case 'critical':
        return 'text-red-500'
      case 'high':
        return 'text-orange-500'
      case 'medium':
        return 'text-yellow-500'
      case 'low':
        return 'text-green-500'
      default:
        return 'text-gray-400'
    }
  }

  const formatDate = (dateStr: string) => {
    if (!dateStr) return 'N/A'
    return new Date(dateStr).toLocaleString()
  }

  return (
    <div className="space-y-6">
      {/* Search Form */}
      <div className="card">
        <div className="flex items-center gap-3 mb-6">
          <Search className="h-6 w-6 text-primary-500" />
          <h2 className="text-xl font-semibold text-white">Retrieve Analysis</h2>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-2">Entry Reference</label>
            <input
              type="text"
              value={entryRef}
              onChange={(e) => setEntryRef(e.target.value.toUpperCase())}
              placeholder="e.g., MSB0001"
              className="input-field w-full"
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-2">Secret Key</label>
            <input
              type="password"
              value={secretKey}
              onChange={(e) => setSecretKey(e.target.value)}
              placeholder="Enter your secret key"
              className="input-field w-full"
            />
            <p className="text-xs text-gray-500 mt-1">
              Analysis results are stored for 15 days and then automatically deleted.
            </p>
          </div>

          <button
            onClick={handleRetrieve}
            disabled={loading}
            className="btn-primary w-full flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent" />
                Retrieving...
              </>
            ) : (
              <>
                <Search className="h-4 w-4" />
                Retrieve Analysis
              </>
            )}
          </button>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="card border-red-500/30 bg-red-500/10">
          <div className="flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-red-500" />
            <p className="text-red-400">{error}</p>
          </div>
        </div>
      )}

      {/* Result Display */}
      {result && (
        <div className="space-y-4">
          {/* Header Card */}
          <div className="card">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <CheckCircle className="h-6 w-6 text-green-500" />
                <div>
                  <h3 className="text-lg font-semibold text-white">Analysis Retrieved</h3>
                  <p className="text-sm text-gray-400">Entry: {result.entryRef}</p>
                </div>
              </div>
              <button
                onClick={handleDownloadPdf}
                disabled={downloading}
                className="btn-secondary flex items-center gap-2"
              >
                {downloading ? (
                  <div className="animate-spin rounded-full h-4 w-4 border-2 border-primary-500 border-t-transparent" />
                ) : (
                  <Download className="h-4 w-4" />
                )}
                Download PDF
              </button>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-dark-400 rounded-lg p-3">
                <p className="text-xs text-gray-500 mb-1">Type</p>
                <p className="text-white font-medium capitalize">{result.type || 'Unknown'}</p>
              </div>
              <div className="bg-dark-400 rounded-lg p-3">
                <p className="text-xs text-gray-500 mb-1">Risk Score</p>
                <p className={`text-2xl font-bold ${getRiskColor(result.riskLevel)}`}>
                  {result.riskScore || 0}
                </p>
              </div>
              <div className="bg-dark-400 rounded-lg p-3">
                <p className="text-xs text-gray-500 mb-1">Risk Level</p>
                <p className={`font-medium ${getRiskColor(result.riskLevel)}`}>
                  {result.riskLevel || 'Unknown'}
                </p>
              </div>
              <div className="bg-dark-400 rounded-lg p-3">
                <p className="text-xs text-gray-500 mb-1">Analysis Date</p>
                <p className="text-white text-sm">{formatDate(result.storedAt)}</p>
              </div>
            </div>
          </div>

          {/* Expiration Notice */}
          <div className="card border-yellow-500/30 bg-yellow-500/5">
            <div className="flex items-center gap-3">
              <Clock className="h-5 w-5 text-yellow-500" />
              <div>
                <p className="text-yellow-400 font-medium">Data Retention Notice</p>
                <p className="text-sm text-gray-400">
                  This analysis will be automatically deleted on {formatDate(result.expiresAt)}
                </p>
              </div>
            </div>
          </div>

          {/* Email Analysis Details */}
          {result.type === 'email' && (
            <>
              {/* Headers */}
              {result.headers && (
                <div className="card">
                  <h4 className="text-lg font-semibold text-white mb-4">Email Headers</h4>
                  <div className="space-y-2">
                    {Object.entries(result.headers).map(([key, value]) => (
                      <div key={key} className="flex">
                        <span className="text-gray-500 w-32 flex-shrink-0 capitalize">
                          {key.replace(/_/g, ' ')}:
                        </span>
                        <span className="text-white break-all">{String(value) || 'N/A'}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Phishing Indicators */}
              {result.phishingIndicators && result.phishingIndicators.length > 0 && (
                <div className="card">
                  <h4 className="text-lg font-semibold text-white mb-4">Phishing Indicators</h4>
                  <div className="space-y-2">
                    {result.phishingIndicators.map((indicator: any, idx: number) => (
                      <div
                        key={idx}
                        className={`p-3 rounded-lg border ${
                          indicator.severity === 'high'
                            ? 'border-red-500/30 bg-red-500/10'
                            : indicator.severity === 'medium'
                            ? 'border-yellow-500/30 bg-yellow-500/10'
                            : 'border-gray-500/30 bg-gray-500/10'
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          <AlertTriangle
                            className={`h-4 w-4 ${
                              indicator.severity === 'high'
                                ? 'text-red-500'
                                : indicator.severity === 'medium'
                                ? 'text-yellow-500'
                                : 'text-gray-500'
                            }`}
                          />
                          <span className="text-white">{indicator.description}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* URLs */}
              {result.urls && result.urls.length > 0 && (
                <div className="card">
                  <h4 className="text-lg font-semibold text-white mb-4">
                    Extracted URLs ({result.urls.length})
                  </h4>
                  <div className="space-y-2">
                    {result.urls.map((url: string, idx: number) => (
                      <div key={idx} className="bg-dark-400 p-2 rounded text-sm font-mono text-gray-300 break-all">
                        {url}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Attachments */}
              {result.attachments && result.attachments.length > 0 && (
                <div className="card">
                  <h4 className="text-lg font-semibold text-white mb-4">
                    Attachments ({result.attachments.length})
                  </h4>
                  <div className="space-y-3">
                    {result.attachments.map((att: any, idx: number) => (
                      <div
                        key={idx}
                        className={`p-3 rounded-lg border ${
                          att.isSuspicious
                            ? 'border-red-500/30 bg-red-500/10'
                            : 'border-dark-100 bg-dark-400'
                        }`}
                      >
                        <div className="flex items-center gap-3">
                          <FileText className={`h-5 w-5 ${att.isSuspicious ? 'text-red-500' : 'text-gray-400'}`} />
                          <div className="flex-1">
                            <p className="text-white font-medium">{att.filename}</p>
                            <p className="text-xs text-gray-500">
                              {att.contentType} | {att.size} bytes
                            </p>
                            {att.sha256 && (
                              <p className="text-xs text-gray-500 font-mono mt-1">
                                SHA256: {att.sha256}
                              </p>
                            )}
                          </div>
                          {att.isSuspicious && (
                            <span className="px-2 py-1 bg-red-500/20 text-red-400 text-xs rounded">
                              Suspicious
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}

          {/* IOC Investigation */}
          {result.iocInvestigation && (
            <div className="card">
              <h4 className="text-lg font-semibold text-white mb-4">IOC Investigation</h4>
              <div className="grid grid-cols-3 gap-4 mb-4">
                <div className="bg-dark-400 rounded-lg p-3 text-center">
                  <p className="text-2xl font-bold text-white">
                    {result.iocInvestigation.summary?.totalIOCs || 0}
                  </p>
                  <p className="text-xs text-gray-500">Total IOCs</p>
                </div>
                <div className="bg-dark-400 rounded-lg p-3 text-center">
                  <p className="text-2xl font-bold text-red-500">
                    {result.iocInvestigation.summary?.maliciousIOCs || 0}
                  </p>
                  <p className="text-xs text-gray-500">Malicious</p>
                </div>
                <div className="bg-dark-400 rounded-lg p-3 text-center">
                  <p className="text-2xl font-bold text-primary-500">
                    {result.iocInvestigation.summary?.overallRiskScore || 0}
                  </p>
                  <p className="text-xs text-gray-500">Risk Score</p>
                </div>
              </div>

              {/* Malicious URLs */}
              {result.iocInvestigation.urls?.filter((u: any) => u.summary?.isMalicious).length > 0 && (
                <div className="space-y-2">
                  <h5 className="text-sm font-medium text-red-400">Malicious URLs Detected</h5>
                  {result.iocInvestigation.urls
                    .filter((u: any) => u.summary?.isMalicious)
                    .map((url: any, idx: number) => (
                      <div key={idx} className="bg-red-500/10 border border-red-500/30 p-3 rounded-lg">
                        <p className="text-white font-mono text-sm break-all">{url.url}</p>
                        <p className="text-xs text-red-400 mt-1">
                          {url.summary?.findings?.join(', ')}
                        </p>
                      </div>
                    ))}
                </div>
              )}
            </div>
          )}

          {/* Raw JSON for debugging */}
          <details className="card">
            <summary className="text-gray-400 cursor-pointer hover:text-white">
              View Raw Analysis Data
            </summary>
            <pre className="mt-4 p-4 bg-dark-400 rounded-lg overflow-auto text-xs text-gray-300 max-h-96">
              {JSON.stringify(result, null, 2)}
            </pre>
          </details>
        </div>
      )}
    </div>
  )
}

export default RetrieveAnalysis
