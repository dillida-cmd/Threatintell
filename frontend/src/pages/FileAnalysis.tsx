import { useState, useRef } from 'react'
import {
  Upload, FileSearch, Shield, AlertTriangle, Mail, FileText, Table,
  QrCode, Terminal, Camera, Globe, Link, Code, Package, Download, Key, X, ZoomIn
} from 'lucide-react'
import { analyzeFile } from '../api/client'
import RiskGauge from '../components/RiskGauge'
import LoadingSpinner from '../components/LoadingSpinner'
import { defangUrl, defangIp, defangDomain, defangEmail } from '../utils/defang'

const MAX_FILE_SIZE = 15 * 1024 * 1024 // 15MB

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
function ScreenshotThumbnail({ src, alt, label }: { src: string; alt: string; label?: string }) {
  const [zoomed, setZoomed] = useState(false)

  return (
    <>
      <div
        className="relative cursor-pointer group"
        onClick={() => setZoomed(true)}
      >
        {label && <span className="absolute top-2 left-2 badge badge-neutral z-10">{label}</span>}
        <div className="absolute inset-0 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity bg-black/50 rounded-lg">
          <ZoomIn className="h-8 w-8 text-white" />
        </div>
        <img
          src={src}
          alt={alt}
          className="w-full rounded-lg border border-dark-200 transition-transform group-hover:scale-[1.02]"
        />
      </div>
      {zoomed && (
        <ScreenshotModal src={src} alt={alt} onClose={() => setZoomed(false)} />
      )}
    </>
  )
}

// Attachment item with download and analyze functionality
function AttachmentItem({ attachment }: { attachment: any }) {
  const [analyzing, setAnalyzing] = useState(false)
  const [analysisResult, setAnalysisResult] = useState<any>(null)
  const [error, setError] = useState<string | null>(null)

  const suspicious = attachment.suspicious || attachment.isSuspicious || attachment.is_suspicious
  const filename = attachment.filename || 'unknown'
  const ext = (attachment.extension || '.' + filename.split('.').pop() || '').toLowerCase()

  const handleDownload = () => {
    if (!attachment.data) {
      setError('Attachment data not available for download')
      return
    }
    try {
      const byteCharacters = atob(attachment.data)
      const byteNumbers = new Array(byteCharacters.length)
      for (let i = 0; i < byteCharacters.length; i++) {
        byteNumbers[i] = byteCharacters.charCodeAt(i)
      }
      const byteArray = new Uint8Array(byteNumbers)
      const blob = new Blob([byteArray])
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = filename
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
    } catch (err) {
      setError('Failed to download attachment')
    }
  }

  const handleAnalyze = async () => {
    if (!attachment.data) {
      setError('Attachment data not available for analysis')
      return
    }
    setAnalyzing(true)
    setError(null)
    try {
      const { analyzeAttachment } = await import('../api/client')
      const result = await analyzeAttachment(attachment.data, filename, 'attachment_analysis')
      setAnalysisResult(result)
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to analyze attachment')
    } finally {
      setAnalyzing(false)
    }
  }

  const getRiskColor = (score: number) => {
    if (score >= 50) return 'text-red-400'
    if (score >= 20) return 'text-orange-400'
    return 'text-green-400'
  }

  return (
    <div className={`p-4 rounded-lg ${suspicious ? 'bg-red-500/10 border border-red-500/30' : 'bg-dark-500'}`}>
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-3">
          <FileText className={`h-5 w-5 ${suspicious ? 'text-red-400' : 'text-gray-400'}`} />
          <span className={`font-medium ${suspicious ? 'text-red-400' : 'text-white'}`}>{filename}</span>
        </div>
        <div className="flex items-center gap-2">
          {suspicious && <span className="badge badge-danger">Suspicious</span>}
          <span className="badge badge-neutral">{ext}</span>
          <span className="text-gray-400 text-sm">{formatBytes(attachment.size || 0)}</span>
        </div>
      </div>

      {/* Action buttons */}
      <div className="flex gap-2 mt-3">
        <button
          onClick={handleDownload}
          disabled={!attachment.data}
          className="btn btn-secondary text-sm py-1 px-3"
        >
          <Download className="h-4 w-4" />
          <span>Download</span>
        </button>
        <button
          onClick={handleAnalyze}
          disabled={analyzing || !attachment.data}
          className="btn btn-primary text-sm py-1 px-3"
        >
          <Shield className="h-4 w-4" />
          <span>{analyzing ? 'Analyzing...' : 'Analyze'}</span>
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="mt-3 p-2 bg-red-500/10 rounded text-red-400 text-sm flex items-center gap-2">
          <AlertTriangle className="h-4 w-4" />
          {error}
        </div>
      )}

      {/* Analysis Results */}
      {analysisResult && (
        <div className="mt-4 p-4 bg-dark-600 rounded-lg border border-dark-300">
          <h4 className="text-white font-semibold mb-3 flex items-center gap-2">
            <Shield className="h-4 w-4 text-primary-500" />
            Analysis Results
          </h4>

          {/* Risk Score */}
          {(analysisResult.riskScore !== undefined || analysisResult.risk_score !== undefined) && (
            <div className="flex items-center gap-3 mb-3">
              <span className="text-gray-400 text-sm">Risk Score:</span>
              <span className={`text-2xl font-bold ${getRiskColor(analysisResult.riskScore || analysisResult.risk_score || 0)}`}>
                {analysisResult.riskScore || analysisResult.risk_score || 0}
              </span>
              <span className={`badge ${(analysisResult.riskScore || analysisResult.risk_score || 0) >= 50 ? 'badge-danger' : (analysisResult.riskScore || analysisResult.risk_score || 0) >= 20 ? 'badge-warning' : 'badge-success'}`}>
                {analysisResult.riskLevel || analysisResult.risk_level || 'Unknown'}
              </span>
            </div>
          )}

          {/* Entry Reference */}
          {(analysisResult.entryRef || analysisResult.entry_ref) && (
            <div className="mb-3">
              <span className="text-gray-400 text-xs">Entry Reference:</span>
              <span className="text-primary-400 font-mono ml-2">{analysisResult.entryRef || analysisResult.entry_ref}</span>
            </div>
          )}

          {/* Type-specific results */}
          {analysisResult.type === 'pdf' && (
            <div className="space-y-2 text-sm">
              {analysisResult.hasJavaScript && <p className="text-red-400">Contains JavaScript</p>}
              {analysisResult.hasEmbeddedFiles && <p className="text-orange-400">Contains embedded files</p>}
              {analysisResult.urls?.length > 0 && (
                <p className="text-gray-300">URLs found: {analysisResult.urls.length}</p>
              )}
            </div>
          )}

          {analysisResult.type === 'sandbox' && (
            <div className="space-y-2 text-sm">
              {analysisResult.behaviorSummary && (
                <>
                  <p className="text-gray-300">Processes: {analysisResult.behaviorSummary.processCount || 0}</p>
                  <p className="text-gray-300">Network connections: {analysisResult.behaviorSummary.networkConnections || 0}</p>
                  {analysisResult.behaviorSummary.suspiciousActivities > 0 && (
                    <p className="text-red-400">Suspicious activities: {analysisResult.behaviorSummary.suspiciousActivities}</p>
                  )}
                </>
              )}
            </div>
          )}

          {/* Phishing indicators for emails within attachments */}
          {analysisResult.phishingIndicators?.length > 0 && (
            <div className="mt-3">
              <p className="text-red-400 text-sm font-semibold mb-2">Phishing Indicators:</p>
              <div className="space-y-1">
                {analysisResult.phishingIndicators.slice(0, 5).map((ind: any, i: number) => (
                  <p key={i} className="text-red-300 text-xs">
                    {typeof ind === 'string' ? ind : ind.description}
                  </p>
                ))}
              </div>
            </div>
          )}

          {/* IOCs */}
          {(analysisResult.extractedIocs || analysisResult.iocInvestigation) && (
            <div className="mt-3">
              <p className="text-gray-400 text-sm font-semibold mb-2">Extracted IOCs:</p>
              <div className="flex flex-wrap gap-2">
                {(analysisResult.extractedIocs?.ips || []).slice(0, 5).map((ip: string, i: number) => (
                  <span key={i} className="badge badge-warning text-xs">{ip}</span>
                ))}
                {(analysisResult.extractedIocs?.domains || []).slice(0, 5).map((d: string, i: number) => (
                  <span key={i} className="badge badge-info text-xs">{d}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

const FILE_TYPES = [
  { ext: ['.eml', '.msg'], label: 'Email', icon: Mail, color: 'blue' },
  { ext: ['.pdf'], label: 'PDF', icon: FileText, color: 'red' },
  { ext: ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'], label: 'Documents', icon: Table, color: 'green' },
  { ext: ['.png', '.jpg', '.jpeg', '.gif', '.bmp'], label: 'Images (QR)', icon: QrCode, color: 'purple' },
  { ext: ['.exe', '.dll', '.msi'], label: 'Executables', icon: Terminal, color: 'orange' },
  { ext: ['.sh', '.py', '.js', '.bat', '.ps1', '.vbs'], label: 'Scripts', icon: Code, color: 'yellow' },
]

export default function FileAnalysis() {
  const [file, setFile] = useState<File | null>(null)
  const [secretKey, setSecretKey] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [results, setResults] = useState<any>(null)
  const [dragOver, setDragOver] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFileSelect = (selectedFile: File) => {
    if (selectedFile.size > MAX_FILE_SIZE) {
      setError(`File size exceeds 15MB limit (${formatBytes(selectedFile.size)})`)
      return
    }
    setFile(selectedFile)
    setError(null)
    setResults(null)
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    const droppedFile = e.dataTransfer.files[0]
    if (droppedFile) handleFileSelect(droppedFile)
  }

  const handleAnalyze = async () => {
    if (!file || !secretKey.trim()) return
    setLoading(true)
    setError(null)

    try {
      const data = await analyzeFile(file, secretKey.trim())
      setResults(data)
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to analyze file')
    } finally {
      setLoading(false)
    }
  }

  const clearFile = () => {
    setFile(null)
    setSecretKey('')
    setResults(null)
    setError(null)
  }

  const getFileType = (filename: string) => {
    const ext = '.' + filename.toLowerCase().split('.').pop()
    return FILE_TYPES.find(t => t.ext.includes(ext))
  }

  return (
    <div className="space-y-6">
      {/* Header Card */}
      <div className="card">
        <div className="flex items-center gap-3 mb-6">
          <div className="p-2 bg-primary-600/20 rounded-lg">
            <FileSearch className="h-6 w-6 text-primary-500" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">File Analysis</h2>
            <p className="text-gray-400 text-sm">Upload suspicious files for comprehensive security analysis (max 15MB)</p>
          </div>
        </div>

        {/* Supported file types */}
        <div className="grid grid-cols-2 md:grid-cols-6 gap-2 mb-6">
          {FILE_TYPES.map((type) => (
            <div
              key={type.label}
              className="flex items-center gap-2 p-2 bg-dark-500 rounded-lg text-sm"
            >
              <type.icon className="h-4 w-4 text-primary-500" />
              <span className="text-gray-300">{type.label}</span>
            </div>
          ))}
        </div>

        {/* Drop zone */}
        {!results && (
          <div
            onDrop={handleDrop}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
            onDragLeave={() => setDragOver(false)}
            onClick={() => fileInputRef.current?.click()}
            className={`relative border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all ${
              dragOver
                ? 'border-primary-500 bg-primary-500/10'
                : file
                ? 'border-green-500/50 bg-green-500/10'
                : 'border-dark-100 hover:border-primary-500/50 hover:bg-dark-500'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              onChange={(e) => e.target.files?.[0] && handleFileSelect(e.target.files[0])}
              className="hidden"
              accept=".eml,.msg,.pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.odt,.ods,.odp,.png,.jpg,.jpeg,.gif,.bmp,.webp,.exe,.dll,.msi,.sh,.py,.js,.bat,.ps1,.vbs"
            />

            {file ? (
              <div className="flex items-center justify-center gap-4">
                <div className="p-3 bg-green-500/20 rounded-lg">
                  {getFileType(file.name)?.icon ? (
                    <FileText className="h-8 w-8 text-green-500" />
                  ) : (
                    <FileText className="h-8 w-8 text-green-500" />
                  )}
                </div>
                <div className="text-left">
                  <p className="text-white font-semibold">{file.name}</p>
                  <p className="text-gray-400 text-sm">
                    {formatBytes(file.size)} • {getFileType(file.name)?.label || 'Unknown'}
                  </p>
                </div>
                <button
                  onClick={(e) => { e.stopPropagation(); clearFile() }}
                  className="ml-4 text-gray-400 hover:text-white"
                >
                  ✕
                </button>
              </div>
            ) : (
              <>
                <Upload className="h-12 w-12 text-gray-500 mx-auto mb-4" />
                <p className="text-white font-medium mb-1">
                  Drop file here or <span className="text-primary-500">browse</span>
                </p>
                <p className="text-gray-500 text-sm">Max file size: 15MB</p>
              </>
            )}
          </div>
        )}

        {/* Secret Key Input */}
        {file && !results && !loading && (
          <div className="mt-4">
            <label className="block text-sm font-medium text-gray-400 mb-2">
              <Key className="h-4 w-4 inline mr-1" />
              Secret Key (for result encryption & retrieval)
            </label>
            <input
              type="password"
              value={secretKey}
              onChange={(e) => setSecretKey(e.target.value)}
              placeholder="Enter a secret key to encrypt results"
              className="input w-full"
            />
            <p className="text-gray-500 text-xs mt-2">
              Results will be automatically deleted after 15 days
            </p>
          </div>
        )}

        {/* Analyze button */}
        {file && !results && !loading && (
          <button
            onClick={handleAnalyze}
            disabled={!secretKey.trim()}
            className="btn btn-primary w-full mt-4"
          >
            <Shield className="h-5 w-5" />
            <span>Analyze File</span>
          </button>
        )}

        {/* New analysis button */}
        {results && (
          <button
            onClick={clearFile}
            className="btn btn-secondary w-full mt-4"
          >
            ← Start New Analysis
          </button>
        )}
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
      {loading && <LoadingSpinner message="Analyzing file..." />}

      {/* Results */}
      {results && !loading && <FileResults results={results} secretKey={secretKey} />}
    </div>
  )
}

function FileResults({ results, secretKey }: { results: any; secretKey: string }) {
  const analysis = results.analysis || results
  const fileType = analysis.type || analysis.file_type || 'unknown'
  const riskScore = analysis.riskScore || analysis.risk_score || 0
  const entryRef = results.entryRef || results.entry_ref || analysis.entryRef || analysis.entry_ref

  return (
    <div className="space-y-6">
      {/* Entry Reference & Download */}
      {entryRef && (
        <ResultHeader entryRef={entryRef} secretKey={secretKey} riskScore={riskScore} />
      )}

      {/* Type-specific results */}
      {fileType === 'email' && <EmailResultsView analysis={analysis} riskScore={riskScore} />}
      {fileType === 'pdf' && <PdfResultsView analysis={analysis} riskScore={riskScore} />}
      {fileType === 'office' && <OfficeResultsView analysis={analysis} riskScore={riskScore} />}
      {fileType === 'qrcode' && <QrCodeResultsView analysis={analysis} />}
      {fileType === 'sandbox' && <SandboxResultsView analysis={analysis} riskScore={riskScore} />}
      {!['email', 'pdf', 'office', 'qrcode', 'sandbox'].includes(fileType) && (
        <GenericResultsView analysis={analysis} riskScore={riskScore} />
      )}
    </div>
  )
}

function ResultHeader({ entryRef, secretKey, riskScore }: { entryRef: string; secretKey: string; riskScore: number }) {
  const [downloading, setDownloading] = useState(false)

  const handleDownload = async () => {
    setDownloading(true)
    try {
      const { downloadPdfReport } = await import('../api/client')
      await downloadPdfReport(entryRef, secretKey)
    } catch (err) {
      console.error('Download failed:', err)
    } finally {
      setDownloading(false)
    }
  }

  return (
    <div className="card">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <RiskGauge score={riskScore} size="sm" />
          <div>
            <p className="text-gray-400 text-xs">Entry Reference</p>
            <p className="text-white font-mono text-lg font-bold">{entryRef}</p>
            <p className="text-gray-500 text-xs mt-1">Results will be deleted after 15 days</p>
          </div>
        </div>
        <button
          onClick={handleDownload}
          disabled={downloading}
          className="btn btn-primary"
        >
          <Download className="h-5 w-5" />
          <span>{downloading ? 'Downloading...' : 'Download PDF Report'}</span>
        </button>
      </div>
    </div>
  )
}

function EmailResultsView({ analysis, riskScore }: { analysis: any; riskScore: number }) {
  const headers = analysis.headers || {}
  const phishing = analysis.phishingIndicators || analysis.phishing_indicators || []
  const attachments = analysis.attachments || []
  const urls = analysis.urls || []
  const auth = analysis.authentication || analysis.security_indicators || {}

  return (
    <div className="space-y-6">
      {/* Risk and Summary */}
      <div className="grid md:grid-cols-3 gap-6">
        <div className="card flex items-center justify-center">
          <RiskGauge score={riskScore} size="lg" />
        </div>
        <div className="card md:col-span-2">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Mail className="h-5 w-5 text-primary-500" />
            Email Analysis
          </h3>
          <div className="space-y-2">
            <InfoRow label="Subject" value={headers.subject || analysis.subject} />
            <InfoRow label="From" value={headers.from || analysis.from} />
            <InfoRow label="To" value={headers.to || analysis.to} />
            <InfoRow label="Date" value={headers.date || analysis.date} />
          </div>
        </div>
      </div>

      {/* Phishing Indicators */}
      {phishing.length > 0 && (
        <div className="card glow-red">
          <h3 className="text-lg font-semibold mb-4 text-red-400 flex items-center gap-2">
            <AlertTriangle className="h-5 w-5" />
            Phishing Indicators ({phishing.length})
          </h3>
          <div className="space-y-2">
            {phishing.map((indicator: any, i: number) => (
              <div key={i} className="flex items-center gap-2 p-3 bg-red-500/10 rounded-lg text-red-400">
                <AlertTriangle className="h-4 w-4 flex-shrink-0" />
                <span>{typeof indicator === 'string' ? indicator : indicator.description || indicator.reason}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Authentication */}
      {Object.keys(auth).length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary-500" />
            Email Authentication
          </h3>
          <div className="flex gap-4">
            {['spf', 'dkim', 'dmarc'].map((check) => {
              const value = typeof auth[check] === 'string' ? auth[check] : auth[check]?.result || auth[check]?.status || '-'
              const pass = value.toLowerCase().includes('pass')
              return (
                <div key={check} className={`flex-1 p-4 rounded-lg ${pass ? 'bg-green-500/10' : 'bg-red-500/10'}`}>
                  <span className="text-gray-400 text-xs uppercase">{check}</span>
                  <p className={`font-semibold ${pass ? 'text-green-400' : 'text-red-400'}`}>{value}</p>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Attachments */}
      {attachments.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Package className="h-5 w-5 text-primary-500" />
            Attachments ({attachments.length})
          </h3>
          <div className="space-y-3">
            {attachments.map((att: any, i: number) => (
              <AttachmentItem key={i} attachment={att} />
            ))}
          </div>
        </div>
      )}

      {/* URLs */}
      {urls.length > 0 && <UrlList urls={urls} title="Extracted URLs" />}
    </div>
  )
}

function PdfResultsView({ analysis, riskScore }: { analysis: any; riskScore: number }) {
  const metadata = analysis.metadata || {}
  const screenshots = analysis.pageScreenshots || analysis.page_screenshots || []
  const urls = analysis.urls || []
  const qrCodes = analysis.qrCodes || analysis.qr_codes || []
  const javascript = analysis.javascript || []

  return (
    <div className="space-y-6">
      {/* Risk and Summary */}
      <div className="grid md:grid-cols-3 gap-6">
        <div className="card flex items-center justify-center">
          <RiskGauge score={riskScore} size="lg" />
        </div>
        <div className="card md:col-span-2">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <FileText className="h-5 w-5 text-primary-500" />
            PDF Analysis
          </h3>
          <div className="space-y-2">
            <InfoRow label="Title" value={metadata.title} />
            <InfoRow label="Author" value={metadata.author} />
            <InfoRow label="Pages" value={analysis.pageCount || analysis.page_count} />
            <InfoRow label="Creator" value={metadata.creator} />
          </div>
        </div>
      </div>

      {/* Security Analysis */}
      <div className="card">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Shield className="h-5 w-5 text-primary-500" />
          Security Analysis
        </h3>
        <div className="grid grid-cols-4 gap-2">
          {[
            { label: 'JavaScript', active: analysis.hasJavaScript || analysis.has_javascript },
            { label: 'Embedded Files', active: analysis.hasEmbeddedFiles || analysis.has_embedded_files },
            { label: 'External Refs', active: analysis.hasExternalRefs || analysis.has_external_refs },
            { label: 'Forms', active: analysis.hasForms || analysis.has_forms },
          ].map((item) => (
            <div key={item.label} className={`p-3 rounded-lg text-center ${item.active ? 'bg-red-500/10 text-red-400' : 'bg-green-500/10 text-green-400'}`}>
              <span className="text-sm font-medium">{item.label}</span>
              <p className="text-lg font-bold">{item.active ? 'Yes' : 'No'}</p>
            </div>
          ))}
        </div>
      </div>

      {/* JavaScript Findings */}
      {javascript.length > 0 && (
        <div className="card glow-red">
          <h3 className="text-lg font-semibold mb-4 text-red-400 flex items-center gap-2">
            <AlertTriangle className="h-5 w-5" />
            JavaScript Detected
          </h3>
          <div className="space-y-2">
            {javascript.map((js: string, i: number) => (
              <div key={i} className="p-3 bg-red-500/10 rounded-lg text-red-400 text-sm">
                {js}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Page Screenshots */}
      {screenshots.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Camera className="h-5 w-5 text-primary-500" />
            Page Screenshots ({screenshots.length})
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {screenshots.slice(0, 10).map((screenshot: string, i: number) => (
              <ScreenshotThumbnail
                key={i}
                src={`data:image/png;base64,${screenshot}`}
                alt={`Page ${i + 1}`}
                label={`Page ${i + 1}`}
              />
            ))}
          </div>
        </div>
      )}

      {/* QR Codes */}
      {qrCodes.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <QrCode className="h-5 w-5 text-primary-500" />
            QR Codes Found ({qrCodes.length})
          </h3>
          <div className="space-y-2">
            {qrCodes.map((qr: any, i: number) => (
              <div key={i} className="p-3 bg-dark-500 rounded-lg">
                <code className="text-primary-400 text-sm break-all">{qr.raw_data || qr.data}</code>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* URLs */}
      {urls.length > 0 && <UrlList urls={urls} title="Extracted URLs" />}
    </div>
  )
}

function OfficeResultsView({ analysis, riskScore }: { analysis: any; riskScore: number }) {
  const hasMacros = analysis.hasMacros || analysis.has_macros
  const macros = analysis.macros || []
  const autoExec = analysis.autoExecution || analysis.auto_execution || []
  const patterns = analysis.suspiciousPatterns || analysis.suspicious_patterns || []
  const screenshots = analysis.documentScreenshots || analysis.document_screenshots || []
  const urls = analysis.urls || []

  return (
    <div className="space-y-6">
      {/* Risk and Summary */}
      <div className="grid md:grid-cols-3 gap-6">
        <div className="card flex items-center justify-center">
          <RiskGauge score={riskScore} size="lg" />
        </div>
        <div className="card md:col-span-2">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Table className="h-5 w-5 text-primary-500" />
            Document Analysis
          </h3>
          <div className="space-y-2">
            <InfoRow label="Filename" value={analysis.filename} />
            <InfoRow label="Type" value={analysis.documentType || analysis.type} />
          </div>
        </div>
      </div>

      {/* Macro Analysis */}
      <div className="card">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Code className="h-5 w-5 text-primary-500" />
          Macro Analysis
        </h3>
        <div className={`p-4 rounded-lg ${hasMacros ? 'bg-red-500/10 border border-red-500/30' : 'bg-green-500/10 border border-green-500/30'}`}>
          <span className={`font-semibold ${hasMacros ? 'text-red-400' : 'text-green-400'}`}>
            {hasMacros ? 'Macros Detected' : 'No Macros'}
          </span>
        </div>

        {hasMacros && autoExec.length > 0 && (
          <div className="mt-4">
            <h4 className="text-red-400 font-semibold mb-2">Auto-Execution Triggers</h4>
            <div className="space-y-2">
              {autoExec.map((trigger: any, i: number) => (
                <div key={i} className="flex items-center gap-2 p-2 bg-red-500/10 rounded text-red-400 text-sm">
                  <AlertTriangle className="h-4 w-4" />
                  {trigger.trigger || String(trigger)}
                </div>
              ))}
            </div>
          </div>
        )}

        {patterns.length > 0 && (
          <div className="mt-4">
            <h4 className="text-red-400 font-semibold mb-2">Suspicious Patterns</h4>
            <div className="space-y-2">
              {patterns.map((pattern: any, i: number) => (
                <div key={i} className="p-3 bg-red-500/10 rounded-lg">
                  <span className="badge badge-danger mr-2">{pattern.type}</span>
                  <span className="text-white">{pattern.keyword}</span>
                  {pattern.description && (
                    <p className="text-gray-400 text-xs mt-1">{pattern.description}</p>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Document Screenshots */}
      {screenshots.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Camera className="h-5 w-5 text-primary-500" />
            Document Preview ({screenshots.length} pages)
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {screenshots.slice(0, 10).map((screenshot: string, i: number) => (
              <ScreenshotThumbnail
                key={i}
                src={`data:image/png;base64,${screenshot}`}
                alt={`Page ${i + 1}`}
                label={`Page ${i + 1}`}
              />
            ))}
          </div>
        </div>
      )}

      {/* URLs */}
      {urls.length > 0 && <UrlList urls={urls} title="Extracted URLs" />}
    </div>
  )
}

function QrCodeResultsView({ analysis }: { analysis: any }) {
  const qrCodes = analysis.qr_codes || analysis.qrCodes || []
  const suspicious = qrCodes.filter((qr: any) => qr.risk_indicators?.length > 0)

  return (
    <div className="space-y-6">
      {/* Summary */}
      <div className="card">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <QrCode className="h-5 w-5 text-primary-500" />
          QR Code Analysis
        </h3>
        <div className="grid grid-cols-3 gap-4">
          <StatBox label="Found" value={qrCodes.length} color="blue" />
          <StatBox label="With URLs" value={qrCodes.filter((q: any) => q.urls?.length > 0).length} color="purple" />
          <StatBox label="Suspicious" value={suspicious.length} color={suspicious.length > 0 ? 'red' : 'green'} />
        </div>
      </div>

      {/* Individual QR Codes */}
      {qrCodes.map((qr: any, i: number) => {
        const hasSuspicious = qr.risk_indicators?.length > 0
        return (
          <div key={i} className={`card ${hasSuspicious ? 'glow-red' : ''}`}>
            <div className="flex items-center gap-2 mb-4">
              <span className="badge badge-info">QR Code {i + 1}</span>
              <span className="badge badge-neutral">{qr.data_type || qr.type || 'Text'}</span>
              {hasSuspicious && <span className="badge badge-danger">Suspicious</span>}
            </div>

            <div className="p-3 bg-dark-500 rounded-lg mb-4">
              <code className="text-primary-400 text-sm break-all">{qr.raw_data || qr.data}</code>
            </div>

            {qr.urls?.length > 0 && (
              <div className="mb-4">
                <span className="text-gray-400 text-sm">URLs Found (defanged):</span>
                <div className="mt-2 space-y-1">
                  {qr.urls.map((url: string, j: number) => (
                    <code key={j} className="block p-2 bg-dark-600 rounded text-orange-400 text-xs break-all select-all" title="Defanged URL">
                      {defangUrl(url)}
                    </code>
                  ))}
                </div>
              </div>
            )}

            {qr.risk_indicators?.map((indicator: any, j: number) => (
              <div key={j} className="flex items-center gap-2 p-2 bg-red-500/10 rounded text-red-400 text-sm">
                <AlertTriangle className="h-4 w-4" />
                {indicator.description}
              </div>
            ))}
          </div>
        )
      })}
    </div>
  )
}

function SandboxResultsView({ analysis, riskScore }: { analysis: any; riskScore: number }) {
  const behavior = analysis.behaviorSummary || analysis.behavior_summary || {}
  const processTree = analysis.processTree || analysis.process_tree || []
  const network = analysis.networkConnections || analysis.network_connections || []
  const files = analysis.filesystemChanges || analysis.filesystem_changes || {}
  const iocs = analysis.extractedIocs || analysis.extracted_iocs || {}

  return (
    <div className="space-y-6">
      {/* Risk and Summary */}
      <div className="grid md:grid-cols-3 gap-6">
        <div className="card flex items-center justify-center">
          <RiskGauge score={riskScore} size="lg" />
        </div>
        <div className="card md:col-span-2">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Terminal className="h-5 w-5 text-primary-500" />
            Sandbox Analysis
          </h3>
          <div className="flex flex-wrap gap-2 mb-4">
            <span className={`badge ${riskScore >= 50 ? 'badge-danger' : riskScore >= 20 ? 'badge-warning' : 'badge-success'}`}>
              {analysis.riskLevel || 'Unknown'} Risk
            </span>
            <span className="badge badge-info">{analysis.backend || 'sandbox'}</span>
          </div>
          <div className="grid grid-cols-4 gap-2">
            <StatBox label="Processes" value={behavior.processCount || 0} color="blue" />
            <StatBox label="Files" value={behavior.fileOperations || 0} color="green" />
            <StatBox label="Network" value={behavior.networkConnections || 0} color="purple" />
            <StatBox label="Suspicious" value={behavior.suspiciousActivities || 0} color={behavior.suspiciousActivities > 0 ? 'red' : 'gray'} />
          </div>
        </div>
      </div>

      {/* Process Tree */}
      {processTree.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Terminal className="h-5 w-5 text-primary-500" />
            Process Tree
          </h3>
          <div className="space-y-2 max-h-60 overflow-y-auto">
            {processTree.map((proc: any, i: number) => (
              <div key={i} className="p-3 bg-dark-500 rounded-lg">
                <div className="flex items-center gap-2">
                  <span className="badge badge-info">{proc.pid || '?'}</span>
                  <code className="text-white text-sm font-mono">{proc.name || proc.command}</code>
                </div>
                {proc.children?.map((child: any, j: number) => (
                  <div key={j} className="ml-6 mt-2 text-gray-400 text-sm font-mono">
                    └─ [{child.pid || '?'}] {child.name || child.command}
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Network Connections */}
      {network.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Globe className="h-5 w-5 text-primary-500" />
            Network Connections ({network.length})
          </h3>
          <div className="space-y-2 max-h-40 overflow-y-auto">
            {network.map((conn: any, i: number) => (
              <div key={i} className="flex items-center gap-2 p-2 bg-dark-500 rounded">
                <span className="badge badge-info">{conn.protocol || 'TCP'}</span>
                <code className="text-orange-400 text-sm select-all" title="Defanged IP">
                  {defangIp(conn.remoteIp || conn.ip)}:{conn.remotePort || conn.port}
                </code>
                {conn.domain && <span className="text-gray-400 text-xs">({defangDomain(conn.domain)})</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* File Changes */}
      {(files.created?.length > 0 || files.modified?.length > 0 || files.deleted?.length > 0) && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <FileText className="h-5 w-5 text-primary-500" />
            Filesystem Changes
          </h3>
          {files.created?.length > 0 && (
            <div className="mb-4">
              <h4 className="text-green-400 font-semibold text-sm mb-2">Created ({files.created.length})</h4>
              <div className="space-y-1 max-h-20 overflow-y-auto">
                {files.created.slice(0, 10).map((f: string, i: number) => (
                  <code key={i} className="block text-green-400 text-xs">{f}</code>
                ))}
              </div>
            </div>
          )}
          {files.modified?.length > 0 && (
            <div className="mb-4">
              <h4 className="text-yellow-400 font-semibold text-sm mb-2">Modified ({files.modified.length})</h4>
              <div className="space-y-1 max-h-20 overflow-y-auto">
                {files.modified.slice(0, 10).map((f: string, i: number) => (
                  <code key={i} className="block text-yellow-400 text-xs">{f}</code>
                ))}
              </div>
            </div>
          )}
          {files.deleted?.length > 0 && (
            <div>
              <h4 className="text-red-400 font-semibold text-sm mb-2">Deleted ({files.deleted.length})</h4>
              <div className="space-y-1 max-h-20 overflow-y-auto">
                {files.deleted.slice(0, 10).map((f: string, i: number) => (
                  <code key={i} className="block text-red-400 text-xs">{f}</code>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* IOCs */}
      {(iocs.ips?.length > 0 || iocs.domains?.length > 0 || iocs.urls?.length > 0) && (
        <IocDisplay iocs={iocs} />
      )}
    </div>
  )
}

function GenericResultsView({ analysis, riskScore }: { analysis: any; riskScore: number }) {
  return (
    <div className="space-y-6">
      <div className="grid md:grid-cols-3 gap-6">
        <div className="card flex items-center justify-center">
          <RiskGauge score={riskScore} size="lg" />
        </div>
        <div className="card md:col-span-2">
          <h3 className="text-lg font-semibold mb-4">Analysis Results</h3>
          <pre className="p-4 bg-dark-500 rounded-lg text-sm text-gray-300 overflow-auto max-h-96">
            {JSON.stringify(analysis, null, 2)}
          </pre>
        </div>
      </div>
    </div>
  )
}

// Helper Components
function InfoRow({ label, value }: { label: string; value: any }) {
  return (
    <div className="flex justify-between items-center py-2 border-b border-dark-300 last:border-0">
      <span className="text-gray-400 text-sm">{label}</span>
      <span className="text-white font-medium text-right max-w-xs truncate">{value || '-'}</span>
    </div>
  )
}

function StatBox({ label, value, color }: { label: string; value: number; color: string }) {
  const colors: Record<string, string> = {
    red: 'from-red-500/20 to-red-900/20 border-red-500/30 text-red-400',
    orange: 'from-orange-500/20 to-orange-900/20 border-orange-500/30 text-orange-400',
    green: 'from-green-500/20 to-green-900/20 border-green-500/30 text-green-400',
    blue: 'from-blue-500/20 to-blue-900/20 border-blue-500/30 text-blue-400',
    purple: 'from-purple-500/20 to-purple-900/20 border-purple-500/30 text-purple-400',
    gray: 'from-gray-500/20 to-gray-900/20 border-gray-500/30 text-gray-400',
  }

  return (
    <div className={`p-3 rounded-xl bg-gradient-to-br border text-center ${colors[color]}`}>
      <div className="text-2xl font-bold">{value}</div>
      <div className="text-xs text-gray-400">{label}</div>
    </div>
  )
}

function UrlList({ urls, title }: { urls: string[]; title: string }) {
  return (
    <div className="card">
      <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
        <Link className="h-5 w-5 text-primary-500" />
        {title} ({urls.length})
      </h3>
      <div className="space-y-2 max-h-60 overflow-y-auto">
        {urls.slice(0, 50).map((url, i) => (
          <code key={i} className="block p-2 bg-dark-500 rounded text-orange-400 text-xs break-all select-all" title="Defanged URL - safe to copy">
            {defangUrl(url)}
          </code>
        ))}
      </div>
    </div>
  )
}

function IocDisplay({ iocs }: { iocs: any }) {
  return (
    <div className="card">
      <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
        <Globe className="h-5 w-5 text-primary-500" />
        Extracted IOCs
        <span className="text-xs text-gray-500 font-normal ml-2">(defanged for safety)</span>
      </h3>

      {iocs.ips?.length > 0 && (
        <div className="mb-4">
          <h4 className="text-orange-400 text-sm font-semibold mb-2">IP Addresses ({iocs.ips.length})</h4>
          <div className="flex flex-wrap gap-2">
            {iocs.ips.map((ip: string, i: number) => (
              <span key={i} className="badge badge-warning select-all" title="Defanged IP">{defangIp(ip)}</span>
            ))}
          </div>
        </div>
      )}

      {iocs.domains?.length > 0 && (
        <div className="mb-4">
          <h4 className="text-blue-400 text-sm font-semibold mb-2">Domains ({iocs.domains.length})</h4>
          <div className="flex flex-wrap gap-2">
            {iocs.domains.map((domain: string, i: number) => (
              <span key={i} className="badge badge-info select-all" title="Defanged domain">{defangDomain(domain)}</span>
            ))}
          </div>
        </div>
      )}

      {iocs.urls?.length > 0 && (
        <div>
          <h4 className="text-primary-400 text-sm font-semibold mb-2">URLs ({iocs.urls.length})</h4>
          <div className="space-y-1 max-h-32 overflow-y-auto">
            {iocs.urls.slice(0, 20).map((url: string, i: number) => (
              <code key={i} className="block p-2 bg-dark-500 rounded text-orange-400 text-xs break-all select-all" title="Defanged URL">
                {defangUrl(url)}
              </code>
            ))}
          </div>
        </div>
      )}
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
