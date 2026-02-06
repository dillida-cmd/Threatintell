import { Brain, CheckCircle, AlertTriangle, XCircle, Shield, ChevronDown, ChevronUp } from 'lucide-react'
import { useState } from 'react'

interface AIValidationProps {
  validation: {
    originalScore: number
    validatedScore: number
    originalMalicious?: boolean
    validatedMalicious?: boolean
    validatedRiskLevel?: string
    confidence: number
    recommendation: string
    reasoning: string[]
    factors: {
      positive: string[]
      negative: string[]
      neutral: string[]
    }
    falsePositiveIndicators?: string[]
    threatIndicators?: Array<{
      source: string
      type: string
      severity: string
    }>
    mitreAttacks?: Array<{
      id: string
      name: string
      severity: string
    }>
    malwareFamily?: string
  }
  compact?: boolean
}

export default function AIValidation({ validation, compact = false }: AIValidationProps) {
  const [expanded, setExpanded] = useState(!compact)

  const scoreChanged = validation.originalScore !== validation.validatedScore
  const scoreDiff = validation.validatedScore - validation.originalScore

  const getScoreColor = (score: number) => {
    if (score >= 70) return 'text-red-500'
    if (score >= 40) return 'text-orange-500'
    if (score >= 20) return 'text-yellow-500'
    return 'text-green-500'
  }

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 80) return 'text-green-500'
    if (confidence >= 60) return 'text-yellow-500'
    return 'text-orange-500'
  }

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-500/20 text-red-400 border-red-500/30'
      case 'high':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/30'
      case 'medium':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
      default:
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30'
    }
  }

  return (
    <div className="card bg-gradient-to-br from-dark-400/50 to-dark-500/50 border border-primary-500/20">
      {/* Header */}
      <div
        className="flex items-center justify-between cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary-500/20 rounded-lg">
            <Brain className="h-5 w-5 text-primary-400" />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-white">AI Risk Validation</h3>
            <p className="text-xs text-gray-400">Consensus-based threat analysis</p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          {/* Confidence Badge */}
          <div className="text-center">
            <div className={`text-xl font-bold ${getConfidenceColor(validation.confidence)}`}>
              {validation.confidence}%
            </div>
            <div className="text-xs text-gray-500">Confidence</div>
          </div>

          {/* Validated Score */}
          <div className="text-center">
            <div className="flex items-center gap-2">
              <span className={`text-2xl font-bold ${getScoreColor(validation.validatedScore)}`}>
                {validation.validatedScore}
              </span>
              {scoreChanged && (
                <span className={`text-sm ${scoreDiff < 0 ? 'text-green-400' : 'text-red-400'}`}>
                  ({scoreDiff > 0 ? '+' : ''}{scoreDiff})
                </span>
              )}
            </div>
            <div className="text-xs text-gray-500">AI Score</div>
          </div>

          {expanded ? (
            <ChevronUp className="h-5 w-5 text-gray-400" />
          ) : (
            <ChevronDown className="h-5 w-5 text-gray-400" />
          )}
        </div>
      </div>

      {/* Expanded Content */}
      {expanded && (
        <div className="mt-4 space-y-4 border-t border-dark-300 pt-4">
          {/* Recommendation */}
          {validation.recommendation && (
            <div className={`p-3 rounded-lg ${
              validation.validatedScore >= 70 ? 'bg-red-500/10 border border-red-500/30' :
              validation.validatedScore >= 40 ? 'bg-orange-500/10 border border-orange-500/30' :
              validation.validatedScore >= 20 ? 'bg-yellow-500/10 border border-yellow-500/30' :
              'bg-green-500/10 border border-green-500/30'
            }`}>
              <div className="flex items-start gap-2">
                {validation.validatedScore >= 70 ? (
                  <XCircle className="h-5 w-5 text-red-500 flex-shrink-0 mt-0.5" />
                ) : validation.validatedScore >= 40 ? (
                  <AlertTriangle className="h-5 w-5 text-orange-500 flex-shrink-0 mt-0.5" />
                ) : (
                  <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0 mt-0.5" />
                )}
                <p className={`text-sm font-medium ${
                  validation.validatedScore >= 70 ? 'text-red-300' :
                  validation.validatedScore >= 40 ? 'text-orange-300' :
                  'text-green-300'
                }`}>
                  {validation.recommendation}
                </p>
              </div>
            </div>
          )}

          {/* Malware Family */}
          {validation.malwareFamily && (
            <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
              <span className="text-red-400 text-sm font-semibold">Identified Malware: </span>
              <span className="text-red-300">{validation.malwareFamily}</span>
            </div>
          )}

          {/* MITRE ATT&CK Techniques */}
          {validation.mitreAttacks && validation.mitreAttacks.length > 0 && (
            <div>
              <h4 className="text-sm font-semibold text-gray-300 mb-2 flex items-center gap-2">
                <Shield className="h-4 w-4" /> MITRE ATT&CK Techniques
              </h4>
              <div className="flex flex-wrap gap-2">
                {validation.mitreAttacks.map((attack, i) => (
                  <span
                    key={i}
                    className={`px-2 py-1 rounded text-xs border ${getSeverityBadge(attack.severity)}`}
                  >
                    {attack.id}: {attack.name}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Factors Grid */}
          <div className="grid md:grid-cols-3 gap-3">
            {/* Positive Factors */}
            {validation.factors.positive.length > 0 && (
              <div className="p-3 bg-green-500/5 border border-green-500/20 rounded-lg">
                <h4 className="text-green-400 text-xs font-semibold mb-2 flex items-center gap-1">
                  <CheckCircle className="h-3 w-3" /> Clean Indicators
                </h4>
                <ul className="space-y-1">
                  {validation.factors.positive.map((factor, i) => (
                    <li key={i} className="text-xs text-green-300/80">{factor}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Negative Factors */}
            {validation.factors.negative.length > 0 && (
              <div className="p-3 bg-red-500/5 border border-red-500/20 rounded-lg">
                <h4 className="text-red-400 text-xs font-semibold mb-2 flex items-center gap-1">
                  <XCircle className="h-3 w-3" /> Threat Indicators
                </h4>
                <ul className="space-y-1">
                  {validation.factors.negative.map((factor, i) => (
                    <li key={i} className="text-xs text-red-300/80">{factor}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Neutral Factors */}
            {validation.factors.neutral.length > 0 && (
              <div className="p-3 bg-gray-500/5 border border-gray-500/20 rounded-lg">
                <h4 className="text-gray-400 text-xs font-semibold mb-2 flex items-center gap-1">
                  <AlertTriangle className="h-3 w-3" /> Informational
                </h4>
                <ul className="space-y-1">
                  {validation.factors.neutral.map((factor, i) => (
                    <li key={i} className="text-xs text-gray-400">{factor}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* False Positive Indicators */}
          {validation.falsePositiveIndicators && validation.falsePositiveIndicators.length > 0 && (
            <div className="p-3 bg-yellow-500/5 border border-yellow-500/20 rounded-lg">
              <h4 className="text-yellow-400 text-xs font-semibold mb-2">False Positive Indicators</h4>
              <ul className="space-y-1">
                {validation.falsePositiveIndicators.map((indicator, i) => (
                  <li key={i} className="text-xs text-yellow-300/80">{indicator}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Threat Indicators Detail */}
          {validation.threatIndicators && validation.threatIndicators.length > 0 && (
            <div>
              <h4 className="text-sm font-semibold text-gray-300 mb-2">Confirmed Threat Indicators</h4>
              <div className="flex flex-wrap gap-2">
                {validation.threatIndicators.map((threat, i) => (
                  <span
                    key={i}
                    className={`px-2 py-1 rounded text-xs border ${getSeverityBadge(threat.severity)}`}
                  >
                    {threat.source}: {threat.type}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Reasoning */}
          {validation.reasoning && validation.reasoning.length > 0 && (
            <div className="text-xs text-gray-500 italic border-t border-dark-300 pt-3">
              {validation.reasoning.map((reason, i) => (
                <p key={i}>{reason}</p>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
