import { ShieldAlert, ShieldCheck, Shield } from 'lucide-react'

interface RiskGaugeProps {
  score: number
  size?: 'sm' | 'md' | 'lg'
}

export default function RiskGauge({ score, size = 'md' }: RiskGaugeProps) {
  const getColor = () => {
    if (score >= 70) return 'text-red-500'
    if (score >= 40) return 'text-orange-500'
    if (score >= 20) return 'text-yellow-500'
    return 'text-green-500'
  }

  const getBgColor = () => {
    if (score >= 70) return 'from-red-500/20 to-red-900/20 border-red-500/30'
    if (score >= 40) return 'from-orange-500/20 to-orange-900/20 border-orange-500/30'
    if (score >= 20) return 'from-yellow-500/20 to-yellow-900/20 border-yellow-500/30'
    return 'from-green-500/20 to-green-900/20 border-green-500/30'
  }

  const getLabel = () => {
    if (score >= 70) return 'Critical'
    if (score >= 40) return 'High'
    if (score >= 20) return 'Medium'
    return 'Low'
  }

  const getIcon = () => {
    if (score >= 40) return ShieldAlert
    if (score >= 20) return Shield
    return ShieldCheck
  }

  const sizes = {
    sm: { container: 'w-20 h-20', text: 'text-2xl', label: 'text-xs', icon: 'h-4 w-4' },
    md: { container: 'w-28 h-28', text: 'text-3xl', label: 'text-sm', icon: 'h-5 w-5' },
    lg: { container: 'w-36 h-36', text: 'text-4xl', label: 'text-base', icon: 'h-6 w-6' },
  }

  const Icon = getIcon()
  const s = sizes[size]

  return (
    <div className={`${s.container} relative flex flex-col items-center justify-center rounded-full bg-gradient-to-br ${getBgColor()} border-2`}>
      {/* Progress ring */}
      <svg className="absolute inset-0 -rotate-90" viewBox="0 0 100 100">
        <circle
          className="text-dark-400"
          strokeWidth="6"
          stroke="currentColor"
          fill="transparent"
          r="42"
          cx="50"
          cy="50"
        />
        <circle
          className={getColor()}
          strokeWidth="6"
          strokeDasharray={264}
          strokeDashoffset={264 - (264 * score) / 100}
          strokeLinecap="round"
          stroke="currentColor"
          fill="transparent"
          r="42"
          cx="50"
          cy="50"
          style={{ transition: 'stroke-dashoffset 0.5s ease' }}
        />
      </svg>

      {/* Content */}
      <div className="relative flex flex-col items-center">
        <span className={`${s.text} font-bold ${getColor()}`}>{score}</span>
        <div className={`flex items-center gap-1 ${getColor()}`}>
          <Icon className={s.icon} />
          <span className={`${s.label} font-semibold`}>{getLabel()}</span>
        </div>
      </div>
    </div>
  )
}
