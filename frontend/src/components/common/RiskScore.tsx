import { getRiskColor, formatRiskScore } from '../../utils/formatters';

interface RiskScoreProps {
  score: number;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
}

const sizeConfig = {
  sm: { diameter: 60, strokeWidth: 4, fontSize: 'text-sm' },
  md: { diameter: 100, strokeWidth: 6, fontSize: 'text-xl' },
  lg: { diameter: 140, strokeWidth: 8, fontSize: 'text-3xl' },
};

export const RiskScore = ({ score, size = 'md', showLabel = true }: RiskScoreProps) => {
  const config = sizeConfig[size];
  const radius = (config.diameter - config.strokeWidth) / 2;
  const circumference = radius * 2 * Math.PI;
  const offset = circumference - (score / 100) * circumference;

  const getStrokeColor = (score: number): string => {
    if (score <= 20) return '#00c853';
    if (score <= 50) return '#ffc107';
    if (score <= 75) return '#ff9800';
    return '#ff5252';
  };

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative" style={{ width: config.diameter, height: config.diameter }}>
        {/* Background circle */}
        <svg
          className="absolute transform -rotate-90"
          width={config.diameter}
          height={config.diameter}
        >
          <circle
            cx={config.diameter / 2}
            cy={config.diameter / 2}
            r={radius}
            stroke="currentColor"
            strokeWidth={config.strokeWidth}
            fill="none"
            className="text-white/10"
          />
        </svg>

        {/* Progress circle */}
        <svg
          className="absolute transform -rotate-90"
          width={config.diameter}
          height={config.diameter}
        >
          <circle
            cx={config.diameter / 2}
            cy={config.diameter / 2}
            r={radius}
            stroke={getStrokeColor(score)}
            strokeWidth={config.strokeWidth}
            fill="none"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            className="transition-all duration-500 ease-out"
          />
        </svg>

        {/* Score text */}
        <div
          className="absolute inset-0 flex items-center justify-center"
        >
          <span className={`font-bold ${config.fontSize} ${getRiskColor(score)}`}>
            {score}
          </span>
        </div>
      </div>

      {showLabel && (
        <span className={`text-sm font-medium ${getRiskColor(score)}`}>
          {formatRiskScore(score)} Risk
        </span>
      )}
    </div>
  );
};
