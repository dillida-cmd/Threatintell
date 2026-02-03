type BadgeVariant = 'safe' | 'warning' | 'danger' | 'info' | 'neutral';

interface BadgeProps {
  children: React.ReactNode;
  variant?: BadgeVariant;
  className?: string;
}

const variantStyles: Record<BadgeVariant, string> = {
  safe: 'bg-success/20 text-success border-success/30',
  warning: 'bg-warning/20 text-warning border-warning/30',
  danger: 'bg-danger/20 text-danger border-danger/30',
  info: 'bg-primary/20 text-primary border-primary/30',
  neutral: 'bg-white/10 text-gray-300 border-white/20',
};

export const Badge = ({ children, variant = 'neutral', className = '' }: BadgeProps) => {
  return (
    <span
      className={`
        inline-flex items-center px-2.5 py-0.5
        text-xs font-medium rounded-full
        border
        ${variantStyles[variant]}
        ${className}
      `}
    >
      {children}
    </span>
  );
};
