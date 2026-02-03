import type { ReactNode } from 'react';

interface CardProps {
  title?: string;
  icon?: ReactNode;
  children: ReactNode;
  className?: string;
}

export const Card = ({ title, icon, children, className = '' }: CardProps) => {
  return (
    <div
      className={`
        bg-black/80 backdrop-blur-sm
        border border-red-500/20 rounded-xl
        p-5 shadow-lg shadow-red-500/5
        animate-fade-in
        ${className}
      `}
    >
      {(title || icon) && (
        <div className="flex items-center gap-2 mb-4">
          {icon && <span className="text-primary">{icon}</span>}
          {title && <h3 className="text-lg font-semibold text-white">{title}</h3>}
        </div>
      )}
      {children}
    </div>
  );
};
