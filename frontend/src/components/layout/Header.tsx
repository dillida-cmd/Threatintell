import { Shield } from 'lucide-react';

export const Header = () => {
  return (
    <header className="text-center py-8 px-4">
      <div className="flex items-center justify-center gap-3 mb-3">
        <Shield className="h-10 w-10 text-primary" />
        <h1 className="text-3xl md:text-4xl font-bold text-white">
          Threatintell
        </h1>
      </div>
      <p className="text-gray-400 text-lg max-w-2xl mx-auto">
        Threat Intelligence Platform & File Analysis Sandbox
      </p>
    </header>
  );
};
