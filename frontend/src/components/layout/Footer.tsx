import { Shield } from 'lucide-react';

export const Footer = () => {
  return (
    <footer className="mt-12 py-6 border-t border-white/10">
      <div className="max-w-6xl mx-auto px-4">
        <div className="flex items-center justify-center gap-2 text-sm text-gray-500">
          <Shield className="h-4 w-4 text-primary" />
          <p>Security Tools &copy; {new Date().getFullYear()}</p>
        </div>
      </div>
    </footer>
  );
};
