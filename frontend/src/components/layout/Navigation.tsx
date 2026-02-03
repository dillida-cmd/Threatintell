import { Globe, Link, Hash, FileSearch } from 'lucide-react';
import type { TabType } from '../../types';

interface NavigationProps {
  activeTab: TabType;
  onTabChange: (tab: TabType) => void;
}

export const Navigation = ({ activeTab, onTabChange }: NavigationProps) => {
  const tabs: { id: TabType; label: string; icon: React.ReactNode }[] = [
    { id: 'ip-lookup', label: 'IP Lookup', icon: <Globe className="h-5 w-5" /> },
    { id: 'url-lookup', label: 'URL Lookup', icon: <Link className="h-5 w-5" /> },
    { id: 'hash-lookup', label: 'Hash Lookup', icon: <Hash className="h-5 w-5" /> },
    { id: 'sandbox', label: 'File Sandbox', icon: <FileSearch className="h-5 w-5" /> },
  ];

  return (
    <nav className="flex justify-center mb-8">
      <div className="inline-flex bg-black/60 border border-red-500/30 rounded-xl p-1.5">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => onTabChange(tab.id)}
            className={`
              flex items-center gap-2 px-5 py-2.5 rounded-lg
              font-medium text-sm transition-all duration-200
              ${
                activeTab === tab.id
                  ? 'bg-primary text-white shadow-lg shadow-red-500/25'
                  : 'text-gray-400 hover:text-white hover:bg-red-500/10'
              }
            `}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>
    </nav>
  );
};
