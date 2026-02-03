import { useState } from 'react';
import { Header } from './components/layout/Header';
import { Navigation } from './components/layout/Navigation';
import { Footer } from './components/layout/Footer';
import { IpLookup } from './components/ip-lookup/IpLookup';
import { UrlLookup } from './components/lookup/UrlLookup';
import { HashLookup } from './components/lookup/HashLookup';
import { Sandbox } from './components/sandbox/Sandbox';
import type { TabType } from './types';

function App() {
  const [activeTab, setActiveTab] = useState<TabType>('ip-lookup');

  return (
    <div className="min-h-screen bg-gradient-to-br from-black via-red-950/20 to-black">
      <div className="max-w-5xl mx-auto px-4 pb-8">
        <Header />
        <Navigation activeTab={activeTab} onTabChange={setActiveTab} />

        <main className="animate-fade-in">
          {activeTab === 'ip-lookup' && <IpLookup />}
          {activeTab === 'url-lookup' && <UrlLookup />}
          {activeTab === 'hash-lookup' && <HashLookup />}
          {activeTab === 'sandbox' && <Sandbox />}
        </main>

        <Footer />
      </div>
    </div>
  );
}

export default App;
