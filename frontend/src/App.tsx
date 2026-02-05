import { useState } from 'react'
import { Shield, Globe, Link, Hash, FileSearch, Menu, X, Search } from 'lucide-react'
import IpLookup from './pages/IpLookup'
import UrlLookup from './pages/UrlLookup'
import HashLookup from './pages/HashLookup'
import FileAnalysis from './pages/FileAnalysis'
import RetrieveAnalysis from './pages/RetrieveAnalysis'

type Page = 'ip' | 'url' | 'hash' | 'file' | 'retrieve'

function App() {
  const [activePage, setActivePage] = useState<Page>('ip')
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  const navItems = [
    { id: 'ip' as Page, label: 'IP Lookup', icon: Globe },
    { id: 'url' as Page, label: 'URL Lookup', icon: Link },
    { id: 'hash' as Page, label: 'Hash Lookup', icon: Hash },
    { id: 'file' as Page, label: 'File Analysis', icon: FileSearch },
    { id: 'retrieve' as Page, label: 'Retrieve', icon: Search },
  ]

  const renderPage = () => {
    switch (activePage) {
      case 'ip':
        return <IpLookup />
      case 'url':
        return <UrlLookup />
      case 'hash':
        return <HashLookup />
      case 'file':
        return <FileAnalysis />
      case 'retrieve':
        return <RetrieveAnalysis />
      default:
        return <IpLookup />
    }
  }

  return (
    <div className="min-h-screen bg-dark-600 flex flex-col">
      {/* Header - Logo Only */}
      <header className="sticky top-0 z-50 glass border-b border-dark-100">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <div className="flex items-center gap-3">
              <div className="relative">
                <Shield className="h-10 w-10 text-primary-500" />
                <div className="absolute inset-0 blur-lg bg-primary-500/30 rounded-full" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-gradient">ShieldTier</h1>
                <p className="text-[10px] text-gray-500 -mt-1">powered by MTI</p>
              </div>
            </div>

            {/* Mobile Menu Button */}
            <button
              className="md:hidden p-2 text-gray-400 hover:text-white"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            >
              {mobileMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
            </button>
          </div>
        </div>
      </header>

      {/* Navigation Bar - Separate from Header */}
      <nav className="bg-dark-500 border-b border-dark-100">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center gap-1 py-2">
            {navItems.map((item) => (
              <button
                key={item.id}
                onClick={() => setActivePage(item.id)}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all duration-200 ${
                  activePage === item.id
                    ? 'bg-primary-600/20 text-primary-400 border border-primary-500/30'
                    : 'text-gray-400 hover:text-white hover:bg-dark-400'
                }`}
              >
                <item.icon className="h-4 w-4" />
                <span className="font-medium">{item.label}</span>
              </button>
            ))}
          </div>

          {/* Mobile Navigation */}
          {mobileMenuOpen && (
            <div className="md:hidden py-2 space-y-1">
              {navItems.map((item) => (
                <button
                  key={item.id}
                  onClick={() => {
                    setActivePage(item.id)
                    setMobileMenuOpen(false)
                  }}
                  className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
                    activePage === item.id
                      ? 'bg-primary-600/20 text-primary-400'
                      : 'text-gray-400 hover:text-white hover:bg-dark-400'
                  }`}
                >
                  <item.icon className="h-5 w-5" />
                  <span className="font-medium">{item.label}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      </nav>

      {/* Main Content */}
      <main className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 w-full">
        {renderPage()}
      </main>

      {/* Footer - Fixed at bottom */}
      <footer className="border-t border-dark-100 bg-dark-600">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <p className="text-gray-500 text-xs text-center">
            ShieldTier - Threat Intelligence Platform @2026
          </p>
        </div>
      </footer>
    </div>
  )
}

export default App
