// IP Lookup Types - Matches actual backend response
export interface IpLookupResult {
  ip: string;
  location: {
    continent?: string;
    continentCode?: string;
    country?: string;
    countryCode?: string;
    region?: string;
    regionCode?: string;
    city?: string;
    district?: string;
    zipCode?: string;
    latitude?: number;
    longitude?: number;
    timezone?: string;
    utcOffset?: number;
  };
  network: {
    isp?: string;
    organization?: string;
    asn?: string;
    asName?: string;
    hostname?: string;
  };
  security: {
    isMobile?: boolean;
    isProxy?: boolean;
    isHosting?: boolean;
  };
  threat: {
    abuseScore?: number;
    totalReports?: number;
    lastReported?: string | null;
    isWhitelisted?: boolean;
    categories?: string[];
    recentReports?: string[];
    riskLevel?: string;
    apiConfigured?: boolean;
  };
  currency?: string;
}

export interface ThreatInfo {
  is_threat: boolean;
  is_vpn: boolean;
  is_proxy: boolean;
  is_tor: boolean;
  is_hosting: boolean;
  risk_score: number;
}

// File Analysis Types
export type FileType = 'email' | 'pdf' | 'office' | 'qrcode';

export interface AnalysisResponse {
  success: boolean;
  entryRef?: string;
  entry_ref?: string;
  message?: string;
  error?: string;
}

export interface BaseResults {
  entry_ref?: string;
  entryRef?: string;
  file_type?: FileType;
  fileType?: string;
  filename?: string;
  fileName?: string;
  file_size?: number;
  fileSize?: number;
  analyzed_at?: string;
  analyzedAt?: string;
  iocInvestigation?: IocInvestigation;
}

export interface EmailResults extends BaseResults {
  file_type?: 'email';
  type?: string;
  subject?: string;
  from?: string;
  to?: string | string[];
  cc?: string | string[];
  date?: string;
  headers?: {
    from?: string;
    to?: string;
    subject?: string;
    date?: string;
    message_id?: string;
    reply_to?: string;
    return_path?: string;
  };
  body_text?: string;
  bodyText?: string;
  body_html?: string;
  bodyHtml?: string;
  attachments?: Array<{
    filename: string;
    content_type?: string;
    contentType?: string;
    size: number;
    suspicious?: boolean;
    is_suspicious?: boolean;
  }>;
  attachmentCount?: number;
  urls?: string[];
  urlCount?: number;
  enrichedUrls?: Array<{
    url: string;
    domain?: string;
    suspicious?: boolean;
    download?: any;
  }>;
  ip_addresses?: string[];
  ipAddresses?: string[];
  routingPath?: string[];
  routingIps?: Array<{
    ip: string;
    info?: any;
    threat?: any;
  }>;
  senderDomain?: string;
  senderDomainInfo?: any;
  security_indicators?: {
    spf?: string;
    dkim?: string;
    dmarc?: string;
  };
  securityIndicators?: {
    spf?: string;
    dkim?: string;
    dmarc?: string;
  };
  authentication?: {
    spf?: any;
    dkim?: any;
    dmarc?: any;
  };
  phishingIndicators?: Array<any>;
  phishing_indicators?: Array<any>;
  riskScore?: number;
  risk_score?: number;
  riskLevel?: string;
  risk_level?: string;
  qrCodes?: Array<any>;
  qrCodeCount?: number;
}

export interface PdfResults extends BaseResults {
  file_type?: 'pdf';
  type?: string;
  metadata?: {
    author?: string;
    creator?: string;
    producer?: string;
    subject?: string;
    title?: string;
    creationDate?: string;
    modDate?: string;
  };
  title?: string;
  author?: string;
  creator?: string;
  producer?: string;
  creation_date?: string;
  creationDate?: string;
  modification_date?: string;
  modificationDate?: string;
  page_count?: number;
  pageCount?: number;
  encrypted?: boolean;
  has_javascript?: boolean;
  hasJavaScript?: boolean;
  javascript?: string[];
  has_embedded_files?: boolean;
  hasEmbeddedFiles?: boolean;
  embeddedFiles?: Array<any>;
  has_forms?: boolean;
  hasForms?: boolean;
  forms?: string[];
  has_external_refs?: boolean;
  hasExternalRefs?: boolean;
  externalReferences?: Array<any>;
  urls?: string[];
  urlCount?: number;
  enrichedUrls?: Array<any>;
  httpRequests?: Array<any>;
  downloadUrls?: Array<any>;
  processTriggers?: Array<any>;
  qrCodes?: Array<any>;
  qrCodeCount?: number;
  suspicious_elements?: string[];
  suspiciousElements?: string[];
  riskScore?: number;
  risk_score?: number;
  riskLevel?: string;
  risk_level?: string;
}

export interface OfficeResults extends BaseResults {
  file_type?: 'office';
  type?: string;
  document_type?: string;
  documentType?: string;
  title?: string;
  author?: string;
  last_modified_by?: string;
  lastModifiedBy?: string;
  created?: string;
  modified?: string;
  revision?: number;
  has_macros?: boolean;
  hasMacros?: boolean;
  macros?: Array<{
    filename: string;
    streamPath?: string;
    codePreview?: string;
    codeLength?: number;
  }>;
  autoExecution?: Array<{
    trigger: string;
    location?: string;
  }>;
  auto_execution?: Array<{
    trigger: string;
    location?: string;
  }>;
  suspiciousPatterns?: Array<{
    type: string;
    keyword: string;
    description?: string;
  }>;
  suspicious_patterns?: Array<{
    type: string;
    keyword: string;
    description?: string;
  }>;
  macro_analysis?: {
    suspicious_keywords?: string[];
    suspiciousKeywords?: string[];
    auto_exec?: boolean;
    autoExec?: boolean;
    obfuscated?: boolean;
  };
  macroAnalysis?: {
    suspicious_keywords?: string[];
    suspiciousKeywords?: string[];
    auto_exec?: boolean;
    autoExec?: boolean;
    obfuscated?: boolean;
  };
  external_links?: string[];
  externalLinks?: string[];
  externalReferences?: Array<any>;
  external_references?: Array<any>;
  embedded_objects?: Array<any>;
  embeddedObjects?: Array<any>;
  urls?: string[];
  enrichedUrls?: Array<any>;
  enriched_urls?: Array<any>;
  httpRequests?: Array<any>;
  http_requests?: Array<any>;
  processTriggers?: Array<any>;
  process_triggers?: Array<any>;
  downloadTargets?: Array<any>;
  download_targets?: Array<any>;
  metadata?: Record<string, string>;
  riskScore?: number;
  risk_score?: number;
  riskLevel?: string;
  risk_level?: string;
}

export interface QrCodeResults extends BaseResults {
  file_type?: 'qrcode';
  type?: string;
  qr_codes?: Array<{
    data: string;
    type: string;
    raw_data?: string;
    data_type?: string;
    urls?: string[];
    risk_indicators?: Array<{
      type: string;
      severity: string;
      description: string;
    }>;
    rect?: {
      left: number;
      top: number;
      width: number;
      height: number;
    };
  }>;
  qrCodes?: Array<{
    data: string;
    type: string;
    raw_data?: string;
    data_type?: string;
    urls?: string[];
    risk_indicators?: Array<{
      type: string;
      severity: string;
      description: string;
    }>;
    rect?: {
      left: number;
      top: number;
      width: number;
      height: number;
    };
  }>;
  total_codes?: number;
  totalCodes?: number;
}

export type AnalysisResults = EmailResults | PdfResults | OfficeResults | QrCodeResults;

export interface RetrieveResponse {
  success: boolean;
  results?: AnalysisResults;
  entryRef?: string;
  entry_ref?: string;
  fileType?: string;
  file_type?: string;
  filename?: string;
  fileSize?: number;
  file_size?: number;
  analyzedAt?: string;
  analyzed_at?: string;
  error?: string;
}

// IOC Investigation Types
export interface IocInvestigationSummary {
  isMalicious: boolean;
  totalSources: number;
  maliciousSources: number;
  riskScore: number;
  findings: string[];
}

export interface IocInvestigationResult {
  investigatedAt: string;
  sources: Record<string, any>;
  summary: IocInvestigationSummary;
}

export interface IpInvestigation extends IocInvestigationResult {
  ip: string;
}

export interface UrlInvestigation extends IocInvestigationResult {
  url: string;
}

export interface HashInvestigation extends IocInvestigationResult {
  hash: string;
}

export interface IocInvestigation {
  investigatedAt: string;
  ips: IpInvestigation[];
  urls: UrlInvestigation[];
  hashes: HashInvestigation[];
  summary: {
    totalIOCs: number;
    maliciousIOCs: number;
    overallRiskScore: number;
  };
}

export interface ThreatIntelService {
  enabled: boolean;
  configured: boolean;
  needsKey: boolean;
  description: string;
  rateLimit: string;
}

export interface ThreatIntelStatus {
  available: boolean;
  services: Record<string, ThreatIntelService>;
}

// UI Types
export type TabType = 'ip-lookup' | 'url-lookup' | 'hash-lookup' | 'sandbox';

export interface ApiStatus {
  status: string;
  version?: string;
  uptime?: number;
  features?: {
    qrCodeDetection?: boolean;
    threatIntel?: boolean;
  };
}
