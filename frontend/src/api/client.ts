import axios from 'axios';
import type {
  IpLookupResult,
  AnalysisResponse,
  RetrieveResponse,
  ApiStatus,
  FileType,
  IpInvestigation
} from '../types';

const api = axios.create({
  baseURL: '/api',
  timeout: 60000,
});

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    const message = error.response?.data?.error || error.message || 'An error occurred';
    return Promise.reject(new Error(message));
  }
);

export const getVisitorIp = async (): Promise<string> => {
  const response = await api.get<{ ip: string }>('/my-ip');
  return response.data.ip;
};

export const lookupIp = async (ip?: string): Promise<IpLookupResult> => {
  const url = ip ? `/lookup/${encodeURIComponent(ip)}` : '/lookup';
  const response = await api.get<IpLookupResult>(url);
  return response.data;
};

export const analyzeFile = async (
  type: FileType,
  file: File,
  secretKey: string
): Promise<AnalysisResponse> => {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('secretKey', secretKey);

  const response = await api.post<AnalysisResponse>(`/analyze/${type}`, formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
  return response.data;
};

export const retrieveResults = async (
  entryRef: string,
  secretKey: string
): Promise<RetrieveResponse> => {
  const response = await api.post<RetrieveResponse>(`/results/${encodeURIComponent(entryRef)}`, {
    secretKey,
  });
  return response.data;
};

export const getStatus = async (): Promise<ApiStatus> => {
  const response = await api.get<ApiStatus>('/status');
  return response.data;
};

export const investigateIp = async (ip: string): Promise<IpInvestigation> => {
  const response = await api.post<IpInvestigation>('/threat-intel/investigate/ip', { ip });
  return response.data;
};

export const investigateUrl = async (url: string): Promise<any> => {
  const response = await api.post('/threat-intel/investigate/url', { url });
  return response.data;
};

export const investigateHash = async (hash: string): Promise<any> => {
  const response = await api.post('/threat-intel/investigate/hash', { hash });
  return response.data;
};

export default api;
