import type { FileType } from '../types';

export const FILE_TYPE_CONFIG: Record<FileType, {
  extensions: string[];
  mimeTypes: string[];
  maxSize: number;
  label: string;
}> = {
  email: {
    extensions: ['.eml', '.msg'],
    mimeTypes: ['message/rfc822', 'application/vnd.ms-outlook'],
    maxSize: 25 * 1024 * 1024, // 25MB
    label: 'Email',
  },
  pdf: {
    extensions: ['.pdf'],
    mimeTypes: ['application/pdf'],
    maxSize: 50 * 1024 * 1024, // 50MB
    label: 'PDF',
  },
  office: {
    extensions: ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp'],
    mimeTypes: [
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/vnd.ms-powerpoint',
      'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      'application/vnd.oasis.opendocument.text',
      'application/vnd.oasis.opendocument.spreadsheet',
      'application/vnd.oasis.opendocument.presentation',
    ],
    maxSize: 50 * 1024 * 1024, // 50MB
    label: 'Office Document',
  },
  qrcode: {
    extensions: ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'],
    mimeTypes: ['image/png', 'image/jpeg', 'image/gif', 'image/bmp', 'image/webp'],
    maxSize: 10 * 1024 * 1024, // 10MB
    label: 'Image (QR Code)',
  },
};

export const validateFile = (file: File, fileType: FileType): { valid: boolean; error?: string } => {
  const config = FILE_TYPE_CONFIG[fileType];

  if (!config) {
    return { valid: false, error: 'Invalid file type selected' };
  }

  // Check file size
  if (file.size > config.maxSize) {
    const maxSizeMB = config.maxSize / (1024 * 1024);
    return { valid: false, error: `File size exceeds ${maxSizeMB}MB limit` };
  }

  // Check extension
  const fileName = file.name.toLowerCase();
  const hasValidExtension = config.extensions.some(ext => fileName.endsWith(ext));

  if (!hasValidExtension) {
    return {
      valid: false,
      error: `Invalid file extension. Allowed: ${config.extensions.join(', ')}`
    };
  }

  return { valid: true };
};

export const isValidIpAddress = (ip: string): boolean => {
  // IPv4
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

  // IPv6
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$|^(?:[0-9a-fA-F]{1,4}:){0,6}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$/;

  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
};

export const isValidEntryRef = (ref: string): boolean => {
  // Entry refs should be alphanumeric with possible dashes
  return /^[a-zA-Z0-9-]{8,64}$/.test(ref);
};

export const detectFileType = (file: File): FileType | null => {
  const fileName = file.name.toLowerCase();

  for (const [type, config] of Object.entries(FILE_TYPE_CONFIG)) {
    if (config.extensions.some(ext => fileName.endsWith(ext))) {
      return type as FileType;
    }
  }

  return null;
};
