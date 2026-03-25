import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 120000,
})

// IP Lookup
export const lookupIp = async (ip: string) => {
  const [basicRes, threatRes] = await Promise.all([
    api.get(`/lookup/${ip}`),
    api.post('/threat-intel/investigate/ip', { ip }),
  ])
  return {
    basic: basicRes.data,
    threat: threatRes.data,
  }
}

// My Location (for globe)
export const getMyLocation = async () => {
  const response = await api.get('/my-location')
  return response.data
}

// URL Lookup - Threat Intel
export const lookupUrlThreat = async (url: string) => {
  const response = await api.post('/threat-intel/investigate/url', { url })
  return response.data
}

// URL Analysis - Sandbox with screenshots
export const analyzeUrl = async (url: string) => {
  const response = await api.post('/sandbox/url', {
    url,
    secretKey: 'shieldtier_default',
    mode: 'browser',
  })
  return response.data
}


// Hash Lookup
export const lookupHash = async (hash: string) => {
  const response = await api.post('/threat-intel/investigate/hash', { hash })
  return response.data
}

// File Analysis
export const analyzeFile = async (file: File, secretKey: string, pdfPassword?: string) => {
  const formData = new FormData()
  formData.append('file', file)
  formData.append('secretKey', secretKey)
  if (pdfPassword) {
    formData.append('pdfPassword', pdfPassword)
  }

  // Determine endpoint based on file type
  const ext = file.name.toLowerCase().split('.').pop() || ''
  let endpoint = '/analyze/email'

  if (['eml', 'msg'].includes(ext)) {
    endpoint = '/analyze/email'
  } else if (ext === 'pdf') {
    endpoint = '/analyze/pdf'
  } else if (['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp'].includes(ext)) {
    endpoint = '/analyze/office'
  } else if (['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'].includes(ext)) {
    endpoint = '/analyze/qrcode'
  } else if (['exe', 'dll', 'msi', 'sh', 'py', 'js', 'bat', 'ps1', 'vbs'].includes(ext)) {
    endpoint = '/sandbox/analyze'
  }

  const response = await api.post(endpoint, formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 300000,
  })
  return response.data
}

// Analyze attachment (for email attachments)
export const analyzeAttachment = async (attachmentData: string, filename: string, secretKey: string) => {
  // Convert base64 to blob
  const byteCharacters = atob(attachmentData)
  const byteNumbers = new Array(byteCharacters.length)
  for (let i = 0; i < byteCharacters.length; i++) {
    byteNumbers[i] = byteCharacters.charCodeAt(i)
  }
  const byteArray = new Uint8Array(byteNumbers)
  const blob = new Blob([byteArray])
  const file = new File([blob], filename)

  // Determine endpoint based on file extension
  const ext = filename.toLowerCase().split('.').pop() || ''
  let endpoint = '/sandbox/analyze'

  if (ext === 'pdf') {
    endpoint = '/analyze/pdf'
  } else if (['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp'].includes(ext)) {
    endpoint = '/analyze/office'
  } else if (['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'].includes(ext)) {
    endpoint = '/analyze/qrcode'
  }

  const formData = new FormData()
  formData.append('file', file)
  formData.append('secretKey', secretKey)

  const response = await api.post(endpoint, formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 300000,
  })
  return response.data
}

// Retrieve Analysis
export const retrieveAnalysis = async (entryRef: string, secretKey: string) => {
  const response = await api.post(`/retrieve/${entryRef}`, { secretKey })
  return response.data
}

// Download PDF Report
export const downloadPdfReport = async (entryRef: string, secretKey: string) => {
  const response = await api.post('/export/pdf', {
    entryRef,
    secretKey,
  })

  // Response contains pdf_base64 field
  const data = response.data
  if (!data.success || !data.pdf_base64) {
    throw new Error(data.error || 'Failed to generate PDF')
  }

  // Decode base64 to blob
  const byteCharacters = atob(data.pdf_base64)
  const byteNumbers = new Array(byteCharacters.length)
  for (let i = 0; i < byteCharacters.length; i++) {
    byteNumbers[i] = byteCharacters.charCodeAt(i)
  }
  const byteArray = new Uint8Array(byteNumbers)
  const blob = new Blob([byteArray], { type: 'application/pdf' })

  // Create download link
  const url = window.URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.setAttribute('download', `${entryRef}_report.pdf`)
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.URL.revokeObjectURL(url)
}

export default api
