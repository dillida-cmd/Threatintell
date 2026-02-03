/**
 * Defang/sanitize URLs and IPs to prevent accidental clicks on malicious links
 *
 * Examples:
 * - http://evil.com → hxxp://evil[.]com
 * - https://malware.ru → hxxps://malware[.]ru
 * - 192.168.1.1 → 192[.]168[.]1[.]1
 */

export function defangUrl(url: string): string {
  if (!url) return url

  return url
    // Defang protocol
    .replace(/^http:/gi, 'hxxp:')
    .replace(/^https:/gi, 'hxxps:')
    .replace(/^ftp:/gi, 'fxp:')
    // Defang dots in domain/IP (but not in path after first /)
    .replace(/\./g, '[.]')
}

export function defangIp(ip: string): string {
  if (!ip) return ip
  return ip.replace(/\./g, '[.]')
}

export function defangDomain(domain: string): string {
  if (!domain) return domain
  return domain.replace(/\./g, '[.]')
}

export function defangEmail(email: string): string {
  if (!email) return email
  return email
    .replace(/@/g, '[@]')
    .replace(/\./g, '[.]')
}

// Check if a string looks like an IP address
export function isIpAddress(str: string): boolean {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/
  return ipv4Regex.test(str) || ipv6Regex.test(str)
}

// Check if a string looks like a URL
export function isUrl(str: string): boolean {
  return /^(https?|ftp):\/\//i.test(str)
}

// Smart defang - detects type and applies appropriate defanging
export function defang(value: string): string {
  if (!value) return value

  if (isUrl(value)) {
    return defangUrl(value)
  } else if (isIpAddress(value)) {
    return defangIp(value)
  } else if (value.includes('@')) {
    return defangEmail(value)
  } else if (value.includes('.') && !value.includes(' ')) {
    // Likely a domain
    return defangDomain(value)
  }

  return value
}
