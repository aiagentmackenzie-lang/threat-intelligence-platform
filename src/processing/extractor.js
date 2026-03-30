import net from "node:net";

// Regex patterns for IOC extraction
const ipv4Regex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const domainRegex = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
const hashRegex = /\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/gi;
const urlRegex = /https?:\/\/[^\s\"'<>]+/gi;

// Private IP ranges to exclude
const privateRanges = [
  /^10\./, // 10.0.0.0/8
  /^127\./, // 127.0.0.0/8 (loopback)
  /^192\.168\./, // 192.168.0.0/16
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0/12
  /^169\.254\./, // 169.254.0.0/16 (link-local)
  /^0\./, // 0.0.0.0/8
  /^22[4-9]\./, // 224.0.0.0/4 (multicast)
  /^23[0-9]\./, // multicast continuation
  /^24[0-9]\./, // multicast continuation
  /^25[0-5]\./, // multicast continuation
];

/**
 * Check if IP is private or loopback
 * @param {string} ip - IP address to check
 * @returns {boolean} - True if private/loopback
 */
function isPrivateOrLoopbackIPv4(ip) {
  return privateRanges.some((range) => range.test(ip));
}

/**
 * Detect hash type based on length
 * @param {string} hash - Hash string
 * @returns {string} - Hash type (md5, sha1, sha256, or unknown)
 */
function detectHashType(hash) {
  const length = hash.length;
  if (length === 32) return "md5";
  if (length === 40) return "sha1";
  if (length === 64) return "sha256";
  return "unknown";
}

/**
 * Extract IOCs from normalized events
 * @param {Array} events - Normalized events
 * @returns {Array} - Array of extracted IOC objects
 */
export function extractIOCs(events) {
  const findings = [];

  for (const event of events) {
    const text = event.content || "";

    // Extract IPv4 addresses
    const ips = text.match(ipv4Regex) || [];
    for (const ip of ips) {
      if (net.isIPv4(ip) && !isPrivateOrLoopbackIPv4(ip)) {
        findings.push({
          type: "ip",
          value: ip,
          source: event.source,
          firstSeen: event.timestamp,
          lastSeen: event.timestamp,
        });
      }
    }

    // Extract domains
    const domains = text.match(domainRegex) || [];
    for (const domain of domains) {
      // Filter out common false positives
      const lowerDomain = domain.toLowerCase();
      if (
        !lowerDomain.endsWith(".local") &&
        !lowerDomain.endsWith(".test") &&
        !lowerDomain.endsWith(".localhost") &&
        !lowerDomain.endsWith(".example") &&
        !lowerDomain.endsWith(".invalid")
      ) {
        findings.push({
          type: "domain",
          value: lowerDomain,
          source: event.source,
          firstSeen: event.timestamp,
          lastSeen: event.timestamp,
        });
      }
    }

    // Extract hashes
    const hashes = text.match(hashRegex) || [];
    for (const hash of hashes) {
      const lowerHash = hash.toLowerCase();
      const hashType = detectHashType(lowerHash);
      if (hashType !== "unknown") {
        findings.push({
          type: "hash",
          value: lowerHash,
          hashType: hashType,
          source: event.source,
          firstSeen: event.timestamp,
          lastSeen: event.timestamp,
        });
      }
    }

    // Extract URLs
    const urls = text.match(urlRegex) || [];
    for (const url of urls) {
      try {
        // Basic URL validation
        new URL(url);
        findings.push({
          type: "url",
          value: url,
          source: event.source,
          firstSeen: event.timestamp,
          lastSeen: event.timestamp,
        });
      } catch {
        // Invalid URL, skip
      }
    }
  }

  return findings;
}

/**
 * Get statistics about extracted IOCs
 * @param {Array} iocs - Extracted IOCs
 * @returns {Object} - Statistics by type
 */
export function getIOCStats(iocs) {
  const stats = {
    total: iocs.length,
    ip: 0,
    domain: 0,
    hash: 0,
    url: 0,
  };

  for (const ioc of iocs) {
    if (stats[ioc.type] !== undefined) {
      stats[ioc.type]++;
    }
  }

  return stats;
}
