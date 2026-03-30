import { logger } from "../utils/logger.js";

/**
 * Correlate IOCs - deduplicate and aggregate sightings across sources
 * @param {Array} iocs - Array of extracted IOC objects
 * @returns {Array} - Array of correlated findings
 */
export function correlateIOCs(iocs) {
  const map = new Map();

  for (const ioc of iocs) {
    const key = `${ioc.type}:${ioc.value}`;

    if (!map.has(key)) {
      map.set(key, {
        type: ioc.type,
        value: ioc.value,
        hashType: ioc.hashType || null,
        count: 0,
        sources: new Set(),
        firstSeen: ioc.firstSeen,
        lastSeen: ioc.lastSeen,
      });
    }

    const entry = map.get(key);
    entry.count += 1;
    if (ioc.source) entry.sources.add(ioc.source);

    // Update timestamps
    if (ioc.firstSeen && ioc.firstSeen < entry.firstSeen) {
      entry.firstSeen = ioc.firstSeen;
    }
    if (ioc.lastSeen && ioc.lastSeen > entry.lastSeen) {
      entry.lastSeen = ioc.lastSeen;
    }
  }

  // Convert to final format
  const correlated = Array.from(map.values()).map((entry) => ({
    ...entry,
    sources: Array.from(entry.sources),
  }));

  logger.info(
    { input: iocs.length, output: correlated.length },
    "IOC correlation complete"
  );

  return correlated;
}

/**
 * Calculate confidence score based on correlation
 * @param {Object} finding - Correlated finding
 * @returns {number} - Confidence score 0-100
 */
export function calculateConfidence(finding) {
  let score = 0;

  // Base score by source count
  score += Math.min(finding.sources.length * 20, 60);

  // Bonus for multiple sightings
  if (finding.count >= 3) score += 20;
  else if (finding.count >= 2) score += 10;

  // Type-specific scoring
  switch (finding.type) {
    case "ip":
      score += 5;
      break;
    case "hash":
      score += 10;
      break;
    case "domain":
      score += 5;
      break;
    case "url":
      score += 5;
      break;
  }

  return Math.min(score, 100);
}

/**
 * Get top threats by confidence and source count
 * @param {Array} findings - Correlated findings
 * @param {number} limit - Number of results to return
 * @returns {Array} - Top findings
 */
export function getTopThreats(findings, limit = 10) {
  return findings
    .map((f) => ({
      ...f,
      confidence: calculateConfidence(f),
    }))
    .sort((a, b) => b.confidence - a.confidence)
    .slice(0, limit);
}

/**
 * Group findings by type
 * @param {Array} findings - Correlated findings
 * @returns {Object} - Grouped by type
 */
export function groupByType(findings) {
  const grouped = {
    ip: [],
    domain: [],
    hash: [],
    url: [],
  };

  for (const finding of findings) {
    if (grouped[finding.type]) {
      grouped[finding.type].push(finding);
    }
  }

  return grouped;
}
