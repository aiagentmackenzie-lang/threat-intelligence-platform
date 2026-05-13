import { logger } from "../utils/logger.js";

const ENRICHMENT_TIMEOUT_MS = 10000;

/**
 * Enrich IOC with external intelligence
 * @param {Object} ioc - Correlated IOC object
 * @returns {Promise<Object>} - Enriched IOC with attributes
 */
export async function enrichIOC(ioc) {
  try {
    const enriched = {
      ...ioc,
      attributes: {
        reputation: "unknown",
        score: 0,
        geo: null,
        asn: null,
        tags: [],
      },
    };

    // Enrich based on IOC type
    switch (ioc.type) {
      case "ip":
        await enrichIP(enriched);
        break;
      case "domain":
        await enrichDomain(enriched);
        break;
      case "hash":
        await enrichHash(enriched);
        break;
      case "url":
        await enrichURL(enriched);
        break;
    }

    logger.debug(
      { value: ioc.value, type: ioc.type, reputation: enriched.attributes.reputation },
      "IOC enrichment complete"
    );

    return enriched;
  } catch (error) {
    logger.error({ value: ioc.value, error: error.message }, "Failed to enrich IOC");

    return {
      ...ioc,
      attributes: {
        reputation: "unknown",
        score: 0,
        geo: null,
        asn: null,
        tags: [],
        enrichmentError: error.message,
      },
    };
  }
}

/**
 * Enrich IP address with reputation data
 * @param {Object} enriched - Enriched IOC object
 */
async function enrichIP(enriched) {
  const abuseIPDBKey = process.env.ABUSEIPDB_API_KEY;
  const vtKey = process.env.VT_API_KEY;

  // AbuseIPDB enrichment
  if (abuseIPDBKey) {
    try {
      const response = await fetchAbuseIPDB(enriched.value, abuseIPDBKey);
      if (response) {
        enriched.attributes.reputation = getReputationFromScore(response.abuseConfidenceScore);
        enriched.attributes.score = response.abuseConfidenceScore;
        enriched.attributes.country = response.countryCode;
        enriched.attributes.isp = response.isp;
        enriched.attributes.tags = response.usageType ? [response.usageType] : [];
      }
    } catch (error) {
      logger.debug({ ip: enriched.value, error: error.message }, "AbuseIPDB enrichment failed");
    }
  }

  // VirusTotal enrichment (if available)
  if (vtKey) {
    try {
      const vtData = await fetchVirusTotalIP(enriched.value, vtKey);
      if (vtData) {
        enriched.attributes.virustotal = vtData;
        // Boost score if VT shows malicious
        if (vtData.malicious > 0) {
          enriched.attributes.score = Math.max(enriched.attributes.score, 50);
          if (enriched.attributes.reputation === "unknown") {
            enriched.attributes.reputation = "suspicious";
          }
        }
      }
    } catch (error) {
      logger.debug({ ip: enriched.value, error: error.message }, "VirusTotal enrichment failed");
    }
  }

  // Fallback: basic geo lookup (using ip-api.com - no key needed)
  if (!enriched.attributes.country) {
    try {
      const geoData = await fetchGeoIP(enriched.value);
      if (geoData) {
        enriched.attributes.country = geoData.countryCode;
        enriched.attributes.city = geoData.city;
        enriched.attributes.isp = enriched.attributes.isp || geoData.isp;
      }
    } catch (error) {
      logger.debug({ ip: enriched.value, error: error.message }, "GeoIP enrichment failed");
    }
  }
}

/**
 * Enrich domain with reputation data
 * @param {Object} enriched - Enriched IOC object
 */
async function enrichDomain(enriched) {
  const vtKey = process.env.VT_API_KEY;

  if (vtKey) {
    try {
      const vtData = await fetchVirusTotalDomain(enriched.value, vtKey);
      if (vtData) {
        enriched.attributes.virustotal = vtData;
        enriched.attributes.score = vtData.malicious * 10;
        enriched.attributes.reputation = getReputationFromScore(enriched.attributes.score);
      }
    } catch (error) {
      logger.debug({ domain: enriched.value, error: error.message }, "Domain enrichment failed");
    }
  }
}

/**
 * Enrich hash with reputation data
 * @param {Object} enriched - Enriched IOC object
 */
async function enrichHash(enriched) {
  const vtKey = process.env.VT_API_KEY;

  if (vtKey) {
    try {
      const vtData = await fetchVirusTotalHash(enriched.value, vtKey);
      if (vtData) {
        enriched.attributes.virustotal = vtData;
        enriched.attributes.score = vtData.malicious * 10;
        enriched.attributes.reputation = getReputationFromScore(enriched.attributes.score);
        enriched.attributes.threatLabel = vtData.threatLabel;
      }
    } catch (error) {
      logger.debug({ hash: enriched.value, error: error.message }, "Hash enrichment failed");
    }
  }
}

/**
 * Enrich URL with reputation data
 * @param {Object} enriched - Enriched IOC object
 */
async function enrichURL(enriched) {
  const vtKey = process.env.VT_API_KEY;

  if (vtKey) {
    try {
      const vtData = await fetchVirusTotalURL(enriched.value, vtKey);
      if (vtData) {
        enriched.attributes.virustotal = vtData;
        enriched.attributes.score = vtData.malicious * 10;
        enriched.attributes.reputation = getReputationFromScore(enriched.attributes.score);
      }
    } catch (error) {
      logger.debug({ url: enriched.value, error: error.message }, "URL enrichment failed");
    }
  }
}

// ──────────────────────────────────────────────
// Provider-specific fetch functions
// ──────────────────────────────────────────────

/**
 * Fetch enrichment data from AbuseIPDB
 * @param {string} ip - IP address to check
 * @param {string} apiKey - AbuseIPDB API key
 * @returns {Promise<Object|null>} - Enrichment data
 */
async function fetchAbuseIPDB(ip, apiKey) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), ENRICHMENT_TIMEOUT_MS);

  try {
    const response = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose=true`,
      {
        headers: {
          Key: apiKey,
          Accept: "application/json",
        },
        signal: controller.signal,
      }
    );

    if (!response.ok) {
      logger.debug({ ip, status: response.status }, "AbuseIPDB API returned non-success status");
      return null;
    }

    const data = await response.json();
    const d = data.data;
    return {
      abuseConfidenceScore: d.abuseConfidenceScore || 0,
      countryCode: d.countryCode || null,
      isp: d.isp || null,
      usageType: d.usageType || null,
    };
  } catch (error) {
    logger.debug({ ip, error: error.message }, "AbuseIPDB fetch failed");
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchVirusTotalIP(_ip, _apiKey) {
  // Not yet implemented — requires VT API key
  return null;
}

async function fetchVirusTotalDomain(_domain, _apiKey) {
  // Not yet implemented — requires VT API key
  return null;
}

async function fetchVirusTotalHash(_hash, _apiKey) {
  // Not yet implemented — requires VT API key
  return null;
}

async function fetchVirusTotalURL(_url, _apiKey) {
  // Not yet implemented — requires VT API key
  return null;
}

async function fetchGeoIP(ip) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const response = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,countryCode,city,isp`, {
      signal: controller.signal,
    });

    if (!response.ok) return null;

    const data = await response.json();
    if (data.status !== "success") return null;

    return {
      countryCode: data.countryCode,
      city: data.city,
      isp: data.isp,
    };
  } catch (error) {
    logger.debug({ ip, error: error.message }, "GeoIP fetch failed");
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Convert score to reputation label
 * @param {number} score - Confidence score 0-100
 * @returns {string} - Reputation label
 */
function getReputationFromScore(score) {
  if (score >= 80) return "malicious";
  if (score >= 50) return "suspicious";
  if (score >= 20) return "moderate";
  return "clean";
}