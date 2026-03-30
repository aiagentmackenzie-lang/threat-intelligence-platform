import { logger } from "../utils/logger.js";

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

// Provider-specific fetch functions

async function fetchAbuseIPDB(ip, apiKey) {
  // Implementation would go here
  // For now, return null (placeholder)
  return null;
}

async function fetchVirusTotalIP(ip, apiKey) {
  return null; // Placeholder
}

async function fetchVirusTotalDomain(domain, apiKey) {
  return null; // Placeholder
}

async function fetchVirusTotalHash(hash, apiKey) {
  return null; // Placeholder
}

async function fetchVirusTotalURL(url, apiKey) {
  return null; // Placeholder
}

async function fetchGeoIP(ip) {
  return null; // Placeholder
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
