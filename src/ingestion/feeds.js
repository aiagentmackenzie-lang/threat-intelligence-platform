import axios from "axios";
import { logger } from "../utils/logger.js";

const DEFAULT_TIMEOUT_MS = 15000;
const MAX_CONTENT_LENGTH = 10 * 1024 * 1024;
const MAX_RETRIES = 3;
const RETRY_BASE_DELAY_MS = 1000;

/**
 * Sleep for a given number of milliseconds
 * @param {number} ms - Milliseconds to sleep
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Fetch with retry and exponential backoff
 * @param {string} url - URL to fetch
 * @param {Object} config - Axios config
 * @param {number} retries - Remaining retries
 * @returns {Promise<Object>} - Axios response
 */
async function fetchWithRetry(url, config, retries) {
  const maxRetries = retries ?? MAX_RETRIES;
  try {
    return await axios.get(url, config);
  } catch (error) {
    if (maxRetries <= 0) throw error;

    // Don't retry on 4xx client errors (except 429 rate limit)
    if (error.response && error.response.status >= 400 && error.response.status < 500 && error.response.status !== 429) {
      throw error;
    }

    const delay = RETRY_BASE_DELAY_MS * Math.pow(2, MAX_RETRIES - maxRetries);
    logger.warn({ url, retriesLeft: maxRetries, delay, error: error.message }, "Retrying feed fetch");
    await sleep(delay);
    return fetchWithRetry(url, config, maxRetries - 1);
  }
}

/**
 * Build auth headers for a feed
 * @param {Object} auth - Auth configuration
 * @returns {Object} - Headers object
 */
function buildAuthHeaders(auth) {
  const headers = {};

  if (!auth) return headers;

  switch (auth.type) {
    case "header": {
      const token = process.env[auth.env];
      if (!token) {
        logger.warn({ env: auth.env }, "Missing auth environment variable");
        return headers;
      }
      headers[auth.headerName] = token;
      break;
    }
    case "basic": {
      const credentials = process.env[auth.env];
      if (!credentials) {
        logger.warn({ env: auth.env }, "Missing auth environment variable for basic auth");
        return headers;
      }
      headers["Authorization"] = `Basic ${Buffer.from(credentials).toString("base64")}`;
      break;
    }
    default:
      logger.warn({ authType: auth.type }, "Unsupported auth type");
  }

  return headers;
}

/**
 * Build URL with query parameter auth
 * @param {string} url - Base URL
 * @param {Object} auth - Auth configuration
 * @returns {string} - URL with auth query param appended
 */
function buildAuthUrl(url, auth) {
  if (!auth || auth.type !== "query") return url;

  const token = process.env[auth.env];
  if (!token) {
    logger.warn({ env: auth.env }, "Missing auth environment variable for query auth");
    return url;
  }

  const separator = url.includes("?") ? "&" : "?";
  return `${url}${separator}${auth.headerName || "apiKey"}=${encodeURIComponent(token)}`;
}

/**
 * Fetch threat data from a configured feed
 * @param {Object} feedConfig - Feed configuration object
 * @returns {Promise<Array>} - Array of raw threat data items
 */
export async function fetchThreatFeed(feedConfig) {
  const { name, url, auth } = feedConfig;

  try {
    const headers = buildAuthHeaders(auth);
    const fetchUrl = buildAuthUrl(url, auth);

    logger.debug({ feed: name, url }, "Fetching threat feed");

    const response = await fetchWithRetry(fetchUrl, {
      headers,
      timeout: DEFAULT_TIMEOUT_MS,
      maxContentLength: MAX_CONTENT_LENGTH,
      validateStatus: (status) => status >= 200 && status < 500,
    });

    if (response.status >= 400) {
      logger.warn(
        { feed: name, status: response.status },
        "Feed returned non-success status"
      );
      return [];
    }

    logger.info(
      { feed: name, itemCount: Array.isArray(response.data) ? response.data.length : 1 },
      "Feed fetched successfully"
    );

    return response.data;
  } catch (error) {
    logger.error(
      { feed: name, error: error.message },
      "Failed to fetch threat feed"
    );
    return [];
  }
}

/**
 * Fetch data from RSS feed
 * @param {Object} feedConfig - Feed configuration
 * @returns {Promise<Array>} - Array of normalized items
 */
export async function fetchRSSFeed(feedConfig) {
  const { name, url } = feedConfig;

  try {
    logger.debug({ feed: name, url }, "Fetching RSS feed");

    const response = await fetchWithRetry(url, {
      timeout: DEFAULT_TIMEOUT_MS,
      maxContentLength: MAX_CONTENT_LENGTH,
      validateStatus: (status) => status >= 200 && status < 500,
    });

    if (response.status >= 400) {
      logger.warn({ feed: name, status: response.status }, "RSS feed error");
      return [];
    }

    // Parse RSS XML - simplified extraction
    const xmlData = response.data;
    const items = [];

    // Extract items from RSS XML
    const itemMatches = xmlData.match(/<item>[\s\S]*?<\/item>/g) || [];

    for (const itemXml of itemMatches) {
      const title = itemXml.match(/<title>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/title>/)?.[1] || "";
      const description = itemXml.match(/<description>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/description>/)?.[1] || "";
      const link = itemXml.match(/<link>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/link>/)?.[1] || "";
      const pubDate = itemXml.match(/<pubDate>([^<]+)<\/pubDate>/)?.[1] || new Date().toISOString();

      items.push({
        source: name,
        timestamp: new Date(pubDate).toISOString(),
        text: `${title} ${description}`.trim(),
        data: { link, title, description },
      });
    }

    logger.info({ feed: name, itemCount: items.length }, "RSS feed parsed");
    return items;
  } catch (error) {
    logger.error({ feed: name, error: error.message }, "Failed to fetch RSS feed");
    return [];
  }
}

/**
 * Get demo threat data (for testing without API keys)
 * @returns {Promise<Array>} - Array of demo IOC data
 */
export async function getDemoData() {
  logger.info("Loading demo threat feed data");
  
  return [
    {
      source: "demo-threat-feed",
      timestamp: new Date().toISOString(),
      text: "Suspicious activity detected from IP 185.220.101.47 which was observed communicating with malicious domain evil-c2-server.com. MD5 hash d41d8cd98f00b204e9800998ecf8427e detected in malware sample.",
      data: { threat_type: "c2_communication", severity: "high" }
    },
    {
      source: "demo-threat-feed",
      timestamp: new Date().toISOString(),
      text: "Phishing campaign using domain secure-bank-login.net and IP 192.0.2.100. Related SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. Phishing URL: https://secure-bank-login.net/verify",
      data: { threat_type: "phishing", severity: "medium" }
    },
    {
      source: "demo-threat-feed",
      timestamp: new Date().toISOString(),
      text: "Malware beaconing to 10.0.0.1 (private IP excluded) and malware-c2.ru. File hash: a5b8c9d2e1f4g7h6i3j0k5l8m1n4o7p0q9r2s5t8u1v4w7x0y3z6a9b2c5d8e1f4",
      data: { threat_type: "malware_beacon", severity: "critical" }
    }
  ];
}