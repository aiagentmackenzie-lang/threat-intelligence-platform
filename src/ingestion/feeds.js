import axios from "axios";
import { logger } from "../utils/logger.js";

const DEFAULT_TIMEOUT_MS = 15000;
const MAX_CONTENT_LENGTH = 10 * 1024 * 1024;

/**
 * Fetch threat data from a configured feed
 * @param {Object} feedConfig - Feed configuration object
 * @returns {Promise<Array>} - Array of raw threat data items
 */
export async function fetchThreatFeed(feedConfig) {
  const { name, url, auth } = feedConfig;

  try {
    const headers = {};

    if (auth?.type === "header") {
      const token = process.env[auth.env];
      if (!token) {
        logger.warn({ feed: name }, "Missing auth token for configured feed");
        return [];
      }
      headers[auth.headerName] = token;
    }

    logger.debug({ feed: name, url }, "Fetching threat feed");

    const response = await axios.get(url, {
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

    const response = await axios.get(url, {
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
      const title = itemXml.match(/<title>([^<]+)<\/title>/)?.[1] || "";
      const description = itemXml.match(/<description>([^<]+)<\/description>/)?.[1] || "";
      const link = itemXml.match(/<link>([^<]+)<\/link>/)?.[1] || "";
      const pubDate = itemXml.match(/<pubDate>([^<]+)<\/pubDate>/)?.[1] || new Date().toISOString();

      items.push({
        source: name,
        timestamp: new Date(pubDate).toISOString(),
        text: `${title} ${description}`,
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
