import { z } from "zod";

// Schema for validating raw feed data - requires at least one content field with meaningful content
const RawEventSchema = z.object({
  source: z.string().optional(),
  timestamp: z.string().optional(),
  text: z.string().optional(),
  data: z.unknown().optional(),
  content: z.string().optional(),
}).refine(
  (data) => {
    // At least one content field must exist AND have meaningful content
    const hasText = typeof data.text === 'string' && data.text.trim().length > 0;
    const hasContent = typeof data.content === 'string' && data.content.trim().length > 0;
    const hasData = typeof data.data === 'string' && data.data.trim().length > 0;
    const hasObjectData = typeof data.data === 'object' && data.data !== null && Object.keys(data.data).length > 0;
    return hasText || hasContent || hasData || hasObjectData;
  },
  { message: "At least one content field (text, content, or data) must have meaningful content" }
);

/**
 * Normalize heterogeneous source data into a common event format
 * @param {Array|Object} rawItems - Raw data from feeds
 * @param {string} sourceName - Name of the source feed
 * @returns {Array} - Array of normalized events
 */
export function normalizeData(rawItems, sourceName = "unknown") {
  const items = Array.isArray(rawItems) ? rawItems : [rawItems];

  return items
    .map((item) => {
      const parsed = RawEventSchema.safeParse(item);

      if (!parsed.success) {
        return null;
      }

      const value = parsed.data;

      // Extract content from various possible fields
      const content =
        value.text ||
        value.content ||
        (typeof value.data === "string" ? value.data : JSON.stringify(value.data ?? item));

      return {
        source: value.source || sourceName,
        timestamp: value.timestamp || new Date().toISOString(),
        content: content,
        metadata: {
          normalizedBy: "normalizer.js",
          originalFields: Object.keys(item),
        },
      };
    })
    .filter(Boolean);
}

/**
 * Normalize AbuseIPDB response format
 * @param {Object} response - AbuseIPDB API response
 * @param {string} sourceName - Source name
 * @returns {Array} - Normalized events
 */
export function normalizeAbuseIPDB(response, sourceName = "abuseipdb") {
  if (!response || !Array.isArray(response.data)) {
    return [];
  }

  return response.data.map((item) => ({
    source: sourceName,
    timestamp: new Date().toISOString(),
    content: `IP: ${item.ipAddress} - ${item.comment || "No comment"} (Confidence: ${item.confidenceScore})`,
    metadata: {
      ipAddress: item.ipAddress,
      confidenceScore: item.confidenceScore,
      countryCode: item.countryCode,
      abuseCategory: item.abuseCategory,
    },
  }));
}
