import pLimit from "p-limit";
import { logger } from "./utils/logger.js";
import { fetchThreatFeed, fetchRSSFeed } from "./ingestion/feeds.js";
import { normalizeData, normalizeAbuseIPDB } from "./processing/normalizer.js";
import { extractIOCs, getIOCStats } from "./processing/extractor.js";
import { correlateIOCs, getTopThreats, groupByType } from "./processing/correlator.js";
import { enrichIOC } from "./enrichment/enrich.js";
import { analyzeThreat, batchAnalyzeThreats } from "./ai/analyzer.js";

const CONCURRENCY_LIMIT = 10;

/**
 * Execute full threat intelligence pipeline
 * @param {Array} feeds - Feed configurations
 * @param {Object} options - Pipeline options
 * @returns {Promise<Object>} - Pipeline results
 */
export async function executePipeline(feeds, options = {}) {
  const limit = pLimit(CONCURRENCY_LIMIT);
  const startTime = Date.now();

  logger.info({ feedCount: feeds.length }, "Starting pipeline execution");

  const results = {
    feeds: {},
    extracted: [],
    correlated: [],
    enriched: [],
    analyzed: [],
    duration: 0,
    errors: [],
  };

  // Phase 1: Ingestion
  logger.info("Phase 1: Ingestion");
  const allExtracted = [];

  for (const feed of feeds) {
    try {
      logger.debug({ feed: feed.name }, "Fetching feed");

      let rawData;
      if (feed.type === "rss") {
        rawData = await fetchRSSFeed(feed);
      } else {
        rawData = await fetchThreatFeed(feed);
      }

      results.feeds[feed.name] = {
        raw: Array.isArray(rawData) ? rawData.length : 1,
        status: "success",
      };

      // Phase 2: Normalization
      let normalized;
      if (feed.name === "abuseipdb" && feed.type === "rest") {
        normalized = normalizeAbuseIPDB(rawData, feed.name);
      } else {
        normalized = normalizeData(rawData, feed.name);
      }

      results.feeds[feed.name].normalized = normalized.length;

      // Phase 3: IOC Extraction
      const extracted = extractIOCs(normalized);
      results.feeds[feed.name].extracted = extracted.length;

      allExtracted.push(...extracted);
    } catch (error) {
      logger.error({ feed: feed.name, error: error.message }, "Feed processing failed");
      results.feeds[feed.name] = { status: "error", error: error.message };
      results.errors.push({ phase: "ingestion", feed: feed.name, error: error.message });
    }
  }

  results.extracted = allExtracted;

  if (allExtracted.length === 0) {
    logger.warn("No IOCs extracted, pipeline terminating");
    results.duration = Date.now() - startTime;
    return results;
  }

  // Phase 4: Correlation
  logger.info("Phase 4: Correlation");
  results.correlated = correlateIOCs(allExtracted);

  // Phase 5: Enrichment (with concurrency control)
  logger.info("Phase 5: Enrichment");
  if (options.skipEnrichment) {
    results.enriched = results.correlated;
    logger.info("Enrichment skipped");
  } else {
    results.enriched = await Promise.all(
      results.correlated.map((ioc) =>
        limit(async () => {
          try {
            return await enrichIOC(ioc);
          } catch (error) {
            logger.error({ ioc: ioc.value, error: error.message }, "Enrichment failed");
            return { ...ioc, enrichmentError: error.message };
          }
        })
      )
    );
  }

  // Phase 6: AI Analysis (with concurrency control)
  logger.info("Phase 6: AI Analysis");
  if (options.skipAI || !process.env.OPENAI_API_KEY) {
    results.analyzed = results.enriched.map((ioc) => ({
      ...ioc,
      risk: "unknown",
      explanation: options.skipAI ? "AI analysis disabled" : "No API key",
      recommendation: "Perform manual review",
      aiEnabled: false,
    }));
    logger.info(options.skipAI ? "AI analysis skipped" : "AI analysis disabled - no API key");
  } else {
    results.analyzed = await batchAnalyzeThreats(
      results.enriched,
      options.llmClient,
      limit
    );
  }

  results.duration = Date.now() - startTime;

  logger.info(
    {
      duration: results.duration,
      feeds: Object.keys(results.feeds).length,
      extracted: results.extracted.length,
      correlated: results.correlated.length,
      enriched: results.enriched.length,
      analyzed: results.analyzed.length,
    },
    "Pipeline execution complete"
  );

  return results;
}

/**
 * Get pipeline execution statistics
 * @param {Object} results - Pipeline results
 * @returns {Object} - Formatted statistics
 */
export function getPipelineStats(results) {
  const stats = getIOCStats(results.extracted);

  return {
    execution: {
      duration: `${results.duration}ms`,
      feedsProcessed: Object.keys(results.feeds).length,
      errors: results.errors.length,
    },
    iocs: {
      extracted: results.extracted.length,
      unique: results.correlated.length,
      byType: stats,
    },
    feeds: Object.entries(results.feeds).map(([name, data]) => ({
      name,
      ...data,
    })),
  };
}
