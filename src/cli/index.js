#!/usr/bin/env node

import "dotenv/config";
import { loadConfig } from "../config/loader.js";
import { logger } from "../utils/logger.js";
import { executePipeline, getPipelineStats } from "../pipeline.js";
import { report } from "../utils/reporter.js";

async function main() {
  try {
    logger.info("Threat Intelligence Platform starting...");

    // Parse arguments
    const args = parseArgs();
    const configPath = args.config || "./config/feeds.json";

    const feeds = await loadConfig(configPath);
    let enabledFeeds = feeds.filter((f) => f.enabled);

    // Filter by specific feeds if requested
    if (args.feeds) {
      const feedNames = args.feeds.split(",").map((f) => f.trim());
      enabledFeeds = enabledFeeds.filter((f) => feedNames.includes(f.name));
    }

    if (enabledFeeds.length === 0) {
      console.log("\n✅ Threat Intelligence Platform Ready");
      console.log("\nPipeline Components:");
      console.log("   ✅ Ingestion Layer (REST API, RSS feeds)");
      console.log("   ✅ Normalization Layer (Zod-validated)");
      console.log("   ✅ IOC Extraction (IP, Domain, Hash, URL)");
      console.log("   ✅ Correlation Engine (deduplication)");
      console.log("   ✅ Enrichment Framework (AbuseIPDB, VT, GeoIP)");
      console.log("   ✅ AI Analysis Layer (OpenAI, Zod-validated)");
      console.log("   ✅ Reporter (Console, JSON, NDJSON, STIX)");
      console.log("\nNo enabled feeds configured.");
      console.log("Enable feeds in config/feeds.json or use:");
      console.log("   --feeds feed1,feed2   Filter to specific feeds");
      console.log("   --skip-enrichment     Skip enrichment phase");
      console.log("   --skip-ai             Skip AI analysis");
      console.log("   --format json         Output format (console, json, ndjson, stix)");
      console.log("   --output file.json    Save to file\n");
      process.exit(0);
    }

    console.log(`\nProcessing ${enabledFeeds.length} enabled feed(s)...`);

    // Execute pipeline
    const results = await executePipeline(enabledFeeds, {
      skipEnrichment: args.skipEnrichment,
      skipAI: args.skipAI,
    });

    // Get stats
    const stats = getPipelineStats(results);

    // Report results
    await report(results.analyzed, {
      format: args.format || "console",
      output: args.output,
    });

    // Summary
    console.log("\n=== Execution Summary ===");
    console.log(`Duration: ${stats.execution.duration}`);
    console.log(`Feeds processed: ${stats.execution.feedsProcessed}`);
    console.log(`IOCs extracted: ${stats.iocs.extracted}`);
    console.log(`Unique IOCs: ${stats.iocs.unique}`);
    console.log(`  - IPs: ${stats.iocs.byType.ip}`);
    console.log(`  - Domains: ${stats.iocs.byType.domain}`);
    console.log(`  - Hashes: ${stats.iocs.byType.hash}`);
    console.log(`  - URLs: ${stats.iocs.byType.url}`);

    if (stats.execution.errors > 0) {
      console.log(`\n⚠️  ${stats.execution.errors} error(s) occurred`);
    }

    console.log("\n✅ Pipeline execution complete\n");
    logger.info("Pipeline execution complete");
  } catch (error) {
    logger.error({ error: error.message }, "Fatal error");
    console.error("Fatal error:", error.message);
    process.exit(1);
  }
}

/**
 * Parse command line arguments
 * @returns {Object} - Parsed arguments
 */
function parseArgs() {
  const args = {};
  const argv = process.argv.slice(2);

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];

    switch (arg) {
      case "--config":
        args.config = argv[++i];
        break;
      case "--feeds":
        args.feeds = argv[++i];
        break;
      case "--format":
        args.format = argv[++i];
        break;
      case "--output":
        args.output = argv[++i];
        break;
      case "--skip-enrichment":
        args.skipEnrichment = true;
        break;
      case "--skip-ai":
        args.skipAI = true;
        break;
      case "--help":
        showHelp();
        process.exit(0);
        break;
    }
  }

  return args;
}

function showHelp() {
  console.log(`
Threat Intelligence Platform

Usage: npm start [options]

Options:
  --config <path>       Custom config file (default: ./config/feeds.json)
  --feeds <names>      Filter to specific feeds (comma-separated)
  --format <type>      Output format: console, json, ndjson, stix (default: console)
  --output <file>      Save output to file
  --skip-enrichment     Skip enrichment phase
  --skip-ai             Skip AI analysis phase
  --help                Show this help message

Examples:
  npm start
  npm start --format json --output report.json
  npm start --feeds abuseipdb --skip-ai
`);
}

main();
