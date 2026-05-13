import { randomUUID } from "node:crypto";
import { resolve, dirname } from "node:path";
import { logger } from "./logger.js";
import { writeFile, mkdir } from "fs/promises";

const VALID_FORMATS = ["console", "json", "ndjson", "stix"];

/**
 * Validate report format string
 * @param {string} format - Format name
 * @returns {boolean} - True if valid
 */
export function isValidFormat(format) {
  return VALID_FORMATS.includes(format);
}

/**
 * Get valid format names
 * @returns {string[]} - Array of valid format names
 */
export function getValidFormats() {
  return [...VALID_FORMATS];
}

/**
 * Report findings in multiple formats
 * @param {Array} findings - Analyzed findings
 * @param {Object} options - Report options
 */
export async function report(findings, options = {}) {
  const { format = "console", output } = options;

  if (!VALID_FORMATS.includes(format)) {
    console.error(`Unknown format: ${format}. Valid formats: ${VALID_FORMATS.join(", ")}`);
    return;
  }

  let outputText;

  switch (format) {
    case "console":
      outputText = reportConsole(findings);
      break;
    case "json":
      outputText = reportJSON(findings);
      break;
    case "ndjson":
      outputText = reportNDJSON(findings);
      break;
    case "stix":
      outputText = reportSTIX(findings);
      break;
  }

  // When writing to file, suppress console output for machine-readable formats
  if (output) {
    // Validate output path doesn't escape working directory
    const resolvedPath = resolve(output);
    const cwd = resolve(".");
    if (!resolvedPath.startsWith(cwd)) {
      logger.error({ path: resolvedPath, cwd }, "Output path escapes working directory");
      throw new Error("Output path must be within the project directory");
    }

    try {
      await mkdir(dirname(resolvedPath), { recursive: true });
      await writeFile(resolvedPath, outputText, "utf-8");
      logger.info({ file: resolvedPath }, "Report saved to file");
      console.log(`\nReport saved to ${resolvedPath}`);
    } catch (error) {
      logger.error({ file: resolvedPath, error: error.message }, "Failed to save report");
      throw error;
    }
  } else {
    // No output file — print to console
    console.log(outputText);
  }
}

/**
 * Console format report
 * @param {Array} findings - Analyzed findings
 * @returns {string} - Formatted report
 */
function reportConsole(findings) {
  const lines = ["\n=== Threat Intelligence Report ===\n"];

  for (const finding of findings) {
    lines.push(`[IOC] ${finding.type.toUpperCase()} ${finding.value}`);

    if (finding.hashType) {
      lines.push(`  Hash Type: ${finding.hashType}`);
    }

    lines.push(`  Sources: ${finding.sources?.join(", ") || "unknown"}`);
    lines.push(`  Sightings: ${finding.count ?? "n/a"}`);

    if (finding.confidence) {
      lines.push(`  Confidence: ${finding.confidence}%`);
    }

    if (finding.attributes?.reputation) {
      lines.push(`  Reputation: ${finding.attributes.reputation}`);
    }

    if (finding.attributes?.score) {
      lines.push(`  Score: ${finding.attributes.score}`);
    }

    if (finding.attributes?.country) {
      lines.push(`  Country: ${finding.attributes.country}`);
    }

    if (finding.risk) {
      lines.push(`  Risk: ${finding.risk}`);
    }

    if (finding.explanation) {
      lines.push(`  Explanation: ${finding.explanation}`);
    }

    if (finding.recommendation) {
      lines.push(`  Recommendation: ${finding.recommendation}`);
    }

    lines.push("");
  }

  lines.push(`Total findings: ${findings.length}`);
  lines.push("");

  return lines.join("\n");
}

/**
 * JSON format report
 * @param {Array} findings - Analyzed findings
 * @returns {string} - JSON string
 */
function reportJSON(findings) {
  const report = {
    generatedAt: new Date().toISOString(),
    totalFindings: findings.length,
    findings,
  };
  return JSON.stringify(report, null, 2);
}

/**
 * NDJSON format report (one JSON object per line)
 * @param {Array} findings - Analyzed findings
 * @returns {string} - NDJSON string
 */
function reportNDJSON(findings) {
  return findings.map((f) => JSON.stringify(f)).join("\n");
}

/**
 * STIX 2.1 format report
 * @param {Array} findings - Analyzed findings
 * @returns {string} - STIX 2.1 JSON
 */
function reportSTIX(findings) {
  const stixBundle = {
    type: "bundle",
    id: `bundle--${randomUUID()}`,
    spec_version: "2.1",
    objects: findings.map((finding) => ({
      type: findSTIXType(finding.type),
      id: `indicator--${randomUUID()}`,
      created: finding.firstSeen || new Date().toISOString(),
      modified: finding.lastSeen || new Date().toISOString(),
      labels: finding.attributes?.tags || ["threat-intel"],
      pattern: buildPattern(finding),
      pattern_type: "stix",
      pattern_version: "2.1",
      valid_from: finding.firstSeen || new Date().toISOString(),
      confidence: finding.confidence || 50,
      description: finding.explanation || "",
    })),
  };

  return JSON.stringify(stixBundle, null, 2);
}

/**
 * Map IOC type to STIX type
 * @param {string} type - IOC type
 * @returns {string} - STIX type
 */
function findSTIXType(type) {
  const mapping = {
    ip: "ipv4-addr",
    domain: "domain-name",
    hash: "file",
    url: "url",
  };
  return mapping[type] || "indicator";
}

/**
 * Build STIX pattern from finding
 * @param {Object} finding - Finding object
 * @returns {string} - STIX pattern
 */
function buildPattern(finding) {
  switch (finding.type) {
    case "ip":
      return `[ipv4-addr:value = '${finding.value}']`;
    case "domain":
      return `[domain-name:value = '${finding.value}']`;
    case "hash": {
      const hashType = finding.hashType === "md5" ? "MD5" : finding.hashType === "sha1" ? "SHA-1" : "SHA-256";
      return `[file:hashes.'${hashType}' = '${finding.value}']`;
    }
    case "url":
      return `[url:value = '${finding.value}']`;
    default:
      return `[indicator:pattern = '${finding.value}']`;
  }
}