import { readFile } from "fs/promises";
import { normalizeData } from "./src/processing/normalizer.js";
import { extractIOCs } from "./src/processing/extractor.js";
import { correlateIOCs, getTopThreats } from "./src/processing/correlator.js";
import { report } from "./src/utils/reporter.js";

async function main() {
  const data = await readFile("./test-data.json", "utf-8");
  const rawItems = JSON.parse(data);

  console.log("\n🧪 Pipeline Test with Sample IOC Data\n");

  // Normalize
  const normalized = normalizeData(rawItems, "test-source");
  console.log(`✅ Normalized: ${normalized.length} events`);

  // Extract IOCs
  const extracted = extractIOCs(normalized);
  console.log(`✅ IOCs extracted: ${extracted.length}`);
  extracted.forEach(ioc => console.log(`   - [${ioc.type}] ${ioc.value}`));

  // Correlate
  const correlated = correlateIOCs(extracted);
  console.log(`\n✅ Unique IOCs: ${correlated.length} (after deduplication)`);

  // Show top threats
  const topThreats = getTopThreats(correlated, 10);

  // Report
  console.log("\n");
  report(topThreats);
}

main().catch(console.error);
