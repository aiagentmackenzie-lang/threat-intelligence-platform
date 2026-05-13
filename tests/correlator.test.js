import { describe, it } from "node:test";
import assert from "node:assert";
import { correlateIOCs, calculateConfidence, getTopThreats, groupByType } from "../src/processing/correlator.js";

describe("IOC Correlator", () => {
  describe("correlateIOCs", () => {
    it("should deduplicate identical IOCs", () => {
      const iocs = [
        { type: "ip", value: "1.1.1.1", source: "feed1", firstSeen: "2026-03-30T10:00:00Z", lastSeen: "2026-03-30T10:00:00Z" },
        { type: "ip", value: "1.1.1.1", source: "feed2", firstSeen: "2026-03-30T10:00:00Z", lastSeen: "2026-03-30T10:00:00Z" },
      ];

      const results = correlateIOCs(iocs);
      assert.strictEqual(results.length, 1);
      assert.strictEqual(results[0].count, 2);
      assert.deepStrictEqual(results[0].sources.sort(), ["feed1", "feed2"]);
    });

    it("should keep different IOC types separate", () => {
      const iocs = [
        { type: "ip", value: "1.1.1.1", source: "feed1", firstSeen: "2026-03-30T10:00:00Z", lastSeen: "2026-03-30T10:00:00Z" },
        { type: "domain", value: "1.1.1.1", source: "feed1", firstSeen: "2026-03-30T10:00:00Z", lastSeen: "2026-03-30T10:00:00Z" },
      ];

      const results = correlateIOCs(iocs);
      assert.strictEqual(results.length, 2);
    });

    it("should aggregate sources correctly", () => {
      const iocs = [
        { type: "ip", value: "1.1.1.1", source: "feed1", firstSeen: "2026-03-30T10:00:00Z", lastSeen: "2026-03-30T10:00:00Z" },
        { type: "ip", value: "1.1.1.1", source: "feed1", firstSeen: "2026-03-30T10:00:00Z", lastSeen: "2026-03-30T10:00:00Z" },
        { type: "ip", value: "1.1.1.1", source: "feed2", firstSeen: "2026-03-30T10:00:00Z", lastSeen: "2026-03-30T10:00:00Z" },
      ];

      const results = correlateIOCs(iocs);
      assert.strictEqual(results.length, 1);
      assert.strictEqual(results[0].count, 3);
      assert.deepStrictEqual(results[0].sources.sort(), ["feed1", "feed2"]);
    });
  });

  describe("calculateConfidence", () => {
    it("should give higher confidence for multiple sources", () => {
      const finding1 = { sources: ["feed1"], count: 1, type: "ip" };
      const finding2 = { sources: ["feed1", "feed2", "feed3"], count: 3, type: "ip" };

      const score1 = calculateConfidence(finding1);
      const score2 = calculateConfidence(finding2);

      assert.ok(score2 > score1);
    });

    it("should give bonus for multiple sightings", () => {
      const finding1 = { sources: ["feed1"], count: 1, type: "ip" };
      const finding2 = { sources: ["feed1"], count: 3, type: "ip" };

      const score1 = calculateConfidence(finding1);
      const score2 = calculateConfidence(finding2);

      assert.ok(score2 > score1);
    });

    it("should score hashes higher than IPs", () => {
      const ip = { sources: ["feed1"], count: 1, type: "ip" };
      const hash = { sources: ["feed1"], count: 1, type: "hash" };

      const ipScore = calculateConfidence(ip);
      const hashScore = calculateConfidence(hash);

      assert.ok(hashScore > ipScore);
    });

    it("should cap at 100", () => {
      const finding = { sources: ["feed1", "feed2", "feed3", "feed4", "feed5"], count: 10, type: "hash" };
      const score = calculateConfidence(finding);

      assert.ok(score <= 100);
    });
  });

  describe("getTopThreats", () => {
    it("should return threats sorted by confidence", () => {
      const findings = [
        { type: "ip", value: "1.1.1.1", count: 1, sources: ["feed1"], confidence: 20 },
        { type: "ip", value: "2.2.2.2", count: 3, sources: ["feed1", "feed2"], confidence: 50 },
        { type: "ip", value: "3.3.3.3", count: 5, sources: ["feed1"], confidence: 30 },
      ];

      const top = getTopThreats(findings, 2);
      assert.strictEqual(top.length, 2);
      assert.strictEqual(top[0].value, "2.2.2.2");
      assert.strictEqual(top[1].value, "3.3.3.3");
    });

    it("should respect the limit parameter", () => {
      const findings = Array.from({ length: 20 }, (_, i) => ({
        type: "ip",
        value: `${i}.${i}.${i}.${i}`,
        count: 1,
        sources: ["feed1"],
        confidence: i,
      }));

      const top = getTopThreats(findings, 5);
      assert.strictEqual(top.length, 5);
    });
  });

  describe("groupByType", () => {
    it("should group findings by type", () => {
      const findings = [
        { type: "ip", value: "1.1.1.1" },
        { type: "ip", value: "2.2.2.2" },
        { type: "domain", value: "example.com" },
        { type: "hash", value: "abc123" },
      ];

      const grouped = groupByType(findings);
      assert.strictEqual(grouped.ip.length, 2);
      assert.strictEqual(grouped.domain.length, 1);
      assert.strictEqual(grouped.hash.length, 1);
      assert.strictEqual(grouped.url.length, 0);
    });
  });
});
