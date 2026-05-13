import { describe, it } from "node:test";
import assert from "node:assert";
import { normalizeData, normalizeAbuseIPDB } from "../src/processing/normalizer.js";

describe("Normalizer", () => {
  describe("normalizeData", () => {
    it("should normalize raw events to common format", () => {
      const rawItems = [
        { source: "feed1", timestamp: "2026-03-30T10:00:00Z", text: "Malicious IP detected" },
      ];

      const results = normalizeData(rawItems, "test-source");
      assert.strictEqual(results.length, 1);
      assert.strictEqual(results[0].source, "feed1");
      assert.strictEqual(results[0].content, "Malicious IP detected");
    });

    it("should handle missing timestamps", () => {
      const rawItems = [{ source: "feed1", text: "Alert" }];

      const results = normalizeData(rawItems);
      assert.ok(results[0].timestamp);
      assert.ok(new Date(results[0].timestamp).toISOString());
    });

    it("should handle missing source", () => {
      const rawItems = [{ text: "Alert" }];

      const results = normalizeData(rawItems, "default-source");
      assert.strictEqual(results[0].source, "default-source");
    });

    it("should reject invalid events", () => {
      const rawItems = [{ invalid: "data" }];

      const results = normalizeData(rawItems);
      assert.strictEqual(results.length, 0);
    });

    it("should handle single item input", () => {
      const rawItem = { text: "Single alert" };

      const results = normalizeData(rawItem);
      assert.strictEqual(results.length, 1);
      assert.strictEqual(results[0].content, "Single alert");
    });

    it("should extract content from data field", () => {
      const rawItems = [{ data: "Content from data field" }];

      const results = normalizeData(rawItems);
      assert.strictEqual(results[0].content, "Content from data field");
    });
  });

  describe("normalizeAbuseIPDB", () => {
    it("should normalize AbuseIPDB response", () => {
      const response = {
        data: [
          {
            ipAddress: "192.0.2.1",
            comment: "Brute force attack",
            confidenceScore: 100,
            countryCode: "US",
          },
        ],
      };

      const results = normalizeAbuseIPDB(response, "abuseipdb");
      assert.strictEqual(results.length, 1);
      assert.strictEqual(results[0].source, "abuseipdb");
      assert.ok(results[0].content.includes("192.0.2.1"));
      assert.ok(results[0].content.includes("Brute force attack"));
      assert.strictEqual(results[0].metadata.ipAddress, "192.0.2.1");
    });

    it("should handle empty response", () => {
      const response = { data: [] };
      const results = normalizeAbuseIPDB(response);
      assert.strictEqual(results.length, 0);
    });

    it("should handle null response", () => {
      const results = normalizeAbuseIPDB(null);
      assert.strictEqual(results.length, 0);
    });
  });
});
