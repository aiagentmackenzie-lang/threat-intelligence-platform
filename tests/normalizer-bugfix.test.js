import { describe, it } from "node:test";
import assert from "node:assert";
import { normalizeData } from "../src/processing/normalizer.js";

describe("Normalizer — Bug Fix Tests", () => {
  describe("M-05: Empty object data rejection", () => {
    it("should reject events with empty data object", () => {
      const rawItems = [{ source: "test", data: {} }];
      const results = normalizeData(rawItems, "test-source");
      assert.strictEqual(results.length, 0, "Empty data object should be rejected");
    });

    it("should accept events with meaningful data object", () => {
      const rawItems = [{ source: "test", data: { key: "value" } }];
      const results = normalizeData(rawItems, "test-source");
      assert.strictEqual(results.length, 1);
    });

    it("should accept events with string data", () => {
      const rawItems = [{ source: "test", data: "Important threat intel" }];
      const results = normalizeData(rawItems, "test-source");
      assert.strictEqual(results.length, 1);
      assert.strictEqual(results[0].content, "Important threat intel");
    });
  });
});