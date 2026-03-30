import { describe, it } from "node:test";
import assert from "node:assert";
import { analyzeThreat } from "../src/ai/analyzer.js";

describe("AI Analyzer", () => {
  describe("analyzeThreat", () => {
    it("should return disabled message when no API key", async () => {
      const ioc = {
        type: "ip",
        value: "1.1.1.1",
        sources: ["feed1"],
        confidence: 50,
      };

      // Save original env
      const originalKey = process.env.OPENAI_API_KEY;
      delete process.env.OPENAI_API_KEY;

      const result = await analyzeThreat(ioc, null);

      // Restore env
      if (originalKey) process.env.OPENAI_API_KEY = originalKey;

      assert.strictEqual(result.risk, "unknown");
      assert.strictEqual(result.aiEnabled, false);
      assert.ok(result.explanation.includes("disabled"));
    });

    it("should handle valid AI response", async () => {
      const ioc = {
        type: "ip",
        value: "1.1.1.1",
        sources: ["feed1"],
        confidence: 50,
        attributes: { reputation: "suspicious" },
      };

      // Mock LLM client
      const mockClient = {
        complete: async () => ({
          text: JSON.stringify({
            risk: "medium",
            explanation: "IP shows suspicious activity",
            recommendation: "Monitor traffic",
          }),
        }),
      };

      const result = await analyzeThreat(ioc, mockClient);

      assert.strictEqual(result.risk, "medium");
      assert.strictEqual(result.aiEnabled, true);
      assert.ok(result.explanation.includes("suspicious"));
    });

    it("should handle invalid AI response", async () => {
      const ioc = {
        type: "ip",
        value: "1.1.1.1",
        sources: ["feed1"],
      };

      // Mock LLM client with invalid response
      const mockClient = {
        complete: async () => ({
          text: "This is not valid JSON",
        }),
      };

      const result = await analyzeThreat(ioc, mockClient);

      assert.strictEqual(result.risk, "unknown");
      assert.ok(result.explanation.includes("failed"));
    });

    it("should handle schema validation failure", async () => {
      const ioc = {
        type: "ip",
        value: "1.1.1.1",
        sources: ["feed1"],
      };

      // Mock LLM client with missing required fields
      const mockClient = {
        complete: async () => ({
          text: JSON.stringify({ invalid: "data" }),
        }),
      };

      const result = await analyzeThreat(ioc, mockClient);

      assert.strictEqual(result.risk, "unknown");
      assert.ok(result.explanation.includes("invalid structure"));
    });
  });
});
