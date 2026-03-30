import { describe, it } from "node:test";
import assert from "node:assert";
import { fetchThreatFeed } from "../src/ingestion/feeds.js";

describe("Feed Ingestion", () => {
  describe("fetchThreatFeed", () => {
    it("should return empty array on missing auth", async () => {
      const feedConfig = {
        name: "test-feed",
        url: "https://example.com/api",
        auth: {
          type: "header",
          headerName: "Authorization",
          env: "NONEXISTENT_KEY",
        },
      };

      const result = await fetchThreatFeed(feedConfig);
      assert.deepStrictEqual(result, []);
    });

    it("should return empty array on fetch error", async () => {
      const feedConfig = {
        name: "test-feed",
        url: "https://invalid-domain-12345.test",
      };

      const result = await fetchThreatFeed(feedConfig);
      assert.deepStrictEqual(result, []);
    });
  });
});
