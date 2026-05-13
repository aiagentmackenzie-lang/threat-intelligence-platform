import { describe, it } from "node:test";
import assert from "node:assert";
import { enrichIOC } from "../src/enrichment/enrich.js";

describe("Enrichment", () => {
  describe("enrichIOC", () => {
    it("should return basic enrichment for IP", async () => {
      const ioc = {
        type: "ip",
        value: "1.1.1.1",
        source: "test",
        firstSeen: "2026-03-30T10:00:00Z",
        lastSeen: "2026-03-30T10:00:00Z",
      };

      const result = await enrichIOC(ioc);

      assert.strictEqual(result.type, "ip");
      assert.strictEqual(result.value, "1.1.1.1");
      assert.ok(result.attributes);
      assert.strictEqual(result.attributes.reputation, "unknown");
      assert.strictEqual(result.attributes.score, 0);
    });

    it("should return basic enrichment for domain", async () => {
      const ioc = {
        type: "domain",
        value: "example.com",
        source: "test",
        firstSeen: "2026-03-30T10:00:00Z",
        lastSeen: "2026-03-30T10:00:00Z",
      };

      const result = await enrichIOC(ioc);

      assert.strictEqual(result.type, "domain");
      assert.ok(result.attributes);
    });

    it("should return basic enrichment for hash", async () => {
      const ioc = {
        type: "hash",
        value: "d41d8cd98f00b204e9800998ecf8427e",
        hashType: "md5",
        source: "test",
        firstSeen: "2026-03-30T10:00:00Z",
        lastSeen: "2026-03-30T10:00:00Z",
      };

      const result = await enrichIOC(ioc);

      assert.strictEqual(result.type, "hash");
      assert.strictEqual(result.hashType, "md5");
      assert.ok(result.attributes);
    });

    it("should return basic enrichment for URL", async () => {
      const ioc = {
        type: "url",
        value: "http://example.com/malware",
        source: "test",
        firstSeen: "2026-03-30T10:00:00Z",
        lastSeen: "2026-03-30T10:00:00Z",
      };

      const result = await enrichIOC(ioc);

      assert.strictEqual(result.type, "url");
      assert.ok(result.attributes);
    });

    it("should handle unknown IOC types gracefully", async () => {
      const ioc = {
        type: "unknown",
        value: "test",
        source: "test",
        firstSeen: "2026-03-30T10:00:00Z",
        lastSeen: "2026-03-30T10:00:00Z",
      };

      const result = await enrichIOC(ioc);

      assert.strictEqual(result.type, "unknown");
      assert.ok(result.attributes);
      assert.strictEqual(result.attributes.reputation, "unknown");
    });
  });
});
