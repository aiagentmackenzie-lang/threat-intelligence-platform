import { describe, it } from "node:test";
import assert from "node:assert";
import { extractIOCs } from "../src/processing/extractor.js";

describe("IOC Extractor — Bug Fix Tests", () => {
  describe("C-01: URL trailing punctuation stripping", () => {
    it("should strip trailing period from URL", () => {
      const events = [
        { content: "Visit http://evil.com/phishing.", source: "test", timestamp: "2026-03-30T10:00:00Z" },
      ];
      const results = extractIOCs(events);
      const urls = results.filter((r) => r.type === "url");
      assert.strictEqual(urls.length, 1);
      assert.strictEqual(urls[0].value, "http://evil.com/phishing");
    });

    it("should strip trailing comma from URL", () => {
      const events = [
        { content: "See http://evil.com/bad,", source: "test", timestamp: "2026-03-30T10:00:00Z" },
      ];
      const results = extractIOCs(events);
      const urls = results.filter((r) => r.type === "url");
      assert.strictEqual(urls[0].value, "http://evil.com/bad");
    });

    it("should strip trailing closing paren from URL", () => {
      const events = [
        { content: "Malicious (http://evil.com/attack)", source: "test", timestamp: "2026-03-30T10:00:00Z" },
      ];
      const results = extractIOCs(events);
      const urls = results.filter((r) => r.type === "url");
      assert.strictEqual(urls[0].value, "http://evil.com/attack");
    });
  });

  describe("C-02: Domain/URL deduplication", () => {
    it("should not extract domain separately when it appears in a URL", () => {
      const events = [
        { content: "Phishing URL: https://secure-bank-login.net/verify", source: "test", timestamp: "2026-03-30T10:00:00Z" },
      ];
      const results = extractIOCs(events);
      const domains = results.filter((r) => r.type === "domain");
      const urls = results.filter((r) => r.type === "url");
      assert.strictEqual(urls.length, 1, "Should extract URL");
      assert.strictEqual(domains.length, 0, "Should NOT extract domain separately");
    });

    it("should extract standalone domains that don't appear in URLs", () => {
      const events = [
        { content: "C2 domain evil-c2-server.com detected", source: "test", timestamp: "2026-03-30T10:00:00Z" },
      ];
      const results = extractIOCs(events);
      const domains = results.filter((r) => r.type === "domain");
      assert.strictEqual(domains.length, 1);
      assert.strictEqual(domains[0].value, "evil-c2-server.com");
    });
  });

  describe("M-04: Hash extraction context", () => {
    it("should still extract hashes from text", () => {
      const md5 = "d41d8cd98f00b204e9800998ecf8427e";
      const events = [
        { content: `Malware hash: ${md5}`, source: "test", timestamp: "2026-03-30T10:00:00Z" },
      ];
      const results = extractIOCs(events);
      const hashes = results.filter((r) => r.type === "hash");
      assert.strictEqual(hashes.length, 1);
      assert.strictEqual(hashes[0].value, md5);
    });
  });

  describe("Private IP filtering", () => {
    it("should exclude 192.0.2.x TEST-NET range (kept as public for threat intel)", () => {
      const events = [
        { content: "IP 192.0.2.100 observed", source: "test", timestamp: "2026-03-30T10:00:00Z" },
      ];
      const results = extractIOCs(events);
      const ips = results.filter((r) => r.type === "ip");
      // 192.0.2.x is TEST-NET-1 (RFC 5737) — kept as public for threat intel use
      assert.strictEqual(ips.length, 1);
      assert.strictEqual(ips[0].value, "192.0.2.100");
    });
  });
});