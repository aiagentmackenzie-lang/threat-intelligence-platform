import { describe, it } from "node:test";
import assert from "node:assert";
import { extractIOCs, getIOCStats } from "../src/processing/extractor.js";

describe("IOC Extractor", () => {
  describe("IP extraction", () => {
    it("should extract valid public IPs", () => {
      const events = [
        {
          content: "Malicious activity from 185.220.101.1",
          source: "test",
          timestamp: "2026-03-30T10:00:00Z",
        },
      ];

      const results = extractIOCs(events);
      assert.strictEqual(results.length, 1);
      assert.strictEqual(results[0].type, "ip");
      assert.strictEqual(results[0].value, "185.220.101.1");
    });

    it("should exclude private IPs", () => {
      const events = [
        {
          content: "10.0.0.1 192.168.1.1 127.0.0.1 8.8.8.8",
          source: "test",
          timestamp: "2026-03-30T10:00:00Z",
        },
      ];

      const results = extractIOCs(events);
      const ips = results.filter((r) => r.type === "ip");
      assert.strictEqual(ips.length, 1);
      assert.strictEqual(ips[0].value, "8.8.8.8");
    });

    it("should exclude invalid IPs", () => {
      const events = [
        {
          content: "256.1.1.1 192.300.1.1 1.2.3",
          source: "test",
          timestamp: "2026-03-30T10:00:00Z",
        },
      ];

      const results = extractIOCs(events);
      const ips = results.filter((r) => r.type === "ip");
      assert.strictEqual(ips.length, 0);
    });
  });

  describe("Domain extraction", () => {
    it("should extract valid domains", () => {
      const events = [
        {
          content: "Phishing domain: evil.com",
          source: "test",
          timestamp: "2026-03-30T10:00:00Z",
        },
      ];

      const results = extractIOCs(events);
      const domains = results.filter((r) => r.type === "domain");
      assert.strictEqual(domains.length, 1);
      assert.strictEqual(domains[0].value, "evil.com");
    });

    it("should normalize domains to lowercase", () => {
      const events = [
        {
          content: "EXAMPLE.COM",
          source: "test",
          timestamp: "2026-03-30T10:00:00Z",
        },
      ];

      const results = extractIOCs(events);
      const domains = results.filter((r) => r.type === "domain");
      assert.strictEqual(domains[0].value, "example.com");
    });

    it("should exclude private TLDs", () => {
      const events = [
        {
          content: "test.local test.test example.localhost",
          source: "test",
          timestamp: "2026-03-30T10:00:00Z",
        },
      ];

      const results = extractIOCs(events);
      const domains = results.filter((r) => r.type === "domain");
      assert.strictEqual(domains.length, 0);
    });
  });

  describe("Hash extraction", () => {
    it("should extract MD5 hashes", () => {
      const md5 = "d41d8cd98f00b204e9800998ecf8427e";
      const events = [
        {
          content: `Malware hash: ${md5}`,
          source: "test",
          timestamp: "2026-03-30T10:00:00Z",
        },
      ];

      const results = extractIOCs(events);
      const hashes = results.filter((r) => r.type === "hash");
      assert.strictEqual(hashes.length, 1);
      assert.strictEqual(hashes[0].value, md5);
      assert.strictEqual(hashes[0].hashType, "md5");
    });

    it("should extract SHA256 hashes", () => {
      const sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
      const events = [
        {
          content: `SHA256: ${sha256}`,
          source: "test",
          timestamp: "2026-03-30T10:00:00Z",
        },
      ];

      const results = extractIOCs(events);
      const hashes = results.filter((r) => r.type === "hash");
      assert.strictEqual(hashes.length, 1);
      assert.strictEqual(hashes[0].hashType, "sha256");
    });

    it("should normalize hashes to lowercase", () => {
      const events = [
        {
          content: "D41D8CD98F00B204E9800998ECF8427E",
          source: "test",
          timestamp: "2026-03-30T10:00:00Z",
        },
      ];

      const results = extractIOCs(events);
      const hashes = results.filter((r) => r.type === "hash");
      assert.strictEqual(hashes[0].value, "d41d8cd98f00b204e9800998ecf8427e");
    });
  });

  describe("URL extraction", () => {
    it("should extract valid URLs", () => {
      const events = [
        {
          content: "Phishing URL: http://evil.com/phishing",
          source: "test",
          timestamp: "2026-03-30T10:00:00Z",
        },
      ];

      const results = extractIOCs(events);
      const urls = results.filter((r) => r.type === "url");
      assert.strictEqual(urls.length, 1);
      assert.strictEqual(urls[0].value, "http://evil.com/phishing");
    });

    it("should extract HTTPS URLs", () => {
      const events = [
        {
          content: "https://secure.evil.com/malware",
          source: "test",
          timestamp: "2026-03-30T10:00:00Z",
        },
      ];

      const results = extractIOCs(events);
      const urls = results.filter((r) => r.type === "url");
      assert.strictEqual(urls.length, 1);
      assert.ok(urls[0].value.startsWith("https://"));
    });
  });

  describe("getIOCStats", () => {
    it("should return correct statistics", () => {
      const iocs = [
        { type: "ip", value: "1.1.1.1" },
        { type: "ip", value: "2.2.2.2" },
        { type: "domain", value: "example.com" },
        { type: "hash", value: "abc123" },
        { type: "url", value: "http://test.com" },
      ];

      const stats = getIOCStats(iocs);
      assert.strictEqual(stats.total, 5);
      assert.strictEqual(stats.ip, 2);
      assert.strictEqual(stats.domain, 1);
      assert.strictEqual(stats.hash, 1);
      assert.strictEqual(stats.url, 1);
    });
  });
});
