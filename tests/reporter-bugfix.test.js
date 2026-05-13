import { describe, it } from "node:test";
import assert from "node:assert";
import { isValidFormat, getValidFormats } from "../src/utils/reporter.js";

describe("Reporter — Bug Fix Tests", () => {
  describe("M-07: Format validation", () => {
    it("should accept valid format names", () => {
      assert.strictEqual(isValidFormat("console"), true);
      assert.strictEqual(isValidFormat("json"), true);
      assert.strictEqual(isValidFormat("ndjson"), true);
      assert.strictEqual(isValidFormat("stix"), true);
    });

    it("should reject invalid format names", () => {
      assert.strictEqual(isValidFormat("xml"), false);
      assert.strictEqual(isValidFormat("csv"), false);
      assert.strictEqual(isValidFormat(""), false);
      assert.strictEqual(isValidFormat("HTML"), false);
    });

    it("should return all valid formats", () => {
      const formats = getValidFormats();
      assert.deepStrictEqual(formats, ["console", "json", "ndjson", "stix"]);
    });
  });
});