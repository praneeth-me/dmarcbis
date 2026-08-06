import { test } from "node:test";
import assert from "node:assert/strict";
import { parse } from "../src/parse.ts";

/**
 * parse() cases. Each row checks the mechanical reading of a string —
 * what tags came out, in what order, and what syntax-level issues (by
 * `code`) were raised. None of these rows care whether the *values* make
 * semantic sense (e.g. p=banana parses fine; validate() is what rejects
 * it) — that split is the whole point of keeping the two files separate.
 */
interface ParseCase {
  name: string;
  input: string;
  expectedTags: Record<string, string>;
  expectedIssueCodes: string[];
  expectedDuplicates?: string[];
}

const cases: ParseCase[] = [
  {
    name: "minimal valid record",
    input: "v=DMARC1; p=none",
    expectedTags: { v: "DMARC1", p: "none" },
    expectedIssueCodes: [],
  },
  {
    name: "full record with every current tag",
    input:
      "v=DMARC1; p=quarantine; sp=quarantine; np=reject; adkim=s; aspf=r; fo=1:d:s; rua=mailto:agg@example.com; ruf=mailto:forensic@example.com; t=y; psd=n",
    expectedTags: {
      v: "DMARC1",
      p: "quarantine",
      sp: "quarantine",
      np: "reject",
      adkim: "s",
      aspf: "r",
      fo: "1:d:s",
      rua: "mailto:agg@example.com",
      ruf: "mailto:forensic@example.com",
      t: "y",
      psd: "n",
    },
    expectedIssueCodes: [],
  },
  {
    name: "trailing semicolon is not an error",
    input: "v=DMARC1; p=reject;",
    expectedTags: { v: "DMARC1", p: "reject" },
    expectedIssueCodes: [],
  },
  {
    name: "double semicolon is an empty-segment issue",
    input: "v=DMARC1;; p=reject",
    expectedTags: { v: "DMARC1", p: "reject" },
    expectedIssueCodes: ["empty-segment"],
  },
  {
    name: "a chunk with no '=' is a malformed-chunk issue",
    input: "v=DMARC1; p=reject; oops",
    expectedTags: { v: "DMARC1", p: "reject" },
    expectedIssueCodes: ["malformed-chunk"],
  },
  {
    name: "mixed-case tag names normalize to lowercase",
    input: "V=DMARC1; ADKIM=s; Rua=mailto:dmarc@example.com",
    expectedTags: { v: "DMARC1", adkim: "s", rua: "mailto:dmarc@example.com" },
    expectedIssueCodes: [],
  },
  {
    name: "ragged internal whitespace around '=' and ';'",
    input: "  v = DMARC1  ;   p=reject   ;rua=mailto:dmarc@example.com   ",
    expectedTags: { v: "DMARC1", p: "reject", rua: "mailto:dmarc@example.com" },
    expectedIssueCodes: [],
  },
  {
    name: "a repeated tag: first occurrence wins, issue raised",
    input: "v=DMARC1; p=reject; p=none",
    expectedTags: { v: "DMARC1", p: "reject" },
    expectedIssueCodes: ["duplicate-tag"],
    expectedDuplicates: ["p"],
  },
  {
    name: "DNS TXT multi-string concatenation (dig-style quoting)",
    input: '"v=DMARC1; p=reject; " "rua=mailto:dmarc@example.com"',
    expectedTags: { v: "DMARC1", p: "reject", rua: "mailto:dmarc@example.com" },
    expectedIssueCodes: [],
  },
  {
    name: "a single fully-quoted string is dequoted the same way",
    input: '"v=DMARC1; p=none"',
    expectedTags: { v: "DMARC1", p: "none" },
    expectedIssueCodes: [],
  },
  {
    name: "empty string has nothing to parse",
    input: "",
    expectedTags: {},
    expectedIssueCodes: ["empty-record"],
  },
  {
    name: "whitespace-only string is treated as empty",
    input: "   ",
    expectedTags: {},
    expectedIssueCodes: ["empty-record"],
  },
  {
    name: "a string that isn't a DMARC record at all",
    input: "the quick brown fox jumps over the lazy dog",
    expectedTags: {},
    expectedIssueCodes: ["malformed-chunk"],
  },
  {
    name: "a tag name with non-letters is invalid, not silently coerced",
    input: "v=DMARC1; p1=reject",
    expectedTags: { v: "DMARC1" },
    expectedIssueCodes: ["invalid-tag-name"],
  },
];

test("parse()", async (t) => {
  for (const testCase of cases) {
    await t.test(testCase.name, () => {
      const result = parse(testCase.input);
      // Spread into a plain object before comparing: `tags` has a null
      // prototype (see parse.ts) and deepEqual under node:assert/strict
      // compares prototypes, so a direct comparison against an object
      // literal fails on that alone.
      assert.deepEqual({ ...result.tags }, testCase.expectedTags);
      assert.deepEqual(
        result.issues.map((issue) => issue.code),
        testCase.expectedIssueCodes,
      );
      if (testCase.expectedDuplicates) {
        assert.deepEqual(result.duplicateTags, testCase.expectedDuplicates);
      }
    });
  }
});

test("parse() preserves value casing — case sensitivity is validate()'s call", () => {
  const result = parse("v=DMARC1; p=REJECT");
  assert.equal(result.tags["p"], "REJECT");
});

test("parse() keeps every occurrence in `entries`, including duplicates", () => {
  const result = parse("v=DMARC1; p=reject; p=none");
  assert.deepEqual(
    result.entries.map((entry) => `${entry.name}=${entry.value}`),
    ["v=DMARC1", "p=reject", "p=none"],
  );
});

test("parse() reports input and normalized separately for dig-style quoting", () => {
  const raw = '"v=DMARC1; " "p=reject"';
  const result = parse(raw);
  assert.equal(result.input, raw);
  assert.equal(result.normalized, "v=DMARC1; p=reject");
});

test("parse().tags has a null prototype — no inherited members leak through", () => {
  const result = parse("v=DMARC1; p=none");
  // A plain-object `tags` returns Object.prototype's members for a lookup
  // of e.g. "constructor" or "toString", so a consumer checking
  // `tags[name] !== undefined` for a caller-supplied name gets a false
  // positive. There is nothing to inherit from a null-prototype object.
  assert.equal(Object.getPrototypeOf(result.tags), null);
  assert.equal(result.tags["constructor"], undefined);
  assert.equal(result.tags["toString"], undefined);
});

test("parse() records a tag literally named `constructor` like any other", () => {
  const result = parse("v=DMARC1; constructor=x");
  assert.equal(result.tags["constructor"], "x");
  assert.ok(result.entries.some((entry) => entry.name === "constructor"));
});

test("parse() never throws on randomly malformed input", () => {
  // Deterministic PRNG so a failure is reproducible from the seed rather
  // than being a heisenbug that vanishes on re-run.
  let seed = 0x9e3779b9;
  const random = () => {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    return seed / 0x100000000;
  };
  const alphabet = 'vpDMARC1=; \t"\\:,!@.<>&%_-\u00a0\u201c0123456789';

  for (let iteration = 0; iteration < 5000; iteration += 1) {
    const length = Math.floor(random() * 120);
    let input = "";
    for (let i = 0; i < length; i += 1) {
      input += alphabet[Math.floor(random() * alphabet.length)];
    }
    const result = parse(input);
    assert.ok(Array.isArray(result.issues), `issues missing for input: ${JSON.stringify(input)}`);
    for (const issue of result.issues) {
      assert.ok(typeof issue.code === "string" && issue.code.length > 0);
      assert.ok(["error", "warning", "info"].includes(issue.severity));
      assert.ok(typeof issue.message === "string" && issue.message.length > 0);
    }
  }
});
