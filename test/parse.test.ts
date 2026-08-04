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
      assert.deepEqual(result.tags, testCase.expectedTags);
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
