import { test } from "node:test";
import assert from "node:assert/strict";
import { parse } from "../src/parse.ts";
import { validate } from "../src/validate.ts";

/**
 * validate() cases. Each row is a raw record plus which diagnostic
 * `code`s must appear and which must not — not a full deep-equal of the
 * diagnostics array, because most rows only care about one or two specific
 * findings and pinning the exact array would make every row brittle
 * against unrelated diagnostics (e.g. an unrelated "missing-policy"
 * warning showing up on a record that wasn't trying to test that).
 */
interface ValidateCase {
  name: string;
  record: string;
  mustInclude: string[];
  mustExclude?: string[];
  /** For codes that can legitimately appear more than once (e.g. three
   * separate "removed-tag" findings for pct/rf/ri) — checked by exact
   * count rather than `mustInclude`'s "at least one" test. */
  mustIncludeCounts?: Record<string, number>;
}

const cases: ValidateCase[] = [
  {
    name: "valid minimal record: no findings at all",
    record: "v=DMARC1; p=none",
    mustInclude: [],
    mustExclude: [
      "missing-version",
      "version-not-first",
      "invalid-version-value",
      "missing-policy",
      "invalid-p-value",
    ],
  },
  {
    name: "valid full record: no errors, only the expected np=reject notes",
    record:
      "v=DMARC1; p=quarantine; sp=quarantine; np=reject; adkim=s; aspf=r; fo=1:d:s; rua=mailto:agg@example.com; t=n; psd=n",
    mustInclude: ["np-reject-safe", "np-compact-denial-caveat"],
    mustExclude: [
      "missing-version",
      "invalid-p-value",
      "invalid-sp-value",
      "invalid-np-value",
      "invalid-adkim-value",
      "invalid-aspf-value",
      "invalid-fo-value",
      "invalid-t-value",
      "invalid-psd-value",
      "missing-policy",
    ],
  },

  // --- removed tags (RFC 7489 -> RFC 9989) ---
  {
    name: "pct= is flagged as removed",
    record: "v=DMARC1; p=quarantine; pct=50",
    mustInclude: ["removed-tag"],
  },
  {
    name: "rf= is flagged as removed",
    record: "v=DMARC1; p=quarantine; rf=afrf",
    mustInclude: ["removed-tag"],
  },
  {
    name: "ri= is flagged as removed",
    record: "v=DMARC1; p=quarantine; ri=86400",
    mustInclude: ["removed-tag"],
  },
  {
    name: "a legacy RFC 7489 record trips all three removed-tag findings",
    record: "v=DMARC1; p=quarantine; pct=50; rf=afrf; ri=86400; rua=mailto:dmarc@example.com",
    mustInclude: ["removed-tag"],
    mustIncludeCounts: { "removed-tag": 3 },
  },

  // --- new tags (RFC 9989) ---
  {
    name: "t=y parses and validates cleanly",
    record: "v=DMARC1; p=reject; t=y",
    mustInclude: [],
    mustExclude: ["invalid-t-value"],
  },
  {
    name: "t= with an invalid value is flagged",
    record: "v=DMARC1; p=reject; t=maybe",
    mustInclude: ["invalid-t-value"],
  },
  {
    name: "np=quarantine validates cleanly, without the reject-only notes",
    record: "v=DMARC1; p=quarantine; np=quarantine",
    mustInclude: [],
    mustExclude: ["invalid-np-value", "np-reject-safe", "np-compact-denial-caveat"],
  },
  {
    name: "np=reject triggers both the safe-default note and the DNSSEC caveat",
    record: "v=DMARC1; p=reject; np=reject",
    mustInclude: ["np-reject-safe", "np-compact-denial-caveat"],
  },
  {
    name: "np= with an invalid value is flagged",
    record: "v=DMARC1; p=reject; np=banana",
    mustInclude: ["invalid-np-value"],
  },
  {
    name: "psd=y parses and validates cleanly",
    record: "v=DMARC1; p=reject; psd=y",
    mustInclude: [],
    mustExclude: ["invalid-psd-value"],
  },
  {
    name: "psd= with an invalid value is flagged",
    record: "v=DMARC1; p=reject; psd=maybe",
    mustInclude: ["invalid-psd-value"],
  },

  // --- v= presence / position / value ---
  {
    name: "missing v= entirely",
    record: "p=reject; rua=mailto:dmarc@example.com",
    mustInclude: ["missing-version"],
  },
  {
    name: "v= present but not first",
    record: "p=reject; v=DMARC1",
    mustInclude: ["version-not-first"],
  },
  {
    name: "v= with the wrong value",
    record: "v=DMARC2; p=reject",
    mustInclude: ["invalid-version-value"],
  },
  {
    name: "v= is case-sensitive — lowercase 'dmarc1' is invalid",
    record: "v=dmarc1; p=reject",
    mustInclude: ["invalid-version-value"],
  },

  // --- invalid tag values ---
  {
    name: "invalid p= value",
    record: "v=DMARC1; p=maybe",
    mustInclude: ["invalid-p-value"],
  },
  {
    name: "invalid sp= value",
    record: "v=DMARC1; p=reject; sp=maybe",
    mustInclude: ["invalid-sp-value"],
  },
  {
    name: "invalid fo= value (mixing both 0 and 1 is not allowed)",
    record: "v=DMARC1; p=reject; fo=0:1",
    mustInclude: ["invalid-fo-value"],
  },
  {
    name: "valid fo= combinations validate cleanly",
    record: "v=DMARC1; p=reject; fo=1:d:s",
    mustInclude: [],
    mustExclude: ["invalid-fo-value"],
  },
  {
    name: "invalid adkim= value",
    record: "v=DMARC1; p=reject; adkim=x",
    mustInclude: ["invalid-adkim-value"],
  },
  {
    name: "invalid aspf= value",
    record: "v=DMARC1; p=reject; aspf=x",
    mustInclude: ["invalid-aspf-value"],
  },
  {
    name: "invalid reporting URI on rua=",
    record: "v=DMARC1; p=reject; rua=not-a-uri",
    mustInclude: ["invalid-report-uri"],
  },

  // --- ruf privacy note ---
  {
    name: "ruf= always carries a privacy notice",
    record: "v=DMARC1; p=reject; ruf=mailto:forensic@example.com",
    mustInclude: ["ruf-privacy-notice"],
  },
  {
    name: "no ruf= means no privacy notice",
    record: "v=DMARC1; p=reject; rua=mailto:agg@example.com",
    mustInclude: [],
    mustExclude: ["ruf-privacy-notice"],
  },

  // --- structural / messiness cases ---
  {
    name: "a duplicated tag surfaces validate()'s merged view of parse's issue",
    record: "v=DMARC1; p=reject; p=none",
    mustInclude: ["duplicate-tag"],
  },
  {
    name: "whitespace and casing chaos still validates the intended record",
    record: "  V = DMARC1 ; P=REJECT ; ADKIM=S ",
    mustInclude: [],
    mustExclude: ["missing-version", "invalid-p-value", "invalid-adkim-value"],
  },
  {
    name: "missing p= on what looks like an org-domain policy record",
    record: "v=DMARC1; rua=mailto:dmarc@example.com",
    mustInclude: ["missing-policy"],
  },
  {
    name: "empty string",
    record: "",
    mustInclude: ["empty-record", "missing-version"],
  },
  {
    name: "a string that is not a DMARC record at all",
    record: "the quick brown fox jumps over the lazy dog",
    mustInclude: ["malformed-chunk", "missing-version"],
  },
  {
    name: "an unrecognized tag is noted but not treated as an error",
    record: "v=DMARC1; p=reject; foo=bar",
    mustInclude: ["unrecognized-tag"],
  },
];

test("validate()", async (t) => {
  for (const testCase of cases) {
    await t.test(testCase.name, () => {
      const diagnostics = validate(parse(testCase.record));
      const codes = diagnostics.map((diagnostic) => diagnostic.code);

      for (const expectedCode of testCase.mustInclude) {
        assert.ok(
          codes.includes(expectedCode),
          `expected "${expectedCode}" in [${codes.join(", ")}]`,
        );
      }
      for (const forbiddenCode of testCase.mustExclude ?? []) {
        assert.ok(
          !codes.includes(forbiddenCode),
          `did not expect "${forbiddenCode}" in [${codes.join(", ")}]`,
        );
      }
      for (const [code, expectedCount] of Object.entries(testCase.mustIncludeCounts ?? {})) {
        const actualCount = codes.filter((c) => c === code).length;
        assert.equal(
          actualCount,
          expectedCount,
          `expected "${code}" to appear ${expectedCount} time(s), found ${actualCount} in [${codes.join(", ")}]`,
        );
      }
    });
  }
});

test("validate() never throws, even on garbage input", () => {
  const inputs = ["", "   ", "not a record", "v=DMARC1;;;===;;", "\x00\x01\x02", "a".repeat(10_000)];
  for (const input of inputs) {
    assert.doesNotThrow(() => validate(parse(input)));
  }
});

test("every diagnostic carries a code, severity, tag, and message", () => {
  const diagnostics = validate(
    parse("v=DMARC1; p=quarantine; pct=50; np=reject; foo=bar; p=none"),
  );
  assert.ok(diagnostics.length > 0);
  for (const diagnostic of diagnostics) {
    assert.equal(typeof diagnostic.code, "string");
    assert.ok(["error", "warning", "info"].includes(diagnostic.severity));
    assert.ok(diagnostic.tag === null || typeof diagnostic.tag === "string");
    assert.equal(typeof diagnostic.message, "string");
    assert.ok(diagnostic.message.length > 0);
  }
});

test("the DNSSEC compact-denial caveat names the affected providers", () => {
  const diagnostics = validate(parse("v=DMARC1; p=reject; np=reject"));
  const caveat = diagnostics.find((d) => d.code === "np-compact-denial-caveat");
  assert.ok(caveat, "expected an np-compact-denial-caveat diagnostic");
  for (const provider of ["Cloudflare", "Route 53", "NS1", "Azure"]) {
    assert.ok(caveat!.message.includes(provider), `expected message to mention ${provider}`);
  }
});
