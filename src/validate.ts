import type { Diagnostic, ParsedRecord } from "./types.ts";

/**
 * parse() and validate() are two different jobs, kept in two different
 * files on purpose. parse() answers "what does this string say" — pure
 * syntax, no opinions. validate() answers "is what it says correct and
 * current" — that's where RFC 9989 (DMARCbis) itself lives, including the
 * parts of it that are genuinely new since RFC 7489 (2015):
 *
 *   - pct, rf and ri are gone. A record built by copying an old example
 *     off the internet will very likely still have pct= on it.
 *   - t, np and psd are new. Nothing checks for them yet because nothing
 *     else validates against RFC 9989 yet — that's this library's reason
 *     to exist.
 *
 * Keeping the two apart also means a caller who only wants a syntax check
 * (e.g. a DNS zone-file linter that doesn't want to make RFC-currency
 * judgement calls) can use parse() alone.
 *
 * validate() never throws and never returns a bare pass/fail — every
 * finding is a Diagnostic carrying a stable `code`, a `severity`, which
 * `tag` it's about, and a message meant to be read by the person holding
 * the zone file, not the person who wrote the RFC.
 */

/** Tags RFC 9989 still defines. Anything else present is either a tag
 * that's been removed (see REMOVED_TAGS) or one this record's author made
 * up / mistyped. */
const CURRENT_TAGS = new Set([
  "v",
  "p",
  "sp",
  "np",
  "adkim",
  "aspf",
  "fo",
  "rua",
  "ruf",
  "t",
  "psd",
]);

const REMOVED_TAGS: Record<string, string> = {
  pct: `pct= was removed in RFC 9989 (DMARCbis). DMARCbis receivers ignore it outright, which quietly turns a partial rollout into full enforcement at whatever p= says the moment a receiver updates to the new spec. If a gradual rollout was the goal, use t=y (testing mode) instead.`,
  rf: `rf= (requested failure-report format) was removed in RFC 9989. Report format is no longer sender-configurable — receivers decide unilaterally, and RFC 9990 makes XML the mandatory aggregate-report format regardless. This tag is silently ignored by DMARCbis receivers.`,
  ri: `ri= (requested aggregate-report interval) was removed in RFC 9989. Reporting interval is no longer sender-configurable — receivers choose their own schedule. This tag is silently ignored by DMARCbis receivers.`,
};

const POLICY_VALUES = new Set(["none", "quarantine", "reject"]);
const RELAXED_STRICT_VALUES = new Set(["r", "s"]);
const YES_NO_VALUES = new Set(["y", "n"]);
const PSD_VALUES = new Set(["y", "n", "u"]);

/**
 * RFC 9989's ABNF for fo (dmarc-fo) is three overlapping alternatives that
 * all boil down to the same practical shape: an optional single "0" or "1"
 * (the two are mutually exclusive — they're different definitions of
 * "failure", not combinable flags) plus any number of "d"/"s" tokens,
 * colon-separated in any order:
 *
 *   dmarc-fo   = ("0" / "1") *(":" dmarc-afrf)
 *              / dmarc-afrf [":" ("0"/"1")] [":" dmarc-afrf]
 *              / *(dmarc-afrf ":") ("0" / "1")
 *   dmarc-afrf = "d" / "s"
 *
 * Rather than encode all three alternatives literally (they overlap enough
 * that doing so is more confusing than the grammar it's copying), this
 * checks the same constraint the grammar is actually expressing.
 */
function isValidFoValue(raw: string): boolean {
  const tokens = raw.split(":").map((token) => token.trim().toLowerCase());
  if (tokens.some((token) => token.length === 0)) return false;
  const allowed = new Set(["0", "1", "d", "s"]);
  if (!tokens.every((token) => allowed.has(token))) return false;
  const numericTokenCount = tokens.filter((token) => token === "0" || token === "1").length;
  return numericTokenCount <= 1;
}

/** rua/ruf hold a comma-separated dmarc-urilist. Each entry is a URI
 * (mailto: in practice, though the ABNF doesn't forbid others — https: is
 * the other one RFC 9990 explicitly supports for aggregate reports) with an
 * optional "!<size><unit>" cap, e.g. "mailto:dmarc@example.com!10m". This
 * doesn't attempt full RFC 3986 URI validation — it's a sanity check for
 * "did you paste a plausible reporting address," not a URI RFC conformance
 * suite. */
const REPORT_URI_PATTERN = /^(mailto|https):\S+?(![0-9]+[kmgt]?)?$/i;

function findInvalidReportUris(raw: string): string[] {
  const entries = raw
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  if (entries.length === 0) return [raw];
  return entries.filter((entry) => !REPORT_URI_PATTERN.test(entry));
}

export function validate(parsed: ParsedRecord): Diagnostic[] {
  // Anything parse() already flagged (a malformed chunk, a duplicated tag)
  // is still true here — validate() adds to that list rather than
  // re-deriving it, so a caller gets one complete picture from a single
  // call instead of having to merge parse().issues in themselves.
  const diagnostics: Diagnostic[] = [...parsed.issues];

  validateVersionTag(parsed, diagnostics);
  validatePolicyTags(parsed, diagnostics);
  validateAlignmentTags(parsed, diagnostics);
  validateFoTag(parsed, diagnostics);
  validateBooleanAndPsdTags(parsed, diagnostics);
  validateReportingTags(parsed, diagnostics);
  validateRemovedTags(parsed, diagnostics);
  validateUnrecognizedTags(parsed, diagnostics);

  return diagnostics;
}

function validateVersionTag(parsed: ParsedRecord, diagnostics: Diagnostic[]): void {
  const versionValue = parsed.tags["v"];

  if (versionValue === undefined) {
    diagnostics.push({
      code: "missing-version",
      severity: "error",
      tag: "v",
      message: `No v=DMARC1 tag was found. Without it, receivers MUST disregard this record entirely — it isn't treated as a DMARC record at all, regardless of what else it contains.`,
    });
    return;
  }

  // RFC 9989's ABNF defines the version tag's value with %s"DMARC1" — the
  // %s prefix is what marks it case-sensitive in ABNF (RFC 5234); every
  // other tag's values in this record are ordinary case-insensitive ABNF
  // string literals, which is why only this one check compares raw case
  // instead of lower-casing first.
  const firstEntry = parsed.entries[0];
  const versionIsFirst = firstEntry?.name === "v";

  if (!versionIsFirst) {
    diagnostics.push({
      code: "version-not-first",
      severity: "error",
      tag: "v",
      message: `v=DMARC1 must be the first tag in the record; "${firstEntry?.rawName ?? "?"}" came first instead. Per RFC 9989 §4.8, the entire record MUST be ignored when this happens — not just the v= tag.`,
    });
  }

  if (versionValue !== "DMARC1") {
    diagnostics.push({
      code: "invalid-version-value",
      severity: "error",
      tag: "v",
      message: `v= must be exactly "DMARC1" (case-sensitive) — found "${versionValue}". Unlike this record's other tags, the version value is compared byte-for-byte, so "dmarc1" or "Dmarc1" is not accepted.`,
    });
  }
}

function validatePolicyTags(parsed: ParsedRecord, diagnostics: Diagnostic[]): void {
  const p = parsed.tags["p"];
  const sp = parsed.tags["sp"];
  const np = parsed.tags["np"];

  if (p === undefined) {
    diagnostics.push({
      code: "missing-policy",
      severity: "warning",
      tag: "p",
      message: `No p= tag was found. RFC 9989 treats a policy record with no p= as if it said p=none — nothing will happen to mail that fails authentication unless sp=/np= say otherwise. Add an explicit p= if that's not the intent.`,
    });
  } else if (!POLICY_VALUES.has(p.toLowerCase())) {
    diagnostics.push({
      code: "invalid-p-value",
      severity: "error",
      tag: "p",
      message: `p="${p}" isn't valid — must be one of none, quarantine, or reject.`,
    });
  }

  if (sp !== undefined && !POLICY_VALUES.has(sp.toLowerCase())) {
    diagnostics.push({
      code: "invalid-sp-value",
      severity: "error",
      tag: "sp",
      message: `sp="${sp}" isn't valid — must be one of none, quarantine, or reject.`,
    });
  }

  if (np !== undefined) {
    if (!POLICY_VALUES.has(np.toLowerCase())) {
      diagnostics.push({
        code: "invalid-np-value",
        severity: "error",
        tag: "np",
        message: `np="${np}" isn't valid — must be one of none, quarantine, or reject.`,
      });
    } else if (np.toLowerCase() === "reject") {
      diagnostics.push({
        code: "np-reject-safe",
        severity: "info",
        tag: "np",
        message: `np=reject is one of the few enforcement settings that's reasonable to set immediately, without a gradual none -> quarantine -> reject rollout: a subdomain that doesn't exist cannot originate legitimate mail, so there's no legitimate traffic for a false positive to break.`,
      });
      diagnostics.push({
        code: "np-compact-denial-caveat",
        severity: "info",
        tag: "np",
        message: `np= relies on the receiver seeing an NXDOMAIN response for the non-existent subdomain. Some DNSSEC-signed providers instead use "compact denial of existence" (RFC 9824): they return NOERROR with an NSEC record's NXNAME bit set, rather than NXDOMAIN. Cloudflare (since 2016), NS1 (2019), AWS Route 53 (2020) and Azure DNS (2025) all do this by default. A receiver that checks strictly for NXDOMAIN will conclude the subdomain exists and silently skip this policy. There's no sender-side fix — confirm your receiving mail providers recognize NXNAME before treating np=reject as airtight.`,
      });
    }
  }
}

function validateAlignmentTags(parsed: ParsedRecord, diagnostics: Diagnostic[]): void {
  const adkim = parsed.tags["adkim"];
  const aspf = parsed.tags["aspf"];

  if (adkim !== undefined && !RELAXED_STRICT_VALUES.has(adkim.toLowerCase())) {
    diagnostics.push({
      code: "invalid-adkim-value",
      severity: "error",
      tag: "adkim",
      message: `adkim="${adkim}" isn't valid — must be "r" (relaxed) or "s" (strict).`,
    });
  }

  if (aspf !== undefined && !RELAXED_STRICT_VALUES.has(aspf.toLowerCase())) {
    diagnostics.push({
      code: "invalid-aspf-value",
      severity: "error",
      tag: "aspf",
      message: `aspf="${aspf}" isn't valid — must be "r" (relaxed) or "s" (strict).`,
    });
  }
}

function validateFoTag(parsed: ParsedRecord, diagnostics: Diagnostic[]): void {
  const fo = parsed.tags["fo"];
  if (fo !== undefined && !isValidFoValue(fo)) {
    diagnostics.push({
      code: "invalid-fo-value",
      severity: "error",
      tag: "fo",
      message: `fo="${fo}" isn't valid — must be a colon-separated combination of "0"/"1" (pick at most one) and "d"/"s", e.g. "0", "1:d", or "d:s".`,
    });
  }
}

function validateBooleanAndPsdTags(parsed: ParsedRecord, diagnostics: Diagnostic[]): void {
  const t = parsed.tags["t"];
  if (t !== undefined && !YES_NO_VALUES.has(t.toLowerCase())) {
    diagnostics.push({
      code: "invalid-t-value",
      severity: "error",
      tag: "t",
      message: `t="${t}" isn't valid — must be "y" or "n". t=y is RFC 9989's replacement for the old pct=<N> partial rollout: instead of enforcing against a percentage of mail, it asks receivers to apply the policy one level below the one you published.`,
    });
  } else if (t?.toLowerCase() === "y") {
    // RFC 9989 §4.7 defines t=y as a *downgrade by one level*, not as a
    // suspension of the policy. That distinction is easy to get wrong — the
    // intuitive reading is "testing means nothing happens", which is only
    // true at p=quarantine. At p=reject, t=y still quarantines. Since t= is
    // the replacement for pct= and everyone's muscle memory is the old
    // percentage ramp, spell the actual effect out rather than assuming the
    // reader infers it.
    const policy = parsed.tags["p"]?.toLowerCase();
    const effect =
      policy === "reject"
        ? `you published p=reject, so failing mail is being quarantined, not rejected`
        : policy === "quarantine"
          ? `you published p=quarantine, so failing mail is being treated as p=none — nothing is happening to it yet`
          : `it applies one level below whatever p= says (reject becomes quarantine; quarantine becomes none). At p=none there is no lower level, so it changes nothing`;
    diagnostics.push({
      code: "t-testing-mode",
      severity: "info",
      tag: "t",
      message: `t=y puts this record in testing mode: receivers apply the policy one level below the one published — ${effect}. Reports still arrive as though the full policy were in force, which is the point: you see the impact before taking it. Drop t=y when you want the published policy to actually apply.`,
    });
  }

  const psd = parsed.tags["psd"];
  if (psd !== undefined && !PSD_VALUES.has(psd.toLowerCase())) {
    diagnostics.push({
      code: "invalid-psd-value",
      severity: "error",
      tag: "psd",
      message: `psd="${psd}" isn't valid — must be "y" (this is a public suffix domain), "n" (it isn't), or "u" (undeclared).`,
    });
  }
}

function validateReportingTags(parsed: ParsedRecord, diagnostics: Diagnostic[]): void {
  const rua = parsed.tags["rua"];
  if (rua !== undefined) {
    const invalid = findInvalidReportUris(rua);
    if (invalid.length > 0) {
      diagnostics.push({
        code: "invalid-report-uri",
        severity: "error",
        tag: "rua",
        message: `rua= contains ${invalid.length === 1 ? "an entry" : "entries"} that ${invalid.length === 1 ? "isn't" : "aren't"} a valid reporting URI: ${invalid.map((entry) => `"${entry}"`).join(", ")}. Expected mailto: or https: URIs, comma-separated, e.g. "mailto:dmarc@example.com".`,
      });
    }
  }

  const ruf = parsed.tags["ruf"];
  if (ruf !== undefined) {
    const invalid = findInvalidReportUris(ruf);
    if (invalid.length > 0) {
      diagnostics.push({
        code: "invalid-report-uri",
        severity: "error",
        tag: "ruf",
        message: `ruf= contains ${invalid.length === 1 ? "an entry" : "entries"} that ${invalid.length === 1 ? "isn't" : "aren't"} a valid reporting URI: ${invalid.map((entry) => `"${entry}"`).join(", ")}. Expected mailto: or https: URIs, comma-separated, e.g. "mailto:dmarc@example.com".`,
      });
    }

    diagnostics.push({
      code: "ruf-privacy-notice",
      severity: "warning",
      tag: "ruf",
      message: `ruf= requests failure reports, which can include a forwarded copy of the failing message — headers, and depending on the receiver, some or all of the body — for anyone whose mail fails authentication. Make sure the address it points to is somewhere you're prepared to receive that content, since it may contain other people's personal information.`,
    });
  }
}

function validateRemovedTags(parsed: ParsedRecord, diagnostics: Diagnostic[]): void {
  for (const [tag, message] of Object.entries(REMOVED_TAGS)) {
    if (parsed.tags[tag] !== undefined) {
      diagnostics.push({ code: "removed-tag", severity: "warning", tag, message });
    }
  }
}

function validateUnrecognizedTags(parsed: ParsedRecord, diagnostics: Diagnostic[]): void {
  const seen = new Set<string>();
  for (const entry of parsed.entries) {
    if (CURRENT_TAGS.has(entry.name) || entry.name in REMOVED_TAGS) continue;
    if (seen.has(entry.name)) continue;
    seen.add(entry.name);
    diagnostics.push({
      code: "unrecognized-tag",
      severity: "info",
      tag: entry.name,
      message: `"${entry.rawName}" isn't a tag RFC 9989 (or its predecessor) defines. Per spec, receivers ignore unknown tags rather than rejecting the record because of them — but double-check it isn't a typo of a real one (e.g. "adkim").`,
    });
  }
}
