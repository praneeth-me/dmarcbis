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
  pct: `pct= was removed in RFC 9989 (DMARCbis) and is marked "historic" in IANA's DMARC Tags registry. DMARCbis receivers ignore it outright, which quietly turns a partial rollout into full enforcement at whatever p= says the moment a receiver updates to the new spec. RFC 9989 Appendix A.6 explains why it went: operators found values other than 0 and 100 were applied inconsistently between implementations. t=y is the replacement and is analogous to the old pct=0; t=n (the default) is analogous to pct=100.`,
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
  if (numericTokenCount > 1) return false;
  // "dmarc-afrf = "d" / "s" ; each may appear at most once in dmarc-fo" —
  // the constraint is in a comment on the ABNF rule rather than in the
  // grammar itself, which is exactly why it's easy to miss. Every one of
  // the three dmarc-fo alternatives admits at most one "d" and one "s".
  return (
    tokens.filter((token) => token === "d").length <= 1 &&
    tokens.filter((token) => token === "s").length <= 1
  );
}

/**
 * rua/ruf hold a dmarc-urilist: comma-separated entries, each of which the
 * ABNF defines as a bare `URI` imported from RFC 3986. Three consequences
 * that a scheme allow-list gets wrong, and this library used to:
 *
 *   1. "Any valid URI can be specified" (§4.7, for both tags). There is no
 *      list of permitted schemes. Receivers MUST implement `mailto:` and
 *      MUST *ignore* URIs whose scheme they don't support — so an exotic
 *      scheme makes that one destination inert, not the record invalid.
 *   2. Commas and exclamation points inside a URI MUST be percent-encoded
 *      (§4.8). The comma rule is what makes splitting on "," safe.
 *   3. The trailing "!100m" size limit is `obs-dmarc-report-size` — RFC
 *      9989 marks it obsolete and tells reporters to ignore it. It's still
 *      grammatical, so it parses, but it does nothing.
 */
const OBSOLETE_SIZE_LIMIT_PATTERN = /!([0-9]+[kmgt]?)$/i;

interface ReportUriFinding {
  entry: string;
  /** Set when the entry isn't a URI at all (no scheme, unparseable). */
  malformed: boolean;
  /** Set for a syntactically fine URI whose scheme no receiver is obliged
   * to support — informational, not an error. */
  unsupportedScheme: string | null;
  /** Set when the entry carries an obs-dmarc-report-size suffix. */
  obsoleteSizeLimit: string | null;
}

/** Schemes a Mail Receiver is required or expected to handle. `mailto:` is
 * the one every receiver MUST implement (§4.7); `https:` is the transport
 * RFC 9990 describes for aggregate report delivery. Anything else is legal
 * to publish and legal for a receiver to drop on the floor. */
const EXPECTED_SCHEMES = new Set(["mailto:", "https:"]);

function inspectReportUris(raw: string): ReportUriFinding[] {
  const entries = raw
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);

  if (entries.length === 0) {
    return [{ entry: raw, malformed: true, unsupportedScheme: null, obsoleteSizeLimit: null }];
  }

  return entries.flatMap((entry) => {
    const sizeMatch = OBSOLETE_SIZE_LIMIT_PATTERN.exec(entry);
    const obsoleteSizeLimit = sizeMatch?.[1] ?? null;
    // An unencoded "!" is only ever the obsolete size limit, so strip it
    // before parsing the URI itself — otherwise a perfectly good address
    // with a legacy cap on it reads as malformed.
    const uriText = sizeMatch ? entry.slice(0, sizeMatch.index) : entry;

    let scheme: string | null = null;
    try {
      scheme = new URL(uriText).protocol.toLowerCase();
    } catch {
      scheme = null;
    }

    const finding: ReportUriFinding = {
      entry,
      malformed: scheme === null,
      unsupportedScheme: scheme && !EXPECTED_SCHEMES.has(scheme) ? scheme : null,
      obsoleteSizeLimit,
    };

    const isClean =
      !finding.malformed && !finding.unsupportedScheme && !finding.obsoleteSizeLimit;
    return isClean ? [] : [finding];
  });
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

/**
 * RFC 9989 §4.10.1 attaches a consequence to a broken policy tag that is
 * far larger than the tag itself, and it is the single least intuitive
 * rule in the specification:
 *
 *   "If a retrieved DMARC Policy Record does not contain a valid 'p' tag,
 *    or contains an 'sp' or 'np' tag that is not valid, then:
 *      - If a 'rua' tag is present and contains at least one syntactically
 *        valid reporting URI, the Mail Receiver MUST act as if a record
 *        containing 'p=none' was retrieved and continue processing.
 *      - Otherwise, the Mail Receiver applies no DMARC processing to this
 *        message."
 *
 * So a single typo in `sp=` does not disable `sp=`. It discards the whole
 * record's enforcement — `p=reject` included — and, with no usable rua, it
 * switches DMARC off for the domain entirely. An operator reading a
 * tag-scoped "invalid sp value" error would reasonably conclude their
 * p=reject was still standing. It isn't.
 */
function describePolicyFallback(parsed: ParsedRecord): {
  severity: "error";
  consequence: string;
} {
  const rua = parsed.tags["rua"];
  const hasUsableRua =
    rua !== undefined && rua.split(",").some((entry) => isParseableUri(entry.trim()));

  return {
    severity: "error",
    consequence: hasUsableRua
      ? `Because this record carries a rua= with at least one syntactically valid URI, receivers MUST act as though it said p=none and keep processing (RFC 9989 §4.10.1). Aggregate reports keep arriving, so this fails quietly: any enforcement you published here is not being applied.`
      : `This record has no rua= with a syntactically valid URI, so receivers apply no DMARC processing to the message at all (RFC 9989 §4.10.1) — not p=none, but DMARC switched off for this domain. No enforcement and no reports, which is also why nothing will arrive to tell you.`,
  };
}

function isParseableUri(entry: string): boolean {
  const withoutSizeLimit = entry.replace(OBSOLETE_SIZE_LIMIT_PATTERN, "");
  try {
    new URL(withoutSizeLimit);
    return true;
  } catch {
    return false;
  }
}

function validatePolicyTags(parsed: ParsedRecord, diagnostics: Diagnostic[]): void {
  const p = parsed.tags["p"];
  const sp = parsed.tags["sp"];
  const np = parsed.tags["np"];

  if (p === undefined) {
    const { severity, consequence } = describePolicyFallback(parsed);
    diagnostics.push({
      code: "missing-policy",
      severity,
      tag: "p",
      message: `No p= tag was found. ${consequence} Add an explicit p= — it is the tag that decides what happens to mail failing authentication.`,
    });
  } else if (!POLICY_VALUES.has(p.toLowerCase())) {
    const { severity, consequence } = describePolicyFallback(parsed);
    diagnostics.push({
      code: "invalid-p-value",
      severity,
      tag: "p",
      message: `p="${p}" isn't valid — must be one of none, quarantine, or reject. ${consequence}`,
    });
  }

  if (sp !== undefined && !POLICY_VALUES.has(sp.toLowerCase())) {
    const { severity, consequence } = describePolicyFallback(parsed);
    diagnostics.push({
      code: "invalid-sp-value",
      severity,
      tag: "sp",
      message: `sp="${sp}" isn't valid — must be one of none, quarantine, or reject. This does not just disable sp=: an invalid sp= invalidates the policy of the entire record. ${consequence}`,
    });
  }

  if (np !== undefined) {
    if (!POLICY_VALUES.has(np.toLowerCase())) {
      const { severity, consequence } = describePolicyFallback(parsed);
      diagnostics.push({
        code: "invalid-np-value",
        severity,
        tag: "np",
        message: `np="${np}" isn't valid — must be one of none, quarantine, or reject. This does not just disable np=: an invalid np= invalidates the policy of the entire record. ${consequence}`,
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

  // Unlike p/sp/np, a bad alignment value has no §4.10.1 consequence: §4.8
  // discards the syntax error "in favor of default values", and the default
  // for both tags is "r". That makes this a warning rather than an error,
  // and the specific thing worth saying is which way it silently fails —
  // someone who published adkim=strict (a plausible typo for "s") gets
  // relaxed alignment, the looser of the two, with no other signal.
  if (adkim !== undefined && !RELAXED_STRICT_VALUES.has(adkim.toLowerCase())) {
    diagnostics.push({
      code: "invalid-adkim-value",
      severity: "warning",
      tag: "adkim",
      message: `adkim="${adkim}" isn't valid — must be "r" (relaxed) or "s" (strict). Receivers discard the invalid value and fall back to the default, "r", so DKIM alignment is relaxed here — the looser setting, not the stricter one.`,
    });
  }

  if (aspf !== undefined && !RELAXED_STRICT_VALUES.has(aspf.toLowerCase())) {
    diagnostics.push({
      code: "invalid-aspf-value",
      severity: "warning",
      tag: "aspf",
      message: `aspf="${aspf}" isn't valid — must be "r" (relaxed) or "s" (strict). Receivers discard the invalid value and fall back to the default, "r", so SPF alignment is relaxed here — the looser setting, not the stricter one.`,
    });
  }
}

function validateFoTag(parsed: ParsedRecord, diagnostics: Diagnostic[]): void {
  const fo = parsed.tags["fo"];
  if (fo === undefined) return;

  if (!isValidFoValue(fo)) {
    diagnostics.push({
      code: "invalid-fo-value",
      severity: "warning",
      tag: "fo",
      message: `fo="${fo}" isn't valid — a colon-separated combination of "0"/"1" (mutually exclusive, at most one) and "d"/"s" (at most one each), e.g. "0", "1:d", or "d:s". Receivers discard it and fall back to the default "0": a failure report only when every authentication mechanism fails to produce an aligned pass.`,
    });
  }

  // "This tag's content MUST be ignored if a 'ruf' tag (below) is not also
  // specified" (§4.7). fo= alone is inert — and it looks like it is doing
  // something, which is why it's worth saying out loud.
  if (parsed.tags["ruf"] === undefined) {
    diagnostics.push({
      code: "fo-without-ruf",
      severity: "warning",
      tag: "fo",
      message: `fo= is set but there's no ruf= tag. RFC 9989 §4.7 says fo='s content MUST be ignored when ruf= is absent, so this tag currently does nothing — failure reports are only generated for a domain that publishes ruf=. Either add ruf= or drop fo=.`,
    });
  }
}

function validateBooleanAndPsdTags(parsed: ParsedRecord, diagnostics: Diagnostic[]): void {
  const t = parsed.tags["t"];
  if (t !== undefined && !YES_NO_VALUES.has(t.toLowerCase())) {
    diagnostics.push({
      code: "invalid-t-value",
      severity: "warning",
      tag: "t",
      message: `t="${t}" isn't valid — must be "y" or "n". Receivers discard it and fall back to the default "n", meaning the published policy applies in full rather than in testing mode. t=y is RFC 9989's replacement for the old pct= partial rollout (Appendix A.6: t=y is analogous to pct=0, t=n to pct=100).`,
    });
  } else if (t?.toLowerCase() === "y") {
    // RFC 9989 §4.7 defines t=y as a *downgrade by one level*, not as a
    // suspension of the policy. That distinction is easy to get wrong — the
    // intuitive reading is "testing means nothing happens", which is only
    // true at p=quarantine. At p=reject, t=y still quarantines. Since t= is
    // the replacement for pct= and everyone's muscle memory is the old
    // percentage ramp, spell the actual effect out rather than assuming the
    // reader infers it.
    // t= applies to "the Domain Owner Assessment Policy declared in the 'p',
    // 'sp', and/or 'np' tags" (§4.7) — all three, not just p. An earlier
    // version read p= alone, so `p=none; sp=reject; t=y` was reported as
    // changing nothing, when in fact it downgrades subdomain enforcement
    // from reject to quarantine.
    const downgrade: Record<string, string> = {
      reject: "quarantine",
      quarantine: "none",
    };
    const affected: string[] = [];
    for (const tagName of ["p", "sp", "np"] as const) {
      const value = parsed.tags[tagName]?.toLowerCase();
      if (value === undefined) continue;
      const lowered = downgrade[value];
      if (lowered === undefined) continue;
      affected.push(`${tagName}=${value} is being applied as ${lowered}`);
    }

    const effect =
      affected.length > 0
        ? affected.join("; ")
        : `nothing is being downgraded here — the tag has no effect on a policy of "none" (§4.7), and there is no level below it`;

    diagnostics.push({
      code: "t-testing-mode",
      severity: "info",
      tag: "t",
      message: `t=y puts this record in testing mode: receivers apply each declared policy one level below the one published (reject becomes quarantine; quarantine becomes none). Right now, ${effect}. Reports still arrive as though the full policy were in force, which is the point: you see the impact before taking it. Drop t=y when you want the published policy to actually apply.`,
    });
  }

  const psd = parsed.tags["psd"];
  if (psd !== undefined && !PSD_VALUES.has(psd.toLowerCase())) {
    diagnostics.push({
      code: "invalid-psd-value",
      severity: "warning",
      tag: "psd",
      message: `psd="${psd}" isn't valid — must be "y" (this is a public suffix domain), "n" (it isn't), or "u" (undeclared). Receivers discard it and fall back to the default "u", which means the organizational domain is worked out by the DNS tree walk instead of being declared here.`,
    });
  }

  // "DMARC Policy Records for multi-organizational PSDs MUST NOT include the
  // 'ruf' tag" (§10.2). A PSD's failure reports would carry message content
  // belonging to the separate organizations underneath it — the one place in
  // DMARC where a reporting tag is prohibited outright rather than discouraged.
  if (psd?.toLowerCase() === "y" && parsed.tags["ruf"] !== undefined) {
    diagnostics.push({
      code: "psd-ruf-prohibited",
      severity: "error",
      tag: "ruf",
      message: `This record declares psd=y (a public suffix domain) and also publishes ruf=. RFC 9989 §10.2 states that DMARC Policy Records for multi-organizational PSDs MUST NOT include the ruf= tag: failure reports can carry message content belonging to the independent organizations registered beneath the suffix, who have not agreed to send it here. Remove ruf=, or psd=y if this domain is not actually a PSD.`,
    });
  }
}

function validateReportingUriList(
  tag: "rua" | "ruf",
  raw: string,
  diagnostics: Diagnostic[]
): void {
  const findings = inspectReportUris(raw);

  const malformed = findings.filter((finding) => finding.malformed);
  if (malformed.length > 0) {
    const list = malformed.map((finding) => `"${finding.entry}"`).join(", ");
    diagnostics.push({
      code: "invalid-report-uri",
      severity: "error",
      tag,
      message: `${tag}= contains ${malformed.length === 1 ? "an entry that isn't" : "entries that aren't"} a URI at all: ${list}. Each entry must be a full URI with a scheme (RFC 3986), comma-separated — "mailto:dmarc@example.com", not a bare address. Note that commas and exclamation points inside a URI have to be percent-encoded, since a comma separates entries.`,
    });
  }

  const unsupported = findings.filter((finding) => finding.unsupportedScheme !== null);
  if (unsupported.length > 0) {
    const list = unsupported
      .map((finding) => `"${finding.entry}" (${finding.unsupportedScheme})`)
      .join(", ");
    diagnostics.push({
      code: "unsupported-report-uri-scheme",
      severity: "info",
      tag,
      message: `${tag}= includes ${list}. RFC 9989 §4.7 permits any valid URI here, so this is not an error — but receivers MUST ignore URIs whose scheme they don't support, and the only scheme every receiver is required to implement is "mailto:". Expect this destination to be skipped by most or all of them.`,
    });
  }

  const obsolete = findings.filter((finding) => finding.obsoleteSizeLimit !== null);
  if (obsolete.length > 0) {
    const list = obsolete.map((finding) => `"!${finding.obsoleteSizeLimit}"`).join(", ");
    diagnostics.push({
      code: "obsolete-report-size-limit",
      severity: "warning",
      tag,
      message: `${tag}= carries a report size limit (${list}). RFC 9989 §4.8 marks this syntax obsolete — it is "obs-dmarc-report-size" in the ABNF, and reporters are told to ignore it if they find it. The record still parses, but the cap does nothing: reports arrive at whatever size the receiver generates. Remove it, and note that an exclamation point kept for any other purpose has to be percent-encoded.`,
    });
  }
}

function validateReportingTags(parsed: ParsedRecord, diagnostics: Diagnostic[]): void {
  const rua = parsed.tags["rua"];
  if (rua !== undefined) {
    validateReportingUriList("rua", rua, diagnostics);
  }

  const ruf = parsed.tags["ruf"];
  if (ruf !== undefined) {
    validateReportingUriList("ruf", ruf, diagnostics);

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
    // Object.hasOwn, not `in`: `in` walks the prototype chain, and because
    // parse() lower-cases tag names, a record carrying `constructor=...`
    // matched Object.prototype's own member and was silently skipped here
    // — no unrecognized-tag diagnostic, no removed-tag diagnostic, nothing.
    // `constructor` is the only Object.prototype member reachable through
    // the lower-cased 1*ALPHA tag grammar, which is what kept it hidden.
    if (CURRENT_TAGS.has(entry.name) || Object.hasOwn(REMOVED_TAGS, entry.name)) continue;
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
