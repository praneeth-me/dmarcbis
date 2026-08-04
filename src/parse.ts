import type { Diagnostic, ParsedRecord, ParsedTagEntry } from "./types.ts";

/**
 * parse() turns a raw DNS TXT value into structured tag=value data. It is
 * deliberately dumb about meaning: it doesn't know that "p" only accepts
 * none/quarantine/reject, or that "pct" was removed in RFC 9989 — that's
 * validate()'s job (see validate.ts's module doc for why the split exists).
 * What parse() does own is the *syntax* of a DMARC record: RFC 9989 §4.8's
 * ABNF, reproduced here for reference —
 *
 *   dmarc-record  = dmarc-version *(dmarc-sep dmarc-tag) [dmarc-sep]
 *   dmarc-sep     = *WSP ";" *WSP
 *   dmarc-tag     = 1*ALPHA equals 1*dmarc-value
 *   equals        = *WSP "=" *WSP
 *
 * i.e. semicolon-separated tag=value pairs, arbitrary whitespace around both
 * the ";" and the "=". Everything below exists to survive the ways real DNS
 * tooling roughs that grammar up before it reaches you.
 */

/** Tag names are 1*ALPHA in the ABNF — letters only, nothing else. A chunk
 * whose "name" side has digits, punctuation, etc. isn't a tag at all, just
 * a chunk that happens to contain an "=". */
const TAG_NAME_PATTERN = /^[A-Za-z]+$/;

/**
 * `dig`, `nslookup` and every DNS zone file quote a TXT record's value, and
 * a value over 255 bytes gets split across *multiple* quoted
 * <character-string>s that concatenate into one logical value with no
 * separator (that's DNS's rule for multi-string TXT RDATA, not a DMARC
 * one). A record copy-pasted straight from `dig +short TXT` therefore often
 * looks like:
 *
 *   "v=DMARC1; p=reject; " "rua=mailto:dmarc@example.com"
 *
 * This function undoes exactly that, so callers can hand parse() whatever
 * their DNS tool printed instead of having to pre-clean it themselves. If
 * the input isn't wrapped in quotes at all (e.g. it's already the decoded
 * value from a DNS library), it's returned unchanged.
 */
function dequoteTxtStrings(input: string): string {
  const trimmed = input.trim();
  const QUOTED_SEGMENT = /"((?:[^"\\]|\\.)*)"/g;

  const matches = [...trimmed.matchAll(QUOTED_SEGMENT)];
  if (matches.length === 0) {
    return trimmed;
  }

  // Confirm the quoted segments are *all* there is (aside from whitespace
  // between them) — otherwise this isn't the dig-style quoting we're
  // undoing, and blindly concatenating the quoted parts would silently
  // drop real content sitting outside the quotes.
  let cursor = 0;
  for (const match of matches) {
    const gap = trimmed.slice(cursor, match.index);
    if (gap.trim().length > 0) {
      return trimmed;
    }
    cursor = match.index + match[0].length;
  }
  if (trimmed.slice(cursor).trim().length > 0) {
    return trimmed;
  }

  return matches.map((match) => (match[1] ?? "").replace(/\\(.)/g, "$1")).join("");
}

export function parse(record: string): ParsedRecord {
  const issues: Diagnostic[] = [];
  const normalized = dequoteTxtStrings(record);

  if (normalized.length === 0) {
    issues.push({
      code: "empty-record",
      severity: "error",
      tag: null,
      message: "The input was empty (or only whitespace/quotes) — there's nothing to parse.",
    });
    return { input: record, normalized, entries: [], tags: {}, duplicateTags: [], issues };
  }

  const entries: ParsedTagEntry[] = [];
  const tags: Record<string, string> = {};
  const seenNames = new Set<string>();
  const duplicateNames = new Set<string>();

  const chunks = normalized.split(";");

  chunks.forEach((chunk, index) => {
    const trimmedChunk = chunk.trim();

    if (trimmedChunk.length === 0) {
      // A trailing ";" (dmarc-record's own [dmarc-sep]) produces exactly
      // one empty chunk at the end — that's normal and not worth a
      // diagnostic. An empty chunk anywhere else (a stray ";;") means a
      // tag was expected and nothing was there.
      const isTrailingSeparator = index === chunks.length - 1;
      if (!isTrailingSeparator) {
        issues.push({
          code: "empty-segment",
          severity: "error",
          tag: null,
          message: `Found an empty segment between semicolons (position ${index + 1} of the ";"-separated record) — likely a stray double semicolon.`,
        });
      }
      return;
    }

    const equalsIndex = trimmedChunk.indexOf("=");
    if (equalsIndex === -1) {
      issues.push({
        code: "malformed-chunk",
        severity: "error",
        tag: null,
        message: `Segment "${trimmedChunk}" has no "=" — every tag must be written as name=value.`,
      });
      return;
    }

    const rawName = trimmedChunk.slice(0, equalsIndex).trim();
    // dmarc-value permits almost anything (RFC 9989's dmarc-value excludes
    // only ";", the separator) — including a literal "=" — so only the
    // *first* "=" is the name/value boundary. Splitting anywhere else would
    // truncate values like a rua URI's query string.
    const value = trimmedChunk.slice(equalsIndex + 1).trim();

    if (!TAG_NAME_PATTERN.test(rawName)) {
      issues.push({
        code: "invalid-tag-name",
        severity: "error",
        tag: null,
        message: `"${rawName || trimmedChunk}" isn't a valid tag name — tag names are letters only (a-z), so this segment is being skipped.`,
      });
      return;
    }

    const name = rawName.toLowerCase();
    entries.push({ name, rawName, value });

    if (seenNames.has(name)) {
      duplicateNames.add(name);
      // First occurrence wins. RFC 9989 doesn't actually specify tie-break
      // behaviour for a repeated tag, but every real-world DMARC parser we
      // could find treats the first as authoritative and the record as
      // suspect — matching that is more useful than picking a novel
      // interpretation nothing else agrees with.
    } else {
      seenNames.add(name);
      tags[name] = value;
    }
  });

  for (const name of duplicateNames) {
    issues.push({
      code: "duplicate-tag",
      severity: "warning",
      tag: name,
      message: `"${name}" appears more than once in this record. Using the first occurrence (${JSON.stringify(tags[name])}); the repeat(s) are ignored.`,
    });
  }

  return {
    input: record,
    normalized,
    entries,
    tags,
    duplicateTags: [...duplicateNames],
    issues,
  };
}
