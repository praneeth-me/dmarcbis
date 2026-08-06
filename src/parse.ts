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
 * dmarc-value = %x20-3A / %x3C-7E — printable US-ASCII except ";" (0x3B),
 * which is the separator. That excludes control characters and everything
 * non-ASCII, so a value carrying a smart quote or a non-breaking space
 * (both of which a word processor or a wiki will happily substitute into a
 * record someone is drafting) is a syntax error, not a curiosity. Those
 * substitutions are invisible in most DNS UIs, which is exactly why this
 * is worth reporting rather than silently tolerating.
 */
const VALUE_CHARACTER_PATTERN = /^[\x20-\x3A\x3C-\x7E]*$/;

/** Describes an out-of-range character precisely enough to find it in a
 * zone file, where it is likely to be visually indistinguishable from the
 * ASCII character it replaced. */
function describeInvalidCharacters(value: string): string {
  const seen = new Map<string, number>();
  for (const character of value) {
    if (VALUE_CHARACTER_PATTERN.test(character)) continue;
    seen.set(character, (seen.get(character) ?? 0) + 1);
  }
  return [...seen.keys()]
    .slice(0, 5)
    .map((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      const hex = codePoint.toString(16).toUpperCase().padStart(4, "0");
      return `U+${hex}`;
    })
    .join(", ");
}

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
  // Null-prototype, so a tag literally named "constructor" (or any other
  // Object.prototype member) is an ordinary key rather than a collision
  // with an inherited one. Tag names are lower-cased below, which makes
  // "constructor" the only such collision that can actually occur — every
  // other Object.prototype member is camelCase or underscore-prefixed and
  // so unreachable through 1*ALPHA. One name is still one too many: a
  // consumer reading `tags[someName]` on a plain object gets an inherited
  // function back instead of `undefined`.
  const tags: Record<string, string> = Object.create(null) as Record<string, string>;
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
          severity: "warning",
          tag: null,
          message: `Found an empty segment between semicolons (position ${index + 1} of the ";"-separated record) — likely a stray double semicolon. RFC 9989 §4.8 has receivers discard a syntax error like this and carry on with the rest of the record, so it's untidy rather than fatal.`,
        });
      }
      return;
    }

    const equalsIndex = trimmedChunk.indexOf("=");
    if (equalsIndex === -1) {
      issues.push({
        code: "malformed-chunk",
        severity: "warning",
        tag: null,
        message: `Segment "${trimmedChunk}" has no "=" — every tag must be written as name=value. Per RFC 9989 §4.8 a syntax error here is discarded and the rest of the record is still processed, so this doesn't invalidate the record; it just means whatever you intended by this segment isn't happening.`,
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
        severity: "warning",
        tag: null,
        message: `"${rawName || trimmedChunk}" isn't a valid tag name — the ABNF makes tag names 1*ALPHA, letters only. Receivers discard this segment (RFC 9989 §4.8) and process the rest of the record, so anything you meant to configure here isn't in effect.`,
      });
      return;
    }

    const name = rawName.toLowerCase();

    // dmarc-tag = 1*ALPHA equals 1*dmarc-value — "1*", so a tag with no
    // value at all is a syntax error rather than a tag set to the empty
    // string. It matters which one it is: discarded means the tag's
    // *default* applies, which for adkim/aspf is relaxed alignment.
    if (value.length === 0) {
      issues.push({
        code: "empty-tag-value",
        severity: "warning",
        tag: name,
        message: `"${rawName}=" has no value. The ABNF requires at least one character (1*dmarc-value), so receivers discard this tag and fall back to its default — which is not the same as the tag being absent only if you were relying on it.`,
      });
      return;
    }

    if (!VALUE_CHARACTER_PATTERN.test(value)) {
      issues.push({
        code: "invalid-value-characters",
        severity: "warning",
        tag: name,
        message: `"${rawName}=" contains ${describeInvalidCharacters(value)}, outside the printable US-ASCII range the ABNF allows for a value (%x20-3A / %x3C-7E). This is usually a smart quote, an en dash or a non-breaking space substituted by a word processor — visually identical to the ASCII character it replaced, and discarded by receivers.`,
      });
      return;
    }

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
