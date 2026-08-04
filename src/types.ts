/**
 * Shared data shapes for parse() and validate(). Kept in one file, with no
 * imports of their own, so both halves of the library — and anything that
 * consumes them — agree on exactly what a "diagnostic" or "parsed record" is.
 */

/**
 * error   — the record is broken in a way that changes how a receiver
 *            treats it (an ignored record, a rejected tag, etc).
 * warning — the record works, but probably not as the operator intended
 *            (a removed tag that's now silently ignored, a tag that
 *            defaults to something looser than expected).
 * info    — worth knowing, not a defect (a privacy note, a DNSSEC caveat,
 *            confirmation that a risky-looking setting is actually fine).
 *
 * Three levels, not a boolean, because "should I fix this" and "is this
 * broken" are different questions — see the module doc in validate.ts.
 */
export type Severity = "error" | "warning" | "info";

/**
 * One finding, from either parse() (syntax) or validate() (semantics). The
 * two stages share this shape deliberately: a caller building a report
 * shouldn't have to merge two differently-structured lists to get "everything
 * wrong with this record."
 */
export interface Diagnostic {
  /** Stable, machine-readable identifier — safe to switch/branch on, to
   * suppress in a linter-style config, or to use as an i18n key. Never
   * changes meaning across versions; a new situation gets a new code
   * rather than repurposing an old one. */
  code: string;
  severity: Severity;
  /** The lowercase tag this finding is about (e.g. "np"), or null for a
   * finding about the record as a whole (an empty input, a missing v=). */
  tag: string | null;
  /** A human sentence, written for the administrator holding a DNS zone
   * file, not for someone who already has the RFC open. */
  message: string;
}

/** One tag=value pair as it literally appeared in the record, before any
 * judgement is applied about whether that tag is valid, current, or even
 * real. Kept even for tags that turn out to be duplicates or unrecognised —
 * validate() (and anyone auditing a record by hand) needs the raw sequence,
 * not just the deduplicated result. */
export interface ParsedTagEntry {
  /** Tag name lowercased, e.g. "P" and "p" both normalize to "p". Tag
   * *names* are just ASCII letters with no case semantics in the DMARC
   * ABNF, so normalizing here is a syntax-level given, not a policy
   * choice — contrast with tag *values*, which parse() leaves untouched. */
  name: string;
  /** Tag name exactly as written, for diagnostics that want to quote the
   * source back at the person reading them. */
  rawName: string;
  /** The value exactly as written, whitespace-trimmed but otherwise
   * unmodified — including its original case. Whether "REJECT" is
   * acceptable is a semantic question for validate(), not parse(). */
  value: string;
}

/**
 * The result of parse(): a structured, mechanical reading of a DNS TXT
 * string as a DMARC record. Deliberately free of any opinion about whether
 * the record is a *good* DMARC record — that's validate()'s job.
 */
export interface ParsedRecord {
  /** Exactly what was passed to parse(), untouched. */
  input: string;
  /** `input` after DNS TXT dequoting/concatenation (see parse.ts), before
   * being split on ";". Useful for debugging a record that came out of
   * `dig` looking like several quoted strings. */
  normalized: string;
  /** Every syntactically well-formed tag=value pair, in the order it
   * appeared, duplicates included. A tag that failed even to parse as
   * "name=value" does not get an entry here — see `issues` for that. */
  entries: ParsedTagEntry[];
  /** Convenience lookup: normalized tag name -> the value of its *first*
   * occurrence. See parse.ts for why first-occurrence-wins. */
  tags: Record<string, string>;
  /** Normalized names of any tag that appeared more than once. */
  duplicateTags: string[];
  /** Syntax-level problems found while parsing: a chunk with no "=", an
   * empty segment from a stray ";;", a tag name that isn't pure letters,
   * a duplicated tag. Semantic problems (wrong value for a tag, a removed
   * tag, a missing v=) are validate()'s concern, not this array's. */
  issues: Diagnostic[];
}
