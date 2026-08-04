# Changelog

All notable changes to this project are documented in this file.

## [0.1.0] - 2026-08-04

Initial version.

- `parse(record: string): ParsedRecord` — turns a raw DNS TXT value into
  structured tag=value data. Handles inconsistent whitespace, trailing
  semicolons, mixed-case tag names, repeated tags, and DNS TXT records
  split across multiple quoted/concatenated strings. Reports syntax
  problems as structured issues rather than throwing.
- `validate(parsed: ParsedRecord): Diagnostic[]` — checks parsed output
  against RFC 9989 (DMARCbis):
  - Flags the tags RFC 9989 removed from RFC 7489: `pct`, `rf`, `ri`.
  - Validates the tags RFC 9989 added: `t`, `np`, `psd`.
  - Validates all tags still current in RFC 9989: `v`, `p`, `sp`, `adkim`,
    `aspf`, `fo`, `rua`, `ruf`.
  - Flags `np=reject` with an informational note that it's safe to set
    immediately, and a second note about the RFC 9824 "compact denial of
    existence" interaction that can make it silently ineffective on
    DNSSEC-signed zones hosted at Cloudflare, Route 53, NS1, or Azure DNS.
  - Flags `ruf=` with a privacy note about failure reports carrying
    message content.
- Zero runtime dependencies; `typescript` is the only devDependency.
- `node --test` table-driven test suite covering valid/invalid records,
  every removed and new tag, structural edge cases (duplicated tags,
  malformed input, empty string, non-DMARC input), and whitespace/casing
  variation.
- `npm run demo` — prints diagnostics for a handful of real-world-shaped
  records, including a legacy RFC 7489-style record.
