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

## Unreleased

### Added

- MIT `LICENSE`, `CONTRIBUTING.md` and `SECURITY.md`.
- GitHub Actions CI running the type check and test suite on Node 22.6 (the
  declared minimum, and the first version with native TypeScript type
  stripping) and Node 24.
- `repository`, `homepage`, `bugs`, `author` and `files` metadata in
  `package.json`.

### Known before a first npm release

`main`, `types` and `exports` currently point at TypeScript source. That works
for this repo's own tests and for bundlers that compile TypeScript (which is
how praneeth.me consumes it), but it will break consumers on older Node, on
CommonJS, or on any toolchain that expects a package to ship JavaScript.
Publishing to npm needs a build emitting `.js` plus `.d.ts` and `exports`
repointed at it. `private: true` stays set until that is done — `npm publish`
refuses while it is, which is deliberate.
