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

### Added — RFC 9990 and RFC 9991

A read of the two companion RFCs in full. They define report *formats and
delivery*, not record syntax — every policy record tag stays in RFC 9989 §4.7,
which is what this library validates, so the existing scope was right. Three
places where they nonetheless bear on a record:

- **`validate()` takes an optional `ValidateOptions` second argument.** The
  only field is `policyDomain`. Supplying it enables RFC 9990 §4's external
  destination check: where `rua=` (or `ruf=`, which RFC 9991 §5 subjects to the
  same procedure) points outside the publishing domain, the destination must
  authorize it with a `<policy-domain>._report._dmarc.<host>` TXT record, and
  where it hasn't, the receiver **MUST ignore the URI** — reports stop with no
  error anywhere. New `external-report-destination` diagnostic names the exact
  record to look for and the wildcard form that can cover it.

  It is `info`, not a verdict, and permanently so: the library resolves no DNS,
  and §4 compares Organizational Domains, which is the tree walk's output.
  Equal and subdomain-related names are silent; siblings are surfaced with the
  ambiguity stated in the message. Omitting the option changes nothing.
- **`psd-ruf-prohibited` now cites RFC 9991 §2 alongside RFC 9989 §10.2.**
  9989 forbids publishing `ruf=` on a `psd=y` record; 9991 §2 forbids report
  generators acting on it, "unless there are specific agreements between the
  interested parties." That second half is what makes the tag inert in practice
  rather than merely ill-advised, and the caveat is named rather than assumed
  away.
- **New `ruf-rarely-honoured` info diagnostic.** RFC 9991 §7 records that many
  large providers restrict or entirely disable failure reporting on privacy
  grounds. An operator who publishes `ruf=` and sees nothing arrive will go
  hunting for a fault that isn't there, so the library says up front that
  silence is the expected outcome.

`README.md` gains a "what a clean result does not mean" list for the same
reason: no findings means well-formed and current, not working.

### Fixed — RFC 9989 compliance

A rule-by-rule audit against the published RFC turned up several places where
the library described DMARC as it is commonly believed to work rather than as
RFC 9989 specifies it. The first of these was actively misleading.

- **A broken `p=`, `sp=` or `np=` is a whole-record failure, not a tag-scoped
  one.** §4.10.1: when a record has no valid `p` tag, *or* an invalid `sp` or
  `np` tag, receivers act as though it said `p=none` if a syntactically valid
  `rua` URI is present, and apply **no DMARC processing at all** otherwise.
  A typo in `sp=` therefore discards the record's entire enforcement,
  `p=reject` included. The library previously reported `invalid-sp-value` as
  an isolated tag error, which would lead an operator to believe their
  `p=reject` was still standing. These diagnostics now state the actual
  consequence, and which of the two outcomes applies to the record in hand.
- **`rua`/`ruf` accept any valid URI.** §4.7 says so explicitly; there is no
  permitted-scheme list. Receivers MUST *ignore* URIs whose scheme they don't
  support, which makes an exotic scheme an inert destination rather than an
  invalid record. The old `mailto:`/`https:` allow-list rejected conforming
  records outright. Unknown schemes are now `info`
  (`unsupported-report-uri-scheme`); genuinely unparseable entries remain an
  error.
- **The `!size` suffix on a reporting URI is obsolete syntax.** It is
  `obs-dmarc-report-size` in the §4.8 ABNF, and reporters are told to ignore
  it. New `obsolete-report-size-limit` warning. The previous regex accepted
  it as ordinary syntax and, because of a backtracking quirk, never actually
  validated its shape — `!99zz` passed.
- **`fo=` is ignored entirely when `ruf=` is absent** (§4.7). New
  `fo-without-ruf` warning.
- **`d` and `s` may each appear at most once in `fo=`** — a constraint stated
  in a comment on the `dmarc-afrf` ABNF rule. `fo=d:d` was accepted.
- **`t=` applies to `p`, `sp` and `np`, not `p` alone** (§4.7). `p=none;
  sp=reject; t=y` was reported as having no effect; it downgrades subdomain
  enforcement from reject to quarantine.
- **`psd=y` must not be published alongside `ruf=`** (§10.2, a MUST NOT for
  multi-organizational PSDs). New `psd-ruf-prohibited` error.
- **A tag with no value is a syntax error**, not a tag set to empty:
  `dmarc-tag = 1*ALPHA equals 1*dmarc-value`. New `empty-tag-value` warning.
- **Values are restricted to printable US-ASCII except `;`**
  (`dmarc-value = %x20-3A / %x3C-7E`). A smart quote or non-breaking space
  substituted by a word processor is now caught and named by code point —
  the substitution is invisible in most DNS UIs. New
  `invalid-value-characters` warning.
- `pct=` guidance now cites Appendix A.6 and the IANA registry's "historic"
  status, and gives the actual `pct=0` → `t=y` / `pct=100` → `t=n` mapping.

### Fixed — correctness and robustness

- **A tag named `constructor` produced no diagnostic whatsoever.** The
  unknown-tag check used `name in REMOVED_TAGS`, and `in` walks the prototype
  chain. Because parse() lower-cases tag names, `constructor` is the only
  `Object.prototype` member reachable through the `1*ALPHA` grammar — which
  is exactly why it went unnoticed. Now uses `Object.hasOwn`.
- **`ParsedRecord.tags` now has a null prototype.** A consumer testing
  `tags[name] !== undefined` against a caller-supplied name previously got
  inherited `Object.prototype` members back instead of `undefined`.

### Changed — severity semantics (behavioural, pre-1.0)

Severity now tracks RFC 9989's own distinction rather than "how wrong it
looks". `error` means the published policy is not the policy in force —
nothing else earns it. §4.8 requires receivers to discard a syntax error "in
favor of default values (if any) or ignored outright", so a malformed tag in
an otherwise sound record no longer reads as fatal.

- `malformed-chunk`, `empty-segment`, `invalid-tag-name`: error → **warning**
- `invalid-adkim-value`, `invalid-aspf-value`, `invalid-fo-value`,
  `invalid-t-value`, `invalid-psd-value`: error → **warning**, each now
  naming the default it silently falls back to (for the alignment tags, the
  *looser* of the two options)
- `missing-policy`: warning → **error**
- `invalid-p-value`, `invalid-sp-value`, `invalid-np-value`: remain errors,
  now carrying the §4.10.1 consequence

Callers branching on `severity` should re-check those assumptions. Callers
branching on `code` are unaffected — no code changed meaning, and the new
situations got new codes, per this project's stability rule.

### Added

- Regression tests for every item above (78 tests, up from 57), including a
  5000-iteration deterministic fuzz over malformed input asserting that
  parse() never throws and every diagnostic is well-formed.
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
