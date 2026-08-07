# dmarcbis

A TypeScript parser and validator for DMARC records — checked against **RFC
9989** ("DMARCbis"), which replaced RFC 7489 in May 2026. As of this
writing, every other DMARC checker still validates against the 2015 spec.
`dmarcbis` exists to close that gap: it knows which tags RFC 9989 removed
(`pct`, `rf`, `ri`), which it added (`t`, `np`, `psd`), and the DNSSEC
interaction that can make the new `np=reject` tag silently do nothing.

Zero runtime dependencies. TypeScript is the only devDependency.

## Why this exists

RFC 9989 (plus its companions RFC 9990 and RFC 9991) put DMARC on the IETF
Standards Track for the first time — it had run the world's inbox anti-phishing
policy for a decade as an *informational* spec. That upgrade came with real
rule changes, not just a version-number bump, and nothing checks a record
against them yet. If you paste a record written to the old spec (`pct=` and
all) into any existing DMARC validator today, it will tell you it's fine.
It isn't wrong, exactly — receivers that still speak RFC 7489 will honour
it — but it's advice from a decade-old spec, and the tag it relies on
(`pct=`) is gone from the new one.

## Status

Pre-1.0 and **not yet published to npm**. `package.json` still points `main`,
`types` and `exports` at TypeScript source, which suits a bundler but breaks
consumers on CommonJS, on older Node, or on any toolchain expecting a package
to ship JavaScript. A release needs a build emitting `.js` + `.d.ts` first, so
`private: true` stays set until then — `npm publish` refuses while it is,
deliberately.

Read it, borrow from it, or open an issue. Depending on it in production is
premature.

## Install

```bash
git clone https://github.com/praneeth-me/dmarcbis.git
cd dmarcbis
npm install
```

## Usage

`parse()` and `validate()` are deliberately two separate functions. `parse()`
turns a raw DNS TXT string into structured data and has no opinion about
whether the record is any good — it just reads. `validate()` takes that
structured data and checks it against RFC 9989, returning an array of
diagnostics. Keeping them apart means you can parse a record without
pulling in the RFC's judgement calls, and it means a future RFC revision
only has to touch `validate()`.

```typescript
import { parse, validate } from "./src/index.ts";

const record = "v=DMARC1; p=quarantine; pct=50; rua=mailto:dmarc@example.com";

const parsed = parse(record);
const diagnostics = validate(parsed);

for (const d of diagnostics) {
  console.log(`[${d.severity}] (${d.tag ?? "record"}) ${d.code}: ${d.message}`);
}
```

Output:

```
[warning] (pct) removed-tag: pct= was removed in RFC 9989 (DMARCbis) and is
marked "historic" in IANA's DMARC Tags registry. DMARCbis receivers ignore it
outright, which quietly turns a partial rollout into full enforcement at
whatever p= says the moment a receiver updates to the new spec. RFC 9989
Appendix A.6 explains why it went: operators found values other than 0 and 100
were applied inconsistently between implementations. t=y is the replacement and
is analogous to the old pct=0; t=n (the default) is analogous to pct=100.
```

Neither function ever throws. `parse()` reports syntax problems (an
unparseable chunk, a tag with no `=`) as part of its result; `validate()`
never returns a bare boolean — every finding is a `Diagnostic`:

```typescript
interface Diagnostic {
  code: string;                        // stable, machine-readable — e.g. "removed-tag"
  severity: "error" | "warning" | "info";
  tag: string | null;                   // which tag this is about, or null for the whole record
  message: string;                       // a sentence for a human, not a spec citation
}
```

`validate()`'s returned array includes `parse()`'s own syntax-level findings
too (a duplicated tag, a malformed chunk) — so a caller gets one complete
list of everything wrong with a record from a single `validate(parse(record))`
call, without having to merge two arrays by hand.

#### Telling `validate()` where the record was published

`validate()` takes an optional second argument. The only field today is
`policyDomain` — the name the record belongs to, so `example.com` for a record
found at `_dmarc.example.com`:

```typescript
validate(parse(record), { policyDomain: "example.com" });
```

Supplying it enables one check that the record text alone can't support:
RFC 9990 §4's external destination verification. When `rua=` (or `ruf=`, via
RFC 9991 §5) points somewhere outside the publishing domain, that destination
has to opt in by publishing

```
<policy-domain>._report._dmarc.<destination-host>   TXT   "v=DMARC1"
```

and if it hasn't, the receiver **MUST ignore the URI**. No error, no bounce —
the reports simply never arrive, which is the most common reason a
correct-looking record produces an empty inbox for weeks.

The resulting `external-report-destination` diagnostic is `info`, and
deliberately so: it hands you the exact name to `dig` and tells you what
depends on it, but it cannot be a verdict. Two reasons, both permanent —
this library does no DNS, and RFC 9989 compares *Organizational Domains*
rather than hostnames, which is the output of the tree walk. Names that are
equal or in a subdomain relationship are correctly silent; two siblings
(a record on `mail.example.com` pointing at `reports.example.com`) are
surfaced with the caveat spelled out in the message.

Omit the option and nothing changes: you get exactly the diagnostics you got
before.

### What `severity` means

The three levels follow the line RFC 9989 itself draws, which is not the line
"how wrong does this look":

- **`error`** — the policy you published is not the policy in force. Either the
  whole record is disregarded (a missing, misplaced or misspelt `v=`), or
  §4.10.1's fallback has been triggered by an absent or invalid `p=`/`sp=`/`np=`
  and enforcement has collapsed to `p=none` — or to no DMARC processing at all.
- **`warning`** — the record stands and its policy applies, but some part of it
  isn't doing what it appears to. §4.8 requires receivers to discard a syntax
  error "in favor of default values (if any) or ignored outright", so a
  malformed tag reverts to a default rather than invalidating anything.
- **`info`** — worth knowing, not a defect.

The distinction that matters most: a junk segment in the middle of an otherwise
good record is a **warning**, because a receiver steps over it and applies your
`p=reject` exactly as written. Meanwhile a single typo in `sp=` is an
**error**, because it does not disable `sp=` — it discards the record's entire
enforcement, `p=reject` included. That asymmetry is unintuitive and is most of
the reason this library reports the way it does.

`code` is the stable API and never changes meaning; a new situation gets a new
code. `severity` is a judgement and may be re-tuned against the RFC — see
[CHANGELOG.md](CHANGELOG.md).

### What this doesn't do

- No DNS lookups. You bring the record string; where it came from is your
  business.
- No policy *evaluation* — it doesn't tell you whether a given message passes
  DMARC, only whether the record is well-formed and current.
- No organizational-domain resolution or DNS tree walk (§4.10), no PSL.
- No report parsing — that's RFC 9990 and RFC 9991 territory.

Worth stating plainly, because a clean result is easy to over-read: **a record
with no findings is a well-formed, current record — not a record that is
working.** Several things decide whether DMARC actually functions for a domain,
and none of them are visible in the record text:

- **External destination authorization** (RFC 9990 §4, and RFC 9991 §5 for
  `ruf=`). Pass `policyDomain` and this library will at least tell you a
  destination needs one and give you the name to check; it can never tell you
  whether the record exists. See the usage section above.
- **Whether the DKIM and SPF the record depends on are correct.** A flawless
  `p=reject` record in front of a broken DKIM signature is worse than no record
  at all.
- **The tree walk's actual result** — which Organizational Domain a name
  resolves to, and therefore which record applies and whether `sp=`/`np=` come
  into play, is a DNS question (RFC 9989 §4.10).
- **Whether more than one DMARC record is published** at the name, which makes
  all of them inert. That is a property of the DNS response, not of any single
  record string.

### A worked example: `np=` and the DNSSEC gotcha

The single most useful thing this library says is about the new `np=` tag.
`np=reject` tells receivers to reject mail from subdomains that don't exist
— a rare case where jumping straight to enforcement is safe, since a
non-existent subdomain sends no legitimate mail by definition:

```typescript
const parsed = parse("v=DMARC1; p=quarantine; np=reject; rua=mailto:dmarc@example.com");
validate(parsed).forEach((d) => console.log(d.code, "-", d.message));
```

```
np-reject-safe - np=reject is one of the few enforcement settings that's
reasonable to set immediately, without a gradual none -> quarantine ->
reject rollout: a subdomain that doesn't exist cannot originate legitimate
mail, so there's no legitimate traffic for a false positive to break.

np-compact-denial-caveat - np= relies on the receiver seeing an NXDOMAIN
response for the non-existent subdomain. Some DNSSEC-signed providers
instead use "compact denial of existence" (RFC 9824): they return NOERROR
with an NSEC record's NXNAME bit set, rather than NXDOMAIN. Cloudflare
(since 2016), NS1 (2019), AWS Route 53 (2020) and Azure DNS (2025) all do
this by default. A receiver that checks strictly for NXDOMAIN will
conclude the subdomain exists and silently skip this policy. There's no
sender-side fix — confirm your receiving mail providers recognize NXNAME
before treating np=reject as airtight.
```

That second diagnostic is the reason this library exists: `np=reject` on a
DNSSEC-signed zone hosted at one of those four providers may not be doing
anything yet, and nothing else currently tells you that.

## Running it yourself

```bash
npm install
npm test          # node --test, runs every table-driven case in test/
npm run demo       # parses and validates a handful of real-world records, prints the findings
npm run typecheck   # tsc --noEmit
```

## Why no build step

There's no `dist/` and no bundler. `npm test` and `npm run demo` run the
`.ts` source files directly — Node 22.6+ strips TypeScript's type syntax at
load time without a separate compile step, and this project pins Node 24
(see the parent repo's `.nvmrc`), well past that. `tsc` is still a
devDependency, but only for `npm run typecheck`, which type-checks the
source without emitting anything. Adding a real build (`tsc` emitting `dist/`
plus `.d.ts`) is the gate on a first npm release — see "Status" above.

## Development

This repository is a **mirror**. The library is developed inside the
[praneeth.me](https://praneeth.me) site repo and republished here with
`git subtree split`, so every push replaces this repo's history wholesale.

A pull request opened here can't be merged as-is — it would be overwritten on
the next publish. Open an issue instead, or send a patch in one and it'll be
applied upstream with attribution.

## Project layout

```
dmarcbis/
├── src/
│   ├── types.ts       shared types: Diagnostic, ParsedRecord, ParsedTagEntry
│   ├── parse.ts        parse(): string -> ParsedRecord (syntax only)
│   ├── validate.ts       validate(): ParsedRecord -> Diagnostic[] (RFC 9989 semantics)
│   └── index.ts           public exports
├── test/
│   ├── parse.test.ts      table-driven syntax cases
│   └── validate.test.ts     table-driven semantic cases
├── demo/
│   └── demo.ts               npm run demo — real records, printed findings
├── package.json
├── tsconfig.json
└── CHANGELOG.md
```

## What it checks (RFC 9989 vs. RFC 7489)

| Tag             | Status in RFC 9989                                                    |
| --------------- | ----------------------------------------------------------------------- |
| `v`              | Required, must be first, value is case-sensitive `DMARC1`                |
| `p`              | Still current. If absent **or invalid**, §4.10.1 applies: receivers act as `p=none` when a valid `rua` URI is present, and apply **no DMARC processing at all** otherwise |
| `sp`             | Still current — applies to subdomains that **exist**. An invalid value triggers the same §4.10.1 collapse as `p`, taking the whole record's enforcement with it |
| `np`             | **New** — applies to subdomains that **don't exist**; falls back to `sp`, then `p`. An invalid value collapses the record the same way |
| `adkim`, `aspf`  | Still current (`r`/`s`). An invalid value falls back to the default `r` — the *looser* of the two |
| `fo`             | Still current. **Ignored entirely if `ruf=` is absent** (§4.7); `d` and `s` may each appear at most once |
| `rua`, `ruf`     | Still current. **Any valid URI** is permitted (§4.7) — there is no scheme allow-list, and receivers ignore schemes they don't support. The trailing `!size` cap is obsolete syntax (`obs-dmarc-report-size`). `ruf` carries a privacy note — it can include message content |
| `t`              | **New** — boolean testing flag, replaces `pct`'s role                              |
| `psd`            | **New** — declares a public suffix domain                                           |
| `pct`            | **Removed** — partial/percentage enforcement is gone                                 |
| `rf`             | **Removed** — report format is no longer sender-configurable                          |
| `ri`             | **Removed** — report interval is no longer sender-configurable                         |

Source RFCs: [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989.html) (core
protocol), [RFC 9990](https://www.rfc-editor.org/rfc/rfc9990.html)
(aggregate reporting), [RFC 9991](https://www.rfc-editor.org/rfc/rfc9991.html)
(failure reporting), [RFC 9824](https://www.rfc-editor.org/rfc/rfc9824.html)
(compact denial of existence — the DNSSEC interaction behind the `np=`
caveat above).

## License

MIT
