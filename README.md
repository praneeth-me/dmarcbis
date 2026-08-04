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

## Install

This library isn't published to npm — it's staged in this repo for review
before moving to its own public repository. To use it locally:

```bash
git clone <this-repo>
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
[warning] (pct) removed-tag: pct= was removed in RFC 9989 (DMARCbis). DMARCbis
receivers ignore it outright, which quietly turns a partial rollout into full
enforcement at whatever p= says the moment a receiver updates to the new spec.
If a gradual rollout was the goal, use t=y (testing mode) instead.
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
source without emitting anything. When this library eventually moves to
its own repo for publishing, that's the point to add a real build
(`tsc` emitting `dist/` + `.d.ts` files) — there's deliberately no packaging
concern mixed into this staging area yet.

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
| `p`              | Still current; record defaults to `p=none` if absent                       |
| `sp`             | Still current — applies to subdomains that **exist**                        |
| `np`             | **New** — applies to subdomains that **don't exist**; falls back to `sp`, then `p` |
| `adkim`, `aspf`  | Still current (`r`/`s`)                                                       |
| `fo`             | Still current                                                                    |
| `rua`, `ruf`     | Still current (`ruf` carries a privacy note — it can include message content)     |
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
