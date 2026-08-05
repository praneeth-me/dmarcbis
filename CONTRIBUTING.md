# Contributing

Thanks for looking. This is a small, deliberately narrow library: it parses
DMARC records and checks them against RFC 9989. It is not trying to become a
general email-authentication toolkit, and scope creep is the main thing that
would ruin it.

## Getting set up

```bash
git clone https://github.com/praneeth-me/dmarcbis.git
cd dmarcbis
npm install
npm test
npm run demo
```

There is no build step for development. Node 22.6+ runs the TypeScript source
directly via native type stripping, so `npm test` and `npm run demo` execute
`src/` as-is. `npm run typecheck` runs `tsc --noEmit` and is the only thing
TypeScript is installed for.

## The shape of the library

Two functions, kept deliberately apart:

- **`parse()`** reads. It turns a raw TXT string into structured data and
  reports syntax problems. It has no opinions about whether a record is a
  good idea, and it never throws.
- **`validate()`** judges. It takes parse output and checks it against the
  RFC, returning structured diagnostics.

If you find yourself wanting `parse()` to warn about policy choices, or
`validate()` to re-read raw text, that is a sign the change belongs on the
other side of the line.

## Diagnostics

Every finding is an object, never a boolean and never a bare string:

```ts
{ code: "removed-tag", severity: "warning", tag: "pct", message: "..." }
```

- **`code`** is a stable identifier. Consumers match on it, so treat a rename
  as a breaking change.
- **`severity`** is `error` (the record is invalid or will be ignored by
  receivers), `warning` (valid but probably not what you meant), or `info`
  (correct, but there is something worth knowing).
- **`message`** is written for a human administrator, not a spec author.
  Prefer "receivers ignore it outright, which quietly turns a partial rollout
  into full enforcement" over "deprecated per §4.4". Explain the consequence.

## Tests

The test suite is the specification in executable form, and it is the first
thing a reader will judge this library by. Cases are table-driven — one row per
case, fed through one test — in `test/parse.test.ts` and `test/validate.test.ts`.

Any change to behaviour needs a row. Any new diagnostic needs a row asserting
it appears, and usually one asserting it *doesn't* appear on a record that
wasn't trying to trigger it.

`mustMatch` asserts a diagnostic's wording rather than just its presence. Use
it sparingly, for messages whose specific claim is the point — `t=y` at
`p=reject` has to say mail is *quarantined*, because a vague "this is a test"
would read fine and be wrong.

## Verifying against the RFC

Claims in this library are checked against the RFCs themselves, not against
blog posts or other tools — much of the published material still describes
RFC 7489 and is now wrong in specific, load-bearing ways.

- [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989.html) — DMARC (replaces 7489)
- [RFC 9990](https://www.rfc-editor.org/rfc/rfc9990.html) — aggregate reporting
- [RFC 9991](https://www.rfc-editor.org/rfc/rfc9991.html) — failure reporting
- [RFC 9824](https://www.rfc-editor.org/rfc/rfc9824.html) — compact denial of existence

If you are changing what the library says about a tag, cite the section.

## Pull requests

- One concern per PR.
- Tests with the change, not after it.
- `npm test` and `npm run typecheck` both clean.
- Explain *why* in the description. The what is visible in the diff.
