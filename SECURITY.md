# Security policy

## Reporting a vulnerability

Report privately through GitHub's
[security advisory form](https://github.com/praneeth-me/dmarcbis/security/advisories/new),
not as a public issue.

Expect an acknowledgement within a week. This is a personal project maintained
in spare time — it is not a product with an on-call rotation, and you should
size your expectations accordingly.

## What is in scope

This library takes untrusted input: a DMARC record is a string fetched from
DNS, which means it is controlled by whoever owns the domain being looked at,
not by the person running the check. Things that matter:

- **Crashes on hostile input.** `parse()` and `validate()` must never throw,
  whatever they are handed. A record that takes down the caller is a bug worth
  reporting.
- **Runaway processing.** A record crafted to cause pathological backtracking
  or unbounded work — catastrophic regex behaviour, quadratic loops on a long
  string. There are tests for very long inputs, but they are not exhaustive.
- **Wrong verdicts with security consequences.** A record that should raise an
  `error` and comes back clean, particularly around `v=`, `p=`, `sp=` and `np=`.
  Someone may be relying on this to tell them their domain is protected.

## What is not in scope

- **This library does no I/O.** It makes no network requests, reads no files,
  and touches no DNS. It is given a string and returns objects. Anything about
  fetching records belongs to whatever calls it.
- **Being wrong about the RFC** is a correctness bug, not a vulnerability —
  open a normal issue, unless the wrong answer has the security consequence
  described above.
- **Advice quality.** The library explains what a record does and flags what
  looks unwise. It is not a substitute for understanding your own mail flow,
  and acting on its output is the operator's call.

## Supported versions

Pre-1.0. Only the latest release gets fixes.
