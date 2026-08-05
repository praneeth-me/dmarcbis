CI runs the type check and the full table-driven test suite on every push and
pull request, against both the minimum supported Node version and current.

There is no build or publish step here on purpose: releasing is a deliberate
act, not something that happens because a commit landed.
