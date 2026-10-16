# Agent Guidelines

Swarf is the UCAN revocation service; `README.md` describes running it and its CLI.

## Observability

When a change adds or alters behavior someone depends on, decide how on-call
would see it working and see it fail, and add that in the same PR where it is
useful: logs, and an alert or dashboard panel in fil-forge/infra-central. Skip
it for changes nothing operational depends on. When a feature's health is best
read as a number, say so in the PR description, naming the metric and
[FIL-1152](https://linear.app/filecoin-foundation/issue/FIL-1152). "Adding a
signal" in `docs/observability.md` says how to do each.
