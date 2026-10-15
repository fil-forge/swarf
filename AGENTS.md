# Agent Guidelines

Swarf is the UCAN revocation service; `README.md` describes running it and its CLI.

## Observability

When a change adds or alters behavior someone depends on, decide how on-call
would see it working and see it fail, and add that in the same PR where it is
useful. Skip it for changes nothing operational depends on.

- **Logs are what reaches Grafana today.** This service runs in Forge Central,
  whose CloudWatch logs and AWS metrics (load balancer, ECS, RDS) ship to
  Grafana; its own metrics don't yet
  ([FIL-1152](https://linear.app/filecoin-foundation/issue/FIL-1152): Ship
  metrics from swarf, delegator and piri-signing-service to Grafana). Log a
  failure an operator would act on at error level, with the context needed to
  act on it (DIDs and CIDs, never key material), in a stable message an alert
  can match.
- **Metrics.** When a feature's health is best read as a number, such as a
  failure count, a queue depth or the time of the last success, say so in the
  PR description, naming the metric and
  [FIL-1152](https://linear.app/filecoin-foundation/issue/FIL-1152), so it can
  be carried to the issue and instrumented when the service exports metrics.
- **Alerts and dashboard panels** live in fil-forge/infra-central, under
  `terraform/envs/grafana/`; its `AGENTS.md` says how to add them. Open a
  companion PR there, or say in this PR that one is needed.
