# Observability

How this service's failures reach on-call, and what a change adds so that they
do.

## Adding a signal

- **Logs are what reaches Grafana today.** This service runs in Forge Central,
  whose CloudWatch logs and AWS metrics (load balancer, ECS, RDS) ship to
  Grafana; its own metrics don't yet
  ([FIL-1152](https://linear.app/filecoin-foundation/issue/FIL-1152): Ship
  metrics from swarf, delegator and piri-signing-service to Grafana). Log a
  failure an operator would act on at error level, with the context needed to
  act on it (DIDs and CIDs, never key material), in a stable message an alert
  can match.
- **Metrics.** When a feature's health is best read as a number, such as a
  failure count, a queue depth or the time of the last success, say so in the PR
  description, naming the metric and
  [FIL-1152](https://linear.app/filecoin-foundation/issue/FIL-1152), so it can
  be carried to the issue and instrumented when the service exports metrics.
- **Alerts and dashboard panels** live in fil-forge/infra-central, under
  `terraform/envs/grafana/`; its `docs/observability.md` ("Adding an alert or
  panel") says how to add them. Open a companion PR there, or say in this PR
  that one is needed.
