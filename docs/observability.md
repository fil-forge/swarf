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

## Schema migrations

Swarf applies pending Postgres migrations on start, before `/health` answers.
It logs `applying postgres migration` when each one starts, `applied postgres
migration` with its `duration` when it finishes, and `postgres migration
failed` at error level when it does not. A migration runs on connections of
its own with `lock_timeout`, `statement_timeout`,
`idle_in_transaction_session_timeout` and `client_connection_check_interval`
set (`migrations.DefaultLimits`), and a canceled start sends Postgres a cancel
request, so a failed or killed start leaves no backend holding or waiting for a
table lock.
