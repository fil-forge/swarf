# Swarf

Swarf is a UCAN revocation service.

## Running

```sh
swarf serve --storage memory
```

By default, Swarf uses PostgreSQL, version 13 or later. Configure it with
`--postgres-dsn`, a `config.yaml`, or `SWARF_STORAGE_POSTGRES_DSN`.
Configuration sections are `identity`, `server`, `log`, and `storage`;
environment variable names use the `SWARF_` prefix, for example
`SWARF_SERVER_PORT`.

## CLI

### `swarf revoke <revoke-cid> <delegation-or-container>`

Publish a revocation with an issuer PEM key, the CID to revoke, and the
delegation to revoke:

```sh
swarf revoke \
  --issuer-key-file issuer.pem \
  <revoke-cid> \
  <delegation-or-container>
```

`delegation-or-container` can be a file path or an encoded UCAN container
string. A file may contain either a CBOR-encoded delegation or a UCAN container
holding the delegation to revoke. When the issuer key issued the revoked
delegation, the delegation alone is enough; otherwise the container must also
include the delegation witnesses, from which Swarf builds the witness chain.
The service defaults to `did:web:swarf.forgery.network` at
`https://swarf.forgery.network`; override these with `--service-id` and
`--service-url`.

### `swarf get <revoke-cid>`

Retrieve a revocation’s DAG-JSON record with:

```sh
swarf get <revoke-cid>
```

The command prints the service response and exits silently if the revocation is
not found. Override the service endpoint with `--service-url`.

### `swarf stream`

Stream revocation DAG-JSON records as they arrive with:

```sh
swarf stream
```

By default, it starts from the current time. Pass `--from 0` to stream all
records or `--from <RFC3339 timestamp>` to stream records recorded on or after
that time. Press Ctrl+C to stop streaming. Override the service endpoint with
`--service-url`.

## API

### `POST /`

The UCAN RPC endpoint. It supports `/ucan/revoke`; the invocation arguments
identify the revoked delegation and its delegation
[path witness](https://github.com/ucan-wg/revocation#path-witness). These
delegations must be included in the invocation metadata. For example:

```ipldsch
type RevokeArguments struct {
  revoke Link
  path [Link]
}
```

`path` proves the revocation issuer's authority over a delegation issued by
someone else further down a chain the issuer is involved in, and may be empty
when the revocation issuer issued the revoked delegation directly. The revoked
delegation itself must always be included in the invocation metadata.

### `GET /revocation/:cid`

Retrieves the most recent revocation for a delegation. It returns a DAG-JSON
record containing `revoke` (the delegation CID), `cause` (the CBOR-encoded
revocation invocation), and CBOR-encoded witness delegation blocks, or `404`
when no revocation exists. For example:

```json
{
  "revoke": {"/": "bafyreiehytyi4q3t2amvf2abdlt5xnnqtaqkknf6yxhre4klpjnejlnsc4"},
  "cause": {"/": {"bytes": "omF2AWNjYXBnL3VjYW4vcmV2b2tl"}},
  "path": [
    {"/": {"bytes": "omF2AWNjYXBsL3Rlc3QvaW52b2tl"}}
  ],
  "recorded_at": "2026-07-17T09:00:00Z"
}
```

### `GET /revocations/:from`

A Server-Sent Events stream of compact DAG-JSON records recorded at or after a
time. Each event has `revoke` (the revoked delegation CID), `path` (the witness
delegation CIDs), `cause` (the revocation invocation CID), and `recorded_at`
(the time the record was recorded). Use `0` to stream all stored records, or
provide an RFC3339/RFC3339Nano timestamp to stream records recorded on or after
it. The stream never yields a record recorded before that time. Each event's
`id` is a [cursor](#cursors). For example:

```js
id: 1734-bafyreif5fzax7oygfafacvxq2ndhtkshz2av5m42hqeixea7giirdxe5dm
event: revocation
data: {"revoke":{"/":"bafyreiehytyi4q3t2amvf2abdlt5xnnqtaqkknf6yxhre4klpjnejlnsc4"},"path":[{"/":"bafyreiehytyi4q3t2amvf2abdlt5xnnqtaqkknf6yxhre4klpjnejlnsc4"}],"cause":{"/":"bafyreif5fzax7oygfafacvxq2ndhtkshz2av5m42hqeixea7giirdxe5dm"},"recorded_at":"2026-07-17T09:00:00Z"}
```

Records do not reach the stream in `recorded_at` order: `recorded_at` is when
the transaction recording a revocation started, and a transaction that started
earlier can finish later. So a time query is not a way to resume a stream. A
new query from the `recorded_at` of the last event received can miss records
recorded before it that reached the stream after it. To resume, use a cursor.

### `GET /revocations/after/:cursor`

The same stream, starting after a [cursor](#cursors): the `id` of an event
received earlier, from either endpoint. Pass `now` instead to start at the head
of the stream as Swarf's database sees it when the request arrives, rather than
at a time on the client's clock. A stream started at `now` first sends an event
with only an `id`, the cursor `now` stands for. It carries no data, so it
dispatches nothing, but it sets an SSE client's last event ID, so a client that
reconnects before the first record resumes from there.

Swarf answers `409` for a cursor ahead of the stream's head, which it cannot
have issued: one from before its database [moved](#moving-the-database), or
from before an in-memory store restarted. Streaming after it would skip every
record up to it. A consumer that gets one has to start over: from `0`, or from
a time well before the last record it applied, deduplicating by `cause`. A
time query from that record's own `recorded_at` can miss records, as described
above, and `now` skips every record since it.

### Cursors

A cursor is an opaque token, sent as each event's `id`. A stream resumed after
a cursor yields every record that follows it, and only those. A record reaches
the stream only once no earlier record can still appear, so a consumer that
stores the cursor of the last record it applied, and resumes after it, misses
nothing.

Both endpoints honor the standard
[`Last-Event-ID`](https://html.spec.whatwg.org/multipage/server-sent-events.html#the-last-event-id-header)
request header, which an SSE client such as `EventSource` sends when it
reconnects. The stream resumes after that event, and keeps whatever the URL
selects: a time query reconnected this way still yields nothing recorded
before its time, and `Last-Event-ID` takes the place of a `/revocations/after/`
cursor. A `Last-Event-ID` that is not a cursor is ignored, and the stream
starts where the URL says. One ahead of the head shows that the stream's
database changed since the stream began: a time query ignores it and starts
over from its time, and `/revocations/after/` answers `409`, since neither its
cursor nor the head is a safe place to start.

Delivery is at least once: a consumer that stores its cursor less often than
it applies records, or reconnects with an older one, receives some records
again. Deduplicate by `cause`, the CID of the revocation invocation, which is
unique to a record.

### Stream delays

With PostgreSQL storage, the stream holds a record back until every database
transaction that started writing before it has finished, so that no earlier
record can appear once it is sent. That covers every transaction on the
PostgreSQL server, in any database, that has been assigned a transaction ID,
which a transaction is when it first writes or locks rows. So a long-running
transaction that has written, or a session left idle in one, delays the stream
for as long as it stays open; a transaction that only reads does not. To find
what is holding the stream back, look for the oldest transactions with a
`backend_xid` in `pg_stat_activity`, and in `pg_prepared_xacts`.

### Moving the database

The stream's order and its cursors come from the PostgreSQL server's
transaction IDs. A row keeps its transaction ID when it is copied to another
server, while new rows there get that server's. Upgrading in place with
`pg_upgrade`, or failing over to a physical replica that is caught up, keeps
the counter, and cursors keep working.

Moving the data with `pg_dump` and a restore, or with logical replication,
does not keep the counter, and voids every cursor issued before the move:

- Copied rows can sit ahead of the new server's counter, and stay out of the
  stream until it catches up. Before Swarf serves the stream from the new
  server, run `UPDATE revocation SET transaction_id = '0'`, so every copied row
  streams first.
- A consumer resuming after an old cursor can skip records, and that includes
  a stream left open across the move, which reconnects after the last event it
  received. Stop every consumer's stream, have each drop its stored cursor, and
  start them over as after a `409`: from `0`, or from a time well before the
  last record each applied, deduplicating by `cause`. Swarf refuses with `409`
  an old cursor that is ahead of the new server's head, but it accepts one that
  is not, so the refusal can't be relied on to catch every old cursor.

## Client library

Construct a client with the Swarf service DID and URL, and pass the issuer
revoking a delegation to each `Publish` call:

```go
serviceURL, _ := url.Parse("https://swarf.example.com")
client, _ := swarfclient.New(serviceDID, *serviceURL)

// Revoke a delegation you issued directly.
err := client.Publish(ctx, revoker, revoked)

// Provide a witness path (root first) when revoking a delegation issued by
// someone else further down a chain you are involved in.
err = client.Publish(ctx, revoker, revoked, swarfclient.WithWitnessPath(path...))

record, err := client.Get(ctx, delegationCID)

for revocation, err := range client.Stream(ctx, time.Time{}) {
    // revocation.Revoke, revocation.Path, and revocation.Cause are CIDs;
    // revocation.RecordedAt is a time.
}

// Resume after a stored cursor, or start at the head of the stream with
// swarfclient.Now.
for event, err := range client.StreamAfter(ctx, swarfclient.Now) {
    // event.Revocation is the revocation; store event.Cursor once it is
    // applied, and pass it to StreamAfter to resume.
}
```

`Publish` self-signs the revocation invocation with the passed revoker, which
must be the issuer of the revoked delegation or appear as an issuer in the
witness path provided with `WithWitnessPath`. `Get` returns a full
`store.RevocationRecord`; `Stream` returns compact `api.FirehoseRevocation`
values. `StreamAfter` returns them as `Event`s with their cursors, and so does
`StreamEvents`, which runs `Stream`'s time query, for a consumer that starts
from a time and then resumes by cursor. All of them reconnect when the stream
is interrupted, resuming after the last event received. A `409` ends the
stream with an error wrapping `ErrCursorRefused`.

## Container images

A push to `main` publishes to GHCR from the `Container` workflow. The `prod`
target becomes `ghcr.io/fil-forge/swarf:main`, a stripped binary on a slim
Debian base. The `dev` target becomes `ghcr.io/fil-forge/swarf:main-dev` and
adds delve plus a handful of debugging tools. Both cover `linux/amd64` and
`linux/arm64`, and both also carry a `sha-<short-sha>` tag, the dev image with a
`-dev` suffix.

## Deploying to dev

The same run asks [infra-central][] to deploy the prod image. It dispatches a
`bump-deployed-image` event carrying the manifest digest it just pushed, and
infra-central's [Bump deployed image][receiver] workflow opens a pull request
pinning that digest in `terraform/envs/dev/apps/terraform.tfvars`, with
auto-merge enabled. infra-central's [Check and deploy][deploy] workflow runs
`tofu apply` on `dev/apps` on every push to its `main`, so merging that pull
request is what deploys.

The dispatch runs as the `fil-forge-bot` GitHub App and needs the
`FORGE_BOT_APP_ID` variable and the `FORGE_BOT_PRIVATE_KEY` secret. Prod pins
are promoted by hand.

[infra-central]: https://github.com/fil-forge/infra-central
[receiver]: https://github.com/fil-forge/infra-central/blob/main/.github/workflows/bump-deployed-image.yml
[deploy]: https://github.com/fil-forge/infra-central/blob/main/.github/workflows/check-and-deploy.yml
