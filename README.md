# Swarf

Swarf is a UCAN revocation service.

## Running

```sh
swarf serve --storage memory
```

By default, Swarf uses PostgreSQL. Configure it with `--postgres-dsn`, a
`config.yaml`, or `SWARF_STORAGE_POSTGRES_DSN`. Configuration sections are
`identity`, `server`, `log`, and `storage`; environment variable names use the
`SWARF_` prefix, for example `SWARF_SERVER_PORT`.

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

By default, it starts at the head of the stream, so it prints only the records
that arrive from then on. Pass `--after <cursor>` to start after a
[cursor](#cursors), or `--after 0` to stream every record. Press Ctrl+C to
stop streaming. Override the service endpoint with `--service-url`.

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

A request may carry several `/ucan/revoke` invocations. Each one is validated
on its own and gets its own receipt, and the valid ones are stored together
with one database write, so they share the same `recorded_at`. If that write
fails, every revocation of the request gets a short-lived error receipt;
retrying is safe.

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

### `GET /revocations/after/:cursor`

A Server-Sent Events stream of compact DAG-JSON records, starting after a
[cursor](#cursors). Each event has `revoke` (the revoked delegation CID),
`path` (the witness delegation CIDs), `cause` (the revocation invocation CID),
and `recorded_at` (the time the record was recorded), and its `id` is the
record's cursor. Use `0` to stream every stored record. For example:

```js
id: 1734
event: revocation
data: {"revoke":{"/":"bafyreiehytyi4q3t2amvf2abdlt5xnnqtaqkknf6yxhre4klpjnejlnsc4"},"path":[{"/":"bafyreiehytyi4q3t2amvf2abdlt5xnnqtaqkknf6yxhre4klpjnejlnsc4"}],"cause":{"/":"bafyreif5fzax7oygfafacvxq2ndhtkshz2av5m42hqeixea7giirdxe5dm"},"recorded_at":"2026-07-17T09:00:00Z"}
```

Records reach the stream in the order Swarf stored them, which is not always
`recorded_at` order, so `recorded_at` is not a position in the stream.

Pass `now` instead of a cursor to start at the head of the stream as Swarf's
database sees it when the request arrives, rather than at a time on the
client's clock. A stream started at `now` first sends an event with only an
`id`, the cursor `now` stands for. It carries no data, so it dispatches
nothing, but it sets an SSE client's last event ID, so a client that
reconnects before the first record resumes from there.

Swarf answers `409` for a cursor ahead of the stream's head, which it cannot
have issued: one from another database, such as one restored from an older
backup, or from before an in-memory store restarted. Streaming after it would
skip every record up to it. A consumer that gets one has to start over: after
`now`, which skips every record since the last one it applied, or after a
cursor it stored from [`/revocations/head`](#get-revocationshead) earlier, or
after `0`, deduplicating by `cause` the records it receives again.

### `GET /revocations/head`

Responds with the cursor at the head of the stream as plain text: the cursor
of the last record stored, or `0` when there is none. A stream after it yields
every record stored from then on. The response is never cached.

A consumer that starts after `now` has no cursor of its own to store until its
first record arrives, and revocations are rare. If it restarts before then, it
starts after `now` again and misses every record that arrived while it was
down. A new consumer avoids that by fetching the head, storing it, and
streaming after it.

### Cursors

A cursor is a decimal number, sent as each event's `id`. Swarf numbers each
record as it stores it, and records reach the stream in that order. Swarf
stores one write at a time, so a write takes its numbers only after the one
before it has finished, and no record can appear behind one already streamed.
A consumer that stores the cursor of the last record it applied, and resumes
after it, misses nothing. The numbers can have gaps, so treat a cursor as a
position to pass back, not a count.

`/revocations/after/` honors the standard
[`Last-Event-ID`](https://html.spec.whatwg.org/multipage/server-sent-events.html#the-last-event-id-header)
request header, which an SSE client such as `EventSource` sends when it
reconnects. The stream resumes after that event, in place of the cursor or
`now` in the URL. A `Last-Event-ID` that is not a cursor is ignored, and the
stream starts where the URL says. One ahead of the head shows that the
stream's database changed since the stream began, and Swarf answers `409`,
since neither the URL's position nor the head is a safe place to start.

Delivery is at least once: a consumer that stores its cursor less often than
it applies records, or resumes from an older one, receives some records again.
Deduplicate by `cause`, the CID of the revocation invocation, which is unique
to a record. Records repeat when a consumer restarts, so what it deduplicates
against has to survive its restarts too.

### Moving the database

A cursor is the `seq` column of the `revocation` table, so cursors move with
the data. A `pg_dump`, taken once the old server has stopped taking writes, and
restored keeps every row's `seq` and the position of the identity sequence that
numbers new rows, so stored cursors keep working, and so does a stream left
open across the move. Upgrading in place with `pg_upgrade`, or failing over to
a physical replica that is caught up, keeps them too.

Logical replication copies every row's `seq`, but not the sequence's position.
Before the new server takes writes, set the sequence past the highest `seq`:

```sql
SELECT setval(pg_get_serial_sequence('revocation', 'seq'), coalesce(max(seq), 0) + 1, false)
FROM revocation;
```

Otherwise the new server hands out numbers from the start again. A write that
draws a number a copied record holds fails, and one that draws a free number
lands behind records consumers have already streamed, so they never receive
it.

Restoring a backup older than the last write loses the records written after
it, and consumers can hold cursors past the restored head. Swarf refuses those
with `409` until new records pass them, then accepts them and skips the
records in between. After such a restore, have every consumer start over as
after a `409`.

Restarting Swarf with in-memory storage voids every position in the same way,
besides losing every record.

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

// Before following the stream for the first time, store its head.
head, err := client.Head(ctx)

// Resume after a stored cursor, or start at the head of the stream with
// swarfclient.Now.
for event, err := range client.StreamAfter(ctx, head) {
    // event.Revocation.Revoke, .Path, and .Cause are CIDs, and .RecordedAt
    // is a time. Store event.Cursor once the revocation is applied, and pass
    // it to StreamAfter to resume.
}
```

`Publish` self-signs the revocation invocation with the passed revoker, which
must be the issuer of the revoked delegation or appear as an issuer in the
witness path provided with `WithWitnessPath`. `Get` returns a full
`store.RevocationRecord`. `StreamAfter` returns compact
`api.FirehoseRevocation` values as `Event`s with their cursors, and reconnects
when the stream is interrupted, resuming after the last event received. A
`409` ends the stream with an error wrapping `ErrCursorRefused`. `Head`
returns the head of the stream, a cursor to pass to `StreamAfter`.

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
