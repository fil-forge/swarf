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

### `swarf stream <since>`

Stream revocation DAG-JSON records as they arrive with:

```sh
swarf stream
```

By default, it starts from the current time. Pass `--since 0` to stream all
records or `--since <RFC3339 timestamp>` to start after that time. Press Ctrl+C
to stop streaming. Override the service endpoint with `--service-url`.

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

### `GET /revocations/:since`

A Server-Sent Events stream of compact DAG-JSON records. Each event has `revoke`
(the revoked delegation CID), `path` (the witness delegation CIDs), `cause` (the
revocation invocation CID), and `recorded_at` (the time the record was recorded). Use `0`
to stream all stored records, or provide an RFC3339/RFC3339Nano timestamp cursor
to stream records created after it. For example:

```js
id: bafyreif5fzax7oygfafacvxq2ndhtkshz2av5m42hqeixea7giirdxe5dm
event: revocation
data: {"revoke":{"/":"bafyreiehytyi4q3t2amvf2abdlt5xnnqtaqkknf6yxhre4klpjnejlnsc4"},"path":[{"/":"bafyreiehytyi4q3t2amvf2abdlt5xnnqtaqkknf6yxhre4klpjnejlnsc4"}],"cause":{"/":"bafyreif5fzax7oygfafacvxq2ndhtkshz2av5m42hqeixea7giirdxe5dm"},"recorded_at":"2026-07-17T09:00:00Z"}
```

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

for event, err := range client.Stream(ctx, time.Time{}) {
    // event.Revoke, event.Path, and event.Cause are CIDs; event.RecordedAt is a time.
}
```

`Publish` self-signs the revocation invocation with the passed revoker, which
must be the issuer of the revoked delegation or appear as an issuer in the
witness path provided with `WithWitnessPath`. `Get` returns a full
`store.RevocationRecord`; `Stream` returns compact `api.FirehoseRevocation`
values.
