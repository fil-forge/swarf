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

## API

`POST /` is the UCAN RPC endpoint. It supports `/ucan/revoke`; the invocation
arguments identify the revoked delegation and its path, whose witness blocks
must be included in the invocation metadata.

`GET /revocation/:cid` retrieves the most recent revocation for a delegation.
It returns a DAG-JSON record containing `revoke` (the delegation CID), `cause`
(the CBOR-encoded revocation invocation), and CBOR-encoded witness delegation
blocks, or `404` when no revocation exists.

`GET /revocations/:since` is a Server-Sent Events stream of compact DAG-JSON
records. Each event has `revoke` (the revoked delegation CID), `path` (the
witness delegation CIDs), `cause` (the revocation invocation CID), and
`created_at` (the record creation time). Use `0` to stream all stored records,
or provide an RFC3339/RFC3339Nano timestamp cursor to stream records created
after it.

## Client library

Construct a client with the Swarf service DID, URL, and the issuer that is
revoking a delegation:

```go
serviceURL, _ := url.Parse("https://swarf.example.com")
client, _ := swarfclient.New(serviceDID, *serviceURL, issuer)

// The final delegation in path is the delegation to revoke.
err := client.Publish(ctx, path[len(path)-1].Link(), path)

record, err := client.Get(ctx, delegationCID)

for event, err := range client.Stream(ctx, time.Time{}) {
    // event.Revoke, event.Path, and event.Cause are CIDs; event.CreatedAt is a time.
}
```

`Publish` self-signs the revocation invocation; its issuer must appear in the
delegation path. `Get` returns a full `store.RevocationRecord`; `Stream`
returns compact `api.FirehoseRevocation` values.
