# Swarf

Swarf is a UCAN revocation service.

## Running

```sh
swarf serve --storage memory
```

By default, Swarf uses PostgreSQL. Configure it with `--postgres-dsn`, a
`config.yaml`, or `SWARF_STORAGE_POSTGRES_DSN`. Configuration sections are
`identity`, `server`, `log`, `storage`, and `principal`; environment variable
names use the `SWARF_` prefix, for example `SWARF_SERVER_PORT`.

`principal.publishers` holds the DIDs allowed to invoke
`/principal/invalidate`, the service identities of the Hilt deployments Swarf
serves. Set it with `--principal-publishers`, repeated or comma-separated, or
with `SWARF_PRINCIPAL_PUBLISHERS` in comma form. A malformed DID fails
startup, and an empty list refuses every invalidation.

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

Stream DAG-JSON records as they arrive with:

```sh
swarf stream
```

Each line is the event kind followed by the record:

```
revocation {"cause":{"/":"bafyreif5fz..."},"path":[],"recorded_at":1784278800000000000,"revoke":{"/":"bafyreiehyt..."}}
principal {"cause":{"/":"bafyreif5fz..."},"principal":"8f2c","recorded_at":1788948000000000000,"tenant":"did:plc:tenant"}
```

By default, it starts from the current time. Pass `--from 0` to stream all
records or `--from <RFC3339 timestamp>` to stream records recorded on or after
that time. Press Ctrl+C to stop streaming. Override the service endpoint with
`--service-url`.

## API

### `POST /`

The UCAN RPC endpoint. It supports `/ucan/revoke` and `/principal/invalidate`.

For `/ucan/revoke`, the invocation arguments identify the revoked delegation
and its delegation
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

`/principal/invalidate` records that every proof a gateway cached for a
principal's keys is void. Its arguments name the tenant and the principal:

```ipldsch
type InvalidateArguments struct {
  tenant    String
  principal String
}
```

No delegation names a principal, so the invocation carries no proof: the
issuer self-signs it with its own DID as subject, and Swarf accepts it only
from an issuer in `principal.publishers`.

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
  "recorded_at": 1784278800000000000
}
```

### `GET /revocations/:from`

A Server-Sent Events stream of compact DAG-JSON records. Each `revocation`
event has `revoke` (the revoked delegation CID), `path` (the witness delegation
CIDs), `cause` (the revocation invocation CID), and `recorded_at` (the time the
record was recorded). Use `0` to stream all stored records, or provide an
RFC3339/RFC3339Nano timestamp cursor to stream records recorded on or after it.
The cursor is inclusive so consumers resuming from the `recorded_at` of the
last event they received do not miss records that share it; deduplicate by the
event `id` (the `cause` CID). For example:

```js
id: bafyreif5fzax7oygfafacvxq2ndhtkshz2av5m42hqeixea7giirdxe5dm
event: revocation
data: {"cause":{"/":"bafyreif5fzax7oygfafacvxq2ndhtkshz2av5m42hqeixea7giirdxe5dm"},"path":[{"/":"bafyreiehytyi4q3t2amvf2abdlt5xnnqtaqkknf6yxhre4klpjnejlnsc4"}],"recorded_at":1784278800000000000,"revoke":{"/":"bafyreiehytyi4q3t2amvf2abdlt5xnnqtaqkknf6yxhre4klpjnejlnsc4"}}
```

The same stream carries `principal` events, which record that every proof a
gateway cached for a principal's keys is void. Each has `tenant` (the tenant
DID), `principal` (the principal identifier, unique within the tenant), `cause`
(the invalidation invocation CID), and `recorded_at` (unix nanoseconds, as for every DAG-JSON time here). Keys are emitted in lexicographic order. The cursor, the inclusive
resume rule, and deduplication by `cause` are the same as for `revocation`
events. A principal revocation event revokes no delegation, so
`GET /revocation/:cid` never returns one. For example:

```js
id: bafyreif5fzax7oygfafacvxq2ndhtkshz2av5m42hqeixea7giirdxe5dm
event: principal
data: {"cause":{"/":"bafyreif5fzax7oygfafacvxq2ndhtkshz2av5m42hqeixea7giirdxe5dm"},"principal":"8f2c","recorded_at":1788948000000000000,"tenant":"did:plc:tenant"}
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

// Invalidate a principal. The issuer must be a configured publisher.
err = client.Invalidate(ctx, hiltIssuer, tenantDID, "8f2c")

record, err := client.Get(ctx, delegationCID)

for event, err := range client.StreamEvents(ctx, time.Time{}) {
    // Exactly one of event.Revocation and event.PrincipalRevocation is set.
}
```

`Publish` self-signs the revocation invocation with the passed revoker, which
must be the issuer of the revoked delegation or appear as an issuer in the
witness path provided with `WithWitnessPath`. `Invalidate` self-signs the
invalidation the same way, with the issuer as subject; Swarf refuses it unless
the issuer is a configured publisher. `Get` returns a full
`store.RevocationRecord`.

`StreamEvents` returns `api.FirehoseEvent` values carrying either a
`FirehoseRevocation` or a `FirehosePrincipalRevocation`. It resumes from the
newest record it delivered and skips causes it already delivered, so a record
that arrives behind newer ones is still yielded once and a reconnect does not
repeat the newer ones. `Stream` yields only the revocations and is deprecated:
a consumer using it never learns of a principal invalidation.

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
