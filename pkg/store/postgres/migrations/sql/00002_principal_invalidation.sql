-- +goose Up
-- +goose StatementBegin
CREATE TABLE principal_invalidation (
    id          TEXT        PRIMARY KEY,
    cause       BYTEA       NOT NULL,
    tenant      TEXT        NOT NULL,
    principal   TEXT        NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON COLUMN principal_invalidation.id IS 'CID of invalidation';
COMMENT ON COLUMN principal_invalidation.cause IS 'Invocation that invalidated the principal';
COMMENT ON COLUMN principal_invalidation.tenant IS 'DID of the tenant the principal belongs to';
COMMENT ON COLUMN principal_invalidation.principal IS 'Principal identifier, unique within the tenant';

CREATE INDEX principal_invalidation_recorded_at_idx ON principal_invalidation (recorded_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS principal_invalidation;
-- +goose StatementEnd
