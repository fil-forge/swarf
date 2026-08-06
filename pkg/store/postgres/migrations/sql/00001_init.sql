-- +goose Up
-- +goose StatementBegin
CREATE TABLE revocation (
    id                 TEXT        PRIMARY KEY,
    cause              BYTEA       NOT NULL,
    revoked_delegation TEXT        NOT NULL,
    path_witness       BYTEA[]     NOT NULL,
    recorded_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON COLUMN revocation.id IS 'CID of revocation';
COMMENT ON COLUMN revocation.cause IS 'Invocation that revoked the delegation';
COMMENT ON COLUMN revocation.revoked_delegation IS 'CID of revoked delegation';
COMMENT ON COLUMN revocation.path_witness IS 'Delegation chain from root delegation to revoked delegation';

CREATE INDEX revocation_recorded_at_idx ON revocation (recorded_at);
CREATE INDEX revocation_revoked_delegation_idx ON revocation (revoked_delegation);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS revocation;
-- +goose StatementEnd
