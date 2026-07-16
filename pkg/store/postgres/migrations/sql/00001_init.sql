-- +goose Up
-- +goose StatementBegin
CREATE TABLE revocation (
    id                 TEXT        PRIMARY KEY,
    revocation         BYTEA       NOT NULL,
    revoked_delegation TEXT        NOT NULL,
    path_witness       BYTEA[]     NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON COLUMN revocation.id IS 'CID of revocation';
COMMENT ON COLUMN revocation.revocation IS 'Invocation that revoked the delegation';
COMMENT ON COLUMN revocation.revoked_delegation IS 'CID of revoked delegation';
COMMENT ON COLUMN revocation.path_witness IS 'Delegation chain from root delegation to revoked delegation';

CREATE INDEX revocation_created_at_idx ON revocation (created_at);
CREATE INDEX revocation_revoked_delegation_idx ON revocation (revoked_delegation);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS revocation;
-- +goose StatementEnd
