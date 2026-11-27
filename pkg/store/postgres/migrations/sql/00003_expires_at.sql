-- +goose Up
-- +goose StatementBegin
-- Rows stored before this migration keep a NULL expires_at, so they are never
-- evicted, whether or not the delegation they revoke expires.
ALTER TABLE revocation ADD COLUMN expires_at TIMESTAMPTZ;

COMMENT ON COLUMN revocation.expires_at IS 'When the revoked delegation expires, after which the row can be evicted. NULL when the delegation never expires';

CREATE INDEX revocation_expires_at_idx ON revocation (expires_at) WHERE expires_at IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS revocation_expires_at_idx;
ALTER TABLE revocation DROP COLUMN IF EXISTS expires_at;
-- +goose StatementEnd
