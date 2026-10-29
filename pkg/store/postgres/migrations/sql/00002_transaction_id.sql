-- +goose Up
-- +goose StatementBegin
-- Existing rows share transaction ID 0, below any transaction's own, so they
-- stream before every row inserted from here on. Changing the default
-- afterwards leaves their value in place.
ALTER TABLE revocation ADD COLUMN transaction_id XID8 NOT NULL DEFAULT '0';
ALTER TABLE revocation ALTER COLUMN transaction_id SET DEFAULT pg_current_xact_id();

COMMENT ON COLUMN revocation.transaction_id IS 'ID of the transaction that inserted the revocation; the firehose streams in (transaction_id, id) order';

CREATE INDEX revocation_transaction_id_idx ON revocation (transaction_id, id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS revocation_transaction_id_idx;
ALTER TABLE revocation DROP COLUMN IF EXISTS transaction_id;
-- +goose StatementEnd
