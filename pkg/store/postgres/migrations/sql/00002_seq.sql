-- +goose Up
-- +goose StatementBegin
-- Rows stored before this migration are numbered in recorded_at order, with
-- id ordered bytewise (the "C" collation) breaking ties, so they stream
-- before every row inserted from here on.
ALTER TABLE revocation ADD COLUMN seq BIGINT;

UPDATE revocation
SET seq = numbered.seq
FROM (
    SELECT id, row_number() OVER (ORDER BY recorded_at, id COLLATE "C") AS seq
    FROM revocation
) AS numbered
WHERE revocation.id = numbered.id;

ALTER TABLE revocation ALTER COLUMN seq SET NOT NULL;
ALTER TABLE revocation ALTER COLUMN seq ADD GENERATED ALWAYS AS IDENTITY;
SELECT setval(pg_get_serial_sequence('revocation', 'seq'), coalesce(max(seq), 0) + 1, false)
FROM revocation;

CREATE UNIQUE INDEX revocation_seq_idx ON revocation (seq);

COMMENT ON COLUMN revocation.seq IS 'Position of the revocation in the firehose. Writers take an advisory lock before inserting, so seq order is commit order; values lost to a rolled-back or conflicting insert leave gaps';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS revocation_seq_idx;
ALTER TABLE revocation DROP COLUMN IF EXISTS seq;
-- +goose StatementEnd
