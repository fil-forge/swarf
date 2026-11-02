-- +goose Up
-- +goose StatementBegin
-- A /ucan/revoke/batch invocation causes one revocation row per revoked
-- delegation. The invocation is stored once, in revocation_cause, and each
-- row links to it.
CREATE TABLE revocation_cause (
    id         TEXT  PRIMARY KEY,
    invocation BYTEA NOT NULL
);

COMMENT ON COLUMN revocation_cause.id IS 'CID of the revocation invocation';
COMMENT ON COLUMN revocation_cause.invocation IS 'Invocation that revoked the delegations';

INSERT INTO revocation_cause (id, invocation)
SELECT id, cause FROM revocation;

ALTER TABLE revocation DROP CONSTRAINT revocation_pkey;
ALTER TABLE revocation DROP COLUMN cause;
ALTER TABLE revocation RENAME COLUMN id TO cause_id;
ALTER TABLE revocation ADD PRIMARY KEY (cause_id, revoked_delegation);
ALTER TABLE revocation ADD FOREIGN KEY (cause_id) REFERENCES revocation_cause (id);

COMMENT ON COLUMN revocation.cause_id IS 'CID of the invocation that revoked the delegation';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Fails once an invocation has revoked more than one delegation, because the
-- previous schema keys each row by its invocation alone.
ALTER TABLE revocation DROP CONSTRAINT revocation_cause_id_fkey;
ALTER TABLE revocation DROP CONSTRAINT revocation_pkey;
ALTER TABLE revocation RENAME COLUMN cause_id TO id;
ALTER TABLE revocation ADD COLUMN cause BYTEA;
UPDATE revocation SET cause = revocation_cause.invocation
FROM revocation_cause WHERE revocation_cause.id = revocation.id;
ALTER TABLE revocation ALTER COLUMN cause SET NOT NULL;
ALTER TABLE revocation ADD PRIMARY KEY (id);

COMMENT ON COLUMN revocation.id IS 'CID of revocation';
COMMENT ON COLUMN revocation.cause IS 'Invocation that revoked the delegation';

DROP TABLE revocation_cause;
-- +goose StatementEnd
