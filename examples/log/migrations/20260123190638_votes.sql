-- Add migration script here
CREATE TABLE IF NOT EXISTS consensus_votes (
    id BIGSERIAL PRIMARY KEY,
    epoch BIGINT NOT NULL,
    view BIGINT NOT NULL,
    artifact BYTEA NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_consensus_votes_epoch_view ON consensus_votes(epoch, view);
