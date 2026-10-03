-- Enrichment layer schema (PostgreSQL).
-- Cache can live in Redis instead; the enrichment_cache table is the DB fallback.

-- Opt-out / suppression list. A subject is matchable by any identifier they own.
CREATE TABLE IF NOT EXISTS suppression_list (
    entity_type      TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    reason           TEXT,
    added_by         TEXT,
    added_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (entity_type, normalized_value)
);

-- One row per scan: who ran it, why, when, and the outcome summary.
CREATE TABLE IF NOT EXISTS scan_audit (
    scan_id      TEXT PRIMARY KEY,
    requester_id TEXT NOT NULL,
    purpose      TEXT NOT NULL,
    seed_type    TEXT NOT NULL,
    seed_value   TEXT NOT NULL,           -- normalized
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at     TIMESTAMPTZ,
    summary      JSONB
);
CREATE INDEX IF NOT EXISTS scan_audit_requester_idx ON scan_audit (requester_id, started_at DESC);

-- Every time a suppressed entity was encountered (seed, discovered, or produced).
CREATE TABLE IF NOT EXISTS suppression_hits (
    id               BIGSERIAL PRIMARY KEY,
    scan_id          TEXT NOT NULL REFERENCES scan_audit(scan_id),
    entity_type      TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    stage            TEXT NOT NULL,       -- seed | discovered | produced
    at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Entity nodes seen in a scan (the graph vertices).
CREATE TABLE IF NOT EXISTS scan_entities (
    scan_id           TEXT NOT NULL REFERENCES scan_audit(scan_id),
    entity_type       TEXT NOT NULL,
    entity_value      TEXT NOT NULL,
    normalized_value  TEXT NOT NULL,
    depth             INT  NOT NULL,
    parent_normalized TEXT,
    PRIMARY KEY (scan_id, entity_type, normalized_value)
);

-- Findings (the graph edges): module derived entity from parent, with provenance.
CREATE TABLE IF NOT EXISTS findings (
    id               BIGSERIAL PRIMARY KEY,
    scan_id          TEXT NOT NULL REFERENCES scan_audit(scan_id),
    module           TEXT NOT NULL,
    parent_type      TEXT,
    parent_value     TEXT,                -- normalized parent identifier
    entity_type      TEXT NOT NULL,
    entity_value     TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    confidence       REAL NOT NULL,
    label            TEXT,
    raw              JSONB,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS findings_scan_idx ON findings (scan_id);
CREATE INDEX IF NOT EXISTS findings_entity_idx ON findings (entity_type, normalized_value);

-- Response cache (DB fallback for Redis). Key is "<module>|<type>:<normalized>".
CREATE TABLE IF NOT EXISTS enrichment_cache (
    cache_key   TEXT PRIMARY KEY,
    payload     JSONB NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS enrichment_cache_expires_idx ON enrichment_cache (expires_at);

-- Optional: link findings into your existing person records. Adapt to your schema;
-- merge_findings_into_person() produces the profile JSON this column stores.
-- ALTER TABLE persons ADD COLUMN enrichment_profile JSONB;
