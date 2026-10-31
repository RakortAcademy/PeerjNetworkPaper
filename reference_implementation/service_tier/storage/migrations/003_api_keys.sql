-- Müşterilere dağıtılan API anahtarları.
--
-- Anahtarın kendisi saklanmaz; yalnızca SHA-256 özeti tutulur. Panelde tanımak
-- için ilk birkaç karakter (prefix) ayrıca saklanır. Anahtar yalnızca
-- oluşturulduğu anda bir kez gösterilir.

CREATE TABLE IF NOT EXISTS api_keys (
    id            BIGSERIAL   PRIMARY KEY,
    name          TEXT        NOT NULL,
    key_hash      TEXT        NOT NULL UNIQUE,
    key_prefix    TEXT        NOT NULL,
    active        BOOLEAN     NOT NULL DEFAULT TRUE,
    note          TEXT        NOT NULL DEFAULT '',
    request_count BIGINT      NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS api_keys_active_idx ON api_keys (active) WHERE active;
CREATE INDEX IF NOT EXISTS api_keys_created_idx ON api_keys (created_at DESC);

-- Kullanım kaydı — panelde istek grafikleri ve anahtar başına kullanım için.
CREATE TABLE IF NOT EXISTS api_requests (
    id          BIGSERIAL   PRIMARY KEY,
    api_key_id  BIGINT      REFERENCES api_keys (id) ON DELETE SET NULL,
    path        TEXT        NOT NULL,
    method      TEXT        NOT NULL DEFAULT 'POST',
    status_code INTEGER     NOT NULL,
    item_count  INTEGER     NOT NULL DEFAULT 0,
    duration_ms INTEGER     NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS api_requests_created_idx ON api_requests (created_at DESC);
CREATE INDEX IF NOT EXISTS api_requests_key_idx     ON api_requests (api_key_id, created_at DESC);
