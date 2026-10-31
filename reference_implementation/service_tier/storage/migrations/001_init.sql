-- CVE tarayıcı şeması.
--
-- scan_results: ürün+sürüm başına son tarama sonucu (önbellek). Aynı uygulama
-- aynı sürümle tekrar sorulduğunda model çalıştırılmadan buradan dönülür.
-- Model yeniden eğitildiğinde model_version değiştiği için eski satırlar
-- otomatik olarak devre dışı kalır.

CREATE TABLE IF NOT EXISTS scan_results (
    id              BIGSERIAL PRIMARY KEY,
    product_key     TEXT        NOT NULL,
    version         TEXT        NOT NULL,
    platform        TEXT        NOT NULL DEFAULT '',
    model_version   TEXT        NOT NULL DEFAULT '',
    product         TEXT        NOT NULL,
    status          TEXT        NOT NULL,
    safety_score    INTEGER     NOT NULL DEFAULT 0,
    threat_count    INTEGER     NOT NULL DEFAULT 0,
    scanned_cves    INTEGER     NOT NULL DEFAULT 0,
    result          JSONB       NOT NULL,
    hit_count       INTEGER     NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT scan_results_key UNIQUE (product_key, version, platform, model_version)
);

CREATE INDEX IF NOT EXISTS scan_results_updated_idx ON scan_results (updated_at DESC);
CREATE INDEX IF NOT EXISTS scan_results_status_idx  ON scan_results (status);

-- jobs / job_items: asenkron toplu tarama kuyruğu.

CREATE TABLE IF NOT EXISTS jobs (
    id           UUID        PRIMARY KEY,
    status       TEXT        NOT NULL DEFAULT 'PENDING',
    total        INTEGER     NOT NULL DEFAULT 0,
    completed    INTEGER     NOT NULL DEFAULT 0,
    failed       INTEGER     NOT NULL DEFAULT 0,
    error        TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at   TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ,
    CONSTRAINT jobs_status_check
        CHECK (status IN ('PENDING', 'RUNNING', 'DONE', 'FAILED'))
);

CREATE INDEX IF NOT EXISTS jobs_status_idx  ON jobs (status);
CREATE INDEX IF NOT EXISTS jobs_created_idx ON jobs (created_at DESC);

CREATE TABLE IF NOT EXISTS job_items (
    job_id    UUID    NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    position  INTEGER NOT NULL,
    product   TEXT    NOT NULL,
    version   TEXT    NOT NULL,
    platform  TEXT    NOT NULL DEFAULT '',
    status    TEXT,
    cached    BOOLEAN NOT NULL DEFAULT FALSE,
    result    JSONB,
    error     TEXT,
    PRIMARY KEY (job_id, position)
);
