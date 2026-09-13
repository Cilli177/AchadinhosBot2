CREATE SCHEMA IF NOT EXISTS achadinhos;

CREATE TABLE IF NOT EXISTS achadinhos.content_calendar_items (
    id text PRIMARY KEY,
    scheduled_at timestamptz NOT NULL,
    post_type text NOT NULL DEFAULT 'feed',
    source_input text NOT NULL DEFAULT '', offer_context text NOT NULL DEFAULT '',
    reference_url text NOT NULL DEFAULT '', reference_caption text NOT NULL DEFAULT '', reference_media_url text NOT NULL DEFAULT '',
    offer_url text NOT NULL DEFAULT '', keyword text NOT NULL DEFAULT '', generated_caption text NOT NULL DEFAULT '',
    hashtags text NOT NULL DEFAULT '', media_url text NOT NULL DEFAULT '', auto_publish boolean NOT NULL DEFAULT true,
    status text NOT NULL DEFAULT 'planned', draft_id text NULL, published_media_id text NULL, error text NULL,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0), last_attempt_at timestamptz NULL,
    processing_execution_id text NULL, processing_claimed_at timestamptz NULL,
    created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_content_calendar_due_planned
    ON achadinhos.content_calendar_items (scheduled_at, created_at) WHERE status = 'planned';
CREATE INDEX IF NOT EXISTS ix_content_calendar_processing
    ON achadinhos.content_calendar_items (processing_claimed_at) WHERE status = 'processing';

CREATE TABLE IF NOT EXISTS achadinhos.data_migrations (
    name text PRIMARY KEY, source_sha256 text NOT NULL, row_count integer NOT NULL, applied_at timestamptz NOT NULL DEFAULT now()
);
