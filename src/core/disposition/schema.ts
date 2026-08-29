/**
 * Reversible page-disposition storage plane.
 *
 * Shared by migration v142 on both engines. Fresh-install copies live in
 * src/schema.sql and src/core/pglite-schema.ts; keep the three definitions in
 * lockstep and regenerate schema-embedded.generated.ts after changing them.
 */
export const PAGE_DISPOSITION_SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS page_disposition_operations (
    id              BIGSERIAL PRIMARY KEY,
    operation_uuid  UUID NOT NULL UNIQUE,
    idempotency_key TEXT NOT NULL UNIQUE,
    request_hash    TEXT NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    kind            TEXT NOT NULL CHECK (kind IN ('set_page','set_duplicate_set','set_batch','reverse_page','reverse_duplicate_set','reverse_batch')),
    actor           TEXT NOT NULL CHECK (actor IN ('ezra','marco','valentina','kepler','vector')),
    reason          TEXT NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 1000),
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
  );

  CREATE TABLE IF NOT EXISTS page_disposition_events (
    id                BIGSERIAL PRIMARY KEY,
    event_uuid        UUID NOT NULL UNIQUE,
    operation_id      BIGINT NOT NULL REFERENCES page_disposition_operations(id) ON DELETE RESTRICT,
    page_id           INTEGER NOT NULL REFERENCES pages(id) ON DELETE RESTRICT,
    event_kind        TEXT NOT NULL CHECK (event_kind IN ('set','reverse')),
    resulting_state   TEXT NOT NULL CHECK (resulting_state IN ('canonical','superseded','quarantined','undispositioned')),
    duplicate_set_id  UUID,
    canonical_page_id INTEGER REFERENCES pages(id) ON DELETE RESTRICT,
    reverses_event_id BIGINT REFERENCES page_disposition_events(id) ON DELETE RESTRICT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT page_disposition_event_operation_page_key UNIQUE (operation_id, page_id),
    CONSTRAINT page_disposition_event_state_shape CHECK (
      (resulting_state = 'canonical' AND duplicate_set_id IS NOT NULL AND canonical_page_id = page_id)
      OR (resulting_state = 'superseded' AND duplicate_set_id IS NOT NULL AND canonical_page_id IS NOT NULL AND canonical_page_id <> page_id)
      OR (resulting_state = 'quarantined' AND canonical_page_id IS NULL)
      OR (resulting_state = 'undispositioned' AND duplicate_set_id IS NULL AND canonical_page_id IS NULL)
    ),
    CONSTRAINT page_disposition_event_reverse_shape CHECK (
      (event_kind = 'set' AND reverses_event_id IS NULL)
      OR (event_kind = 'reverse' AND reverses_event_id IS NOT NULL)
    )
  );

  CREATE TABLE IF NOT EXISTS page_dispositions (
    page_id           INTEGER PRIMARY KEY REFERENCES pages(id) ON DELETE RESTRICT,
    state             TEXT NOT NULL CHECK (state IN ('canonical','superseded','quarantined')),
    duplicate_set_id  UUID,
    canonical_page_id INTEGER REFERENCES pages(id) ON DELETE RESTRICT,
    last_event_id     BIGINT NOT NULL REFERENCES page_disposition_events(id) ON DELETE RESTRICT,
    reason            TEXT NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 1000),
    actor             TEXT NOT NULL CHECK (actor IN ('ezra','marco','valentina','kepler','vector')),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT page_disposition_projection_state_shape CHECK (
      (state = 'canonical' AND duplicate_set_id IS NOT NULL AND canonical_page_id = page_id)
      OR (state = 'superseded' AND duplicate_set_id IS NOT NULL AND canonical_page_id IS NOT NULL AND canonical_page_id <> page_id)
      OR (state = 'quarantined' AND canonical_page_id IS NULL)
    )
  );

  CREATE UNIQUE INDEX IF NOT EXISTS page_dispositions_one_canonical_per_set
    ON page_dispositions (duplicate_set_id)
    WHERE state = 'canonical';
  CREATE INDEX IF NOT EXISTS page_dispositions_state_updated
    ON page_dispositions (state, updated_at DESC, page_id DESC);
  CREATE INDEX IF NOT EXISTS page_disposition_events_page_history
    ON page_disposition_events (page_id, id DESC);

  CREATE TABLE IF NOT EXISTS page_disposition_state (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    generation BIGINT NOT NULL DEFAULT 0 CHECK (generation >= 0)
  );
  INSERT INTO page_disposition_state (id, generation)
    VALUES (1, 0)
    ON CONFLICT (id) DO NOTHING;

  CREATE OR REPLACE FUNCTION reject_page_disposition_ledger_mutation()
  RETURNS trigger SET search_path = pg_catalog, public AS $func$
  BEGIN
    RAISE EXCEPTION 'page disposition ledger is append-only';
  END;
  $func$ LANGUAGE plpgsql;

  DROP TRIGGER IF EXISTS page_disposition_operations_append_only ON page_disposition_operations;
  CREATE TRIGGER page_disposition_operations_append_only
    BEFORE UPDATE OR DELETE ON page_disposition_operations
    FOR EACH ROW EXECUTE FUNCTION reject_page_disposition_ledger_mutation();
  DROP TRIGGER IF EXISTS page_disposition_events_append_only ON page_disposition_events;
  CREATE TRIGGER page_disposition_events_append_only
    BEFORE UPDATE OR DELETE ON page_disposition_events
    FOR EACH ROW EXECUTE FUNCTION reject_page_disposition_ledger_mutation();

  CREATE OR REPLACE FUNCTION enforce_page_disposition_projection_event()
  RETURNS trigger SET search_path = pg_catalog, public AS $func$
  BEGIN
    IF TG_OP = 'DELETE' THEN
      IF NOT EXISTS (
        SELECT 1 FROM page_disposition_events e
        WHERE e.page_id = OLD.page_id
          AND e.id > OLD.last_event_id
          AND e.resulting_state = 'undispositioned'
      ) THEN
        RAISE EXCEPTION 'page disposition projection delete requires a later undispositioned event';
      END IF;
      RETURN OLD;
    END IF;

    IF NOT EXISTS (
      SELECT 1
      FROM page_disposition_events e
      JOIN page_disposition_operations o ON o.id = e.operation_id
      WHERE e.id = NEW.last_event_id
        AND e.page_id = NEW.page_id
        AND e.resulting_state = NEW.state
        AND e.duplicate_set_id IS NOT DISTINCT FROM NEW.duplicate_set_id
        AND e.canonical_page_id IS NOT DISTINCT FROM NEW.canonical_page_id
        AND o.actor = NEW.actor
        AND o.reason = NEW.reason
    ) THEN
      RAISE EXCEPTION 'page disposition projection must match its ledger event';
    END IF;
    RETURN NEW;
  END;
  $func$ LANGUAGE plpgsql;

  DROP TRIGGER IF EXISTS page_dispositions_event_guard ON page_dispositions;
  CREATE TRIGGER page_dispositions_event_guard
    BEFORE INSERT OR UPDATE OR DELETE ON page_dispositions
    FOR EACH ROW EXECUTE FUNCTION enforce_page_disposition_projection_event();

  CREATE OR REPLACE FUNCTION guard_active_canonical_page_delete()
  RETURNS trigger SET search_path = pg_catalog, public AS $func$
  BEGIN
    IF OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL AND EXISTS (
      SELECT 1 FROM page_dispositions d
      WHERE d.page_id = OLD.id AND d.state = 'canonical'
    ) THEN
      RAISE EXCEPTION 'active_canonical_delete_conflict';
    END IF;
    RETURN NEW;
  END;
  $func$ LANGUAGE plpgsql;

  DROP TRIGGER IF EXISTS pages_active_canonical_delete_guard ON pages;
  CREATE TRIGGER pages_active_canonical_delete_guard
    BEFORE UPDATE OF deleted_at ON pages
    FOR EACH ROW EXECUTE FUNCTION guard_active_canonical_page_delete();

  CREATE OR REPLACE FUNCTION guard_active_canonical_source_archive()
  RETURNS trigger SET search_path = pg_catalog, public AS $func$
  BEGIN
    IF OLD.archived IS NOT TRUE AND NEW.archived IS TRUE AND EXISTS (
      SELECT 1
      FROM page_dispositions d
      JOIN pages p ON p.id = d.page_id
      WHERE p.source_id = OLD.id AND d.state = 'canonical'
    ) THEN
      RAISE EXCEPTION 'active_canonical_archive_conflict';
    END IF;
    RETURN NEW;
  END;
  $func$ LANGUAGE plpgsql;

  DROP TRIGGER IF EXISTS sources_active_canonical_archive_guard ON sources;
  CREATE TRIGGER sources_active_canonical_archive_guard
    BEFORE UPDATE OF archived ON sources
    FOR EACH ROW EXECUTE FUNCTION guard_active_canonical_source_archive();
`;
