-- SPDX-License-Identifier: AGPL-3.0-only
-- Plugin versions, configuration revisions and update sagas (ARCH §6.1, §6.3,
-- §6.5; P3 transactional hot update).
--
-- plugin_versions keeps one row per published version on this node. status is
-- the version lifecycle of ARCH §6.1 (STAGED … QUARANTINED) and install_status
-- is a separate axis for the installation transaction of ARCH §6.6, so a
-- version can be installed but rejected, or running while its files are being
-- removed. active is 1 for the one committed version of a plugin; the partial
-- unique index below makes a second active row impossible. revision is the
-- resource.changed sequence of the last write to the row.
--
-- plugin_configs is an append-only snapshot log: every applied or rejected
-- candidate is kept with active = 0 until the retention policy prunes it, and
-- exactly one row per plugin is active. revision is the host-visible config
-- revision N of ARCH §6.5; revision_seq is the resource.changed sequence
-- (they are different numbers on purpose). Sensitive values are secret
-- references, never plaintext (ARCH §5.4).
--
-- plugin_update_sagas drives §6.3: one row per install, update or rollback,
-- with the step that still has to run. Each step is a short transaction and
-- the process may die between any two of them, so the row is the recovery
-- journal. A partial unique index allows at most one RUNNING saga per plugin;
-- terminal states stay for audit until pruned by the host.

CREATE TABLE plugin_versions (
    plugin_id       TEXT    NOT NULL,
    version         TEXT    NOT NULL,
    digest          TEXT    NOT NULL,
    manifest_json   TEXT    NOT NULL,
    status          TEXT    NOT NULL,
    install_status  TEXT    NOT NULL,
    active          INTEGER NOT NULL DEFAULT 0 CHECK (active IN (0, 1)),
    installed_at    TEXT    NOT NULL,
    activated_at    TEXT    NOT NULL DEFAULT '',
    rejected_reason TEXT    NOT NULL DEFAULT '',
    revision        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (plugin_id, version),
    CHECK (status IN ('STAGED', 'STARTING', 'CANDIDATE', 'ACTIVE', 'DRAINING',
                      'STOPPED', 'REJECTED', 'ROLLED_BACK', 'QUARANTINED')),
    CHECK (install_status IN ('STAGED', 'INSTALLED', 'REMOVED'))
) STRICT;

-- At most one committed active version per plugin.
CREATE UNIQUE INDEX plugin_versions_active_idx
    ON plugin_versions (plugin_id) WHERE active = 1;

-- Recovery scans the transient lifecycle states.
CREATE INDEX plugin_versions_status_idx
    ON plugin_versions (plugin_id, status);

CREATE TABLE plugin_configs (
    plugin_id    TEXT    NOT NULL,
    revision     INTEGER NOT NULL CHECK (revision > 0),
    config_json  TEXT    NOT NULL,
    active       INTEGER NOT NULL DEFAULT 0 CHECK (active IN (0, 1)),
    created_at   TEXT    NOT NULL,
    applied_at   TEXT    NOT NULL DEFAULT '',
    revision_seq INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (plugin_id, revision)
) STRICT;

CREATE UNIQUE INDEX plugin_configs_active_idx
    ON plugin_configs (plugin_id) WHERE active = 1;

-- Retention keeps the newest N revisions and everything younger than the
-- window, so both orders are used by the pruner.
CREATE INDEX plugin_configs_created_idx
    ON plugin_configs (plugin_id, created_at);
CREATE INDEX plugin_configs_revision_idx
    ON plugin_configs (plugin_id, revision);

CREATE TABLE plugin_update_sagas (
    saga_id      TEXT NOT NULL PRIMARY KEY,
    plugin_id    TEXT NOT NULL,
    from_version TEXT NOT NULL DEFAULT '',
    to_version   TEXT NOT NULL,
    mode         TEXT NOT NULL CHECK (mode IN ('install', 'update', 'rollback')),
    strategy     TEXT NOT NULL CHECK (strategy IN ('overlap', 'restart', 'install')),
    state        TEXT NOT NULL CHECK (state IN ('RUNNING', 'COMMITTED', 'ROLLED_BACK', 'FAILED')),
    step         TEXT NOT NULL,
    error        TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
) STRICT;

-- One unfinished saga per plugin (ARCH §6.3: per-plugin update lock).
CREATE UNIQUE INDEX plugin_update_sagas_running_idx
    ON plugin_update_sagas (plugin_id) WHERE state = 'RUNNING';

CREATE INDEX plugin_update_sagas_state_idx
    ON plugin_update_sagas (state, created_at);
