-- SPDX-License-Identifier: AGPL-3.0-only
-- 人类会话的一次性私密材料交付；业务 operation 只保存此资源 ID。
CREATE TABLE private_exports (
  export_id            TEXT PRIMARY KEY,
  owner_user_id        TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  session_id           TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
  action               TEXT NOT NULL,
  plugin_id            TEXT NOT NULL,
  instance_id          TEXT NOT NULL,
  node_id              TEXT NOT NULL,
  purpose              TEXT NOT NULL,
  subject              TEXT NOT NULL,
  status               TEXT NOT NULL CHECK(status IN ('PREPARED','RESERVED','MATERIALIZED','READY','CONSUMED','CANCELED')),
  operation_id         TEXT NOT NULL DEFAULT '',
  secret_ref           TEXT NOT NULL DEFAULT '',
  material_json        TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(material_json)),
  created_at           TEXT NOT NULL,
  updated_at           TEXT NOT NULL,
  expires_at           TEXT NOT NULL
) STRICT;

CREATE INDEX private_exports_session ON private_exports(session_id, expires_at);
CREATE INDEX private_exports_owner ON private_exports(owner_user_id, status, expires_at);
CREATE INDEX private_exports_expiry ON private_exports(expires_at);

-- Session/User 删除和有界过期清理同样回收加密材料，不留下跨 owner 孤儿。
CREATE TRIGGER private_exports_delete_secret AFTER DELETE ON private_exports
BEGIN
  DELETE FROM secrets WHERE id=OLD.secret_ref
    AND owner='private_exports/' || OLD.export_id AND purpose='private.export';
END;
