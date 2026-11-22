-- SPDX-License-Identifier: AGPL-3.0-only
-- ======================== 兼容 schema 与秘密引用生命周期 ========================
-- 双槽认证的生产接线仍由运行时轨道实现；当前认证继续使用原槽。
ALTER TABLE plugin_credentials ADD COLUMN prev_token_sha256 TEXT NOT NULL DEFAULT ''
  CHECK (prev_token_sha256 = '' OR length(prev_token_sha256) = 64);

-- parent_key 来自宿主资源主键；插件没有写入此表的入口。
CREATE TABLE secret_references (
  parent_kind TEXT NOT NULL CHECK (parent_kind IN ('credential', 'plan', 'operation', 'config')),
  parent_key  TEXT NOT NULL,
  secret_id   TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  PRIMARY KEY (parent_kind, parent_key, secret_id)
) STRICT;
CREATE INDEX secret_references_secret ON secret_references(secret_id);

-- ======================== 回填现存合法引用 ========================
INSERT OR IGNORE INTO secret_references
SELECT 'credential', c.credential_id, s.id FROM credentials c JOIN secrets s ON s.id=c.secret
WHERE c.type IN ('totp', 'totp_pending') AND s.purpose='identity.totp'
  AND s.owner IN ('system', 'users/' || c.user_id);

INSERT OR IGNORE INTO secret_references
SELECT 'operation', o.operation_id, s.id FROM operations o, json_tree(o.args) j
JOIN secrets s ON s.id=j.atom
WHERE j.key='$secret' AND j.type='text' AND s.owner='plugins/' || o.plugin_id
  AND s.purpose IN ('plugin.operation', 'plugin.config');

INSERT OR IGNORE INTO secret_references
SELECT 'plan', p.plan_id, s.id FROM plans p, json_tree(p.args) j
JOIN secrets s ON s.id=j.atom
WHERE j.key='$secret' AND j.type='text' AND s.owner='plugins/' || json_extract(p.target, '$.plugin_id')
  AND s.purpose IN ('plugin.operation', 'plugin.config');

INSERT OR IGNORE INTO secret_references
SELECT 'config', json_array(c.plugin_id, c.revision), s.id FROM plugin_configs c, json_tree(c.config_json) j
JOIN secrets s ON s.id=j.atom
WHERE j.key='$secret' AND j.type='text' AND s.owner='plugins/' || c.plugin_id
  AND s.purpose='plugin.config';

-- 只回收已知资源用途；其他宿主秘密（含指纹密钥、Provider、私有导出）不在此范围。
DELETE FROM secrets WHERE NOT EXISTS (
  SELECT 1 FROM secret_references r WHERE r.secret_id=secrets.id
) AND (
  (purpose='identity.totp' AND (owner='system' OR owner LIKE 'users/%')) OR
  (purpose IN ('plugin.operation', 'plugin.config') AND owner LIKE 'plugins/%')
);

-- ======================== 自动建立资源引用 ========================
CREATE TRIGGER secret_refs_credential_insert AFTER INSERT ON credentials
WHEN NEW.type IN ('totp', 'totp_pending')
BEGIN
  INSERT OR IGNORE INTO secret_references
  SELECT 'credential', NEW.credential_id, id FROM secrets
  WHERE id=NEW.secret AND purpose='identity.totp' AND owner IN ('system', 'users/' || NEW.user_id);
END;

-- 原地提升 totp_pending -> totp 保留同一引用；换值/退出 TOTP 类型才重建绑定。
CREATE TRIGGER secret_refs_credential_update AFTER UPDATE OF secret, type ON credentials
WHEN NEW.secret<>OLD.secret OR
  (NEW.type IN ('totp', 'totp_pending'))<>(OLD.type IN ('totp', 'totp_pending'))
BEGIN
  INSERT OR IGNORE INTO secret_references
  SELECT 'credential', NEW.credential_id, id FROM secrets
  WHERE NEW.type IN ('totp', 'totp_pending') AND id=NEW.secret
    AND purpose='identity.totp' AND owner IN ('system', 'users/' || NEW.user_id);
  DELETE FROM secret_references WHERE parent_kind='credential' AND parent_key=OLD.credential_id
    AND (secret_id<>NEW.secret OR NEW.type NOT IN ('totp', 'totp_pending'));
END;

CREATE TRIGGER secret_refs_operation_insert AFTER INSERT ON operations
BEGIN
  INSERT OR IGNORE INTO secret_references
  SELECT 'operation', NEW.operation_id, s.id FROM json_tree(NEW.args) j JOIN secrets s ON s.id=j.atom
  WHERE j.key='$secret' AND j.type='text' AND s.owner='plugins/' || NEW.plugin_id
    AND s.purpose IN ('plugin.operation', 'plugin.config');
END;

CREATE TRIGGER secret_refs_plan_insert AFTER INSERT ON plans
BEGIN
  INSERT OR IGNORE INTO secret_references
  SELECT 'plan', NEW.plan_id, s.id FROM json_tree(NEW.args) j JOIN secrets s ON s.id=j.atom
  WHERE j.key='$secret' AND j.type='text' AND s.owner='plugins/' || json_extract(NEW.target, '$.plugin_id')
    AND s.purpose IN ('plugin.operation', 'plugin.config');
END;

CREATE TRIGGER secret_refs_config_insert AFTER INSERT ON plugin_configs
BEGIN
  INSERT OR IGNORE INTO secret_references
  SELECT 'config', json_array(NEW.plugin_id, NEW.revision), s.id
  FROM json_tree(CASE WHEN json_valid(NEW.config_json) THEN NEW.config_json ELSE '{}' END) j
  JOIN secrets s ON s.id=j.atom
  WHERE j.key='$secret' AND j.type='text' AND s.owner='plugins/' || NEW.plugin_id
    AND s.purpose='plugin.config';
END;

-- ======================== 删除与最后引用回收（同一写事务） ========================
CREATE TRIGGER secret_refs_credential_delete AFTER DELETE ON credentials
BEGIN
  DELETE FROM secret_references WHERE parent_kind='credential' AND parent_key=OLD.credential_id;
END;
CREATE TRIGGER secret_refs_operation_delete AFTER DELETE ON operations
BEGIN
  DELETE FROM secret_references WHERE parent_kind='operation' AND parent_key=OLD.operation_id;
END;
CREATE TRIGGER secret_refs_plan_delete AFTER DELETE ON plans
BEGIN
  DELETE FROM secret_references WHERE parent_kind='plan' AND parent_key=OLD.plan_id;
END;
CREATE TRIGGER secret_refs_config_delete AFTER DELETE ON plugin_configs
BEGIN
  DELETE FROM secret_references WHERE parent_kind='config' AND parent_key=json_array(OLD.plugin_id, OLD.revision);
END;
CREATE TRIGGER secret_refs_delete_last AFTER DELETE ON secret_references
BEGIN
  DELETE FROM secrets WHERE id=OLD.secret_id
    AND NOT EXISTS (SELECT 1 FROM secret_references WHERE secret_id=OLD.secret_id);
END;
