-- SPDX-License-Identifier: AGPL-3.0-only
-- 服务权限元数据；NULL 明确表示旧版角色账号。
ALTER TABLE service_accounts ADD COLUMN scope_json TEXT
    CHECK (scope_json IS NULL OR json_valid(scope_json));
