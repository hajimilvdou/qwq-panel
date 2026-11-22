// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 模拟后端 · Vite 插件入口（只在 dev / preview 生效，不进生产产物）
 * --------------------------------------------------------------------------
 * vite.config.ts 在未设置 QWQ_BACKEND 时加载。shell/src 不得 import 本目录，
 * postbuild 会校验 dist 不含 "__mock"。
 * 登录：alice / bob / carol，密码取 QWQ_MOCK_PASSWORD（缺省启动时随机生成并打印）。
 * ========================================================================== */
import type { Plugin } from 'vite';
import { createMockServer } from './server.ts';
import { mockPassword } from './seed.ts';
import { MOCK_RECOVERY, MOCK_TOTP } from './handlers/auth.ts';
import { SCENARIOS } from './scenarios.ts';

export function mockBackend(): Plugin {
  const password = mockPassword();
  const mock = createMockServer(password);

  const banner = () => {
    const lines = [
      '',
      '  qwq 模拟后端已启用',
      `  登录      alice（管理员）/ bob（运维）/ carol（只读），密码 ${password}`,
      `  两步验证  ${MOCK_TOTP}（恢复码 ${MOCK_RECOVERY}）；初始化令牌 ${mock.db.setup.token}`,
      `  场景      ?mock=<名称> 或 POST /__mock/scenario：${Object.keys(SCENARIOS).join(' ')}`,
      '',
    ];
    console.info(lines.join('\n'));
  };

  return {
    name: 'qwq-mock-backend',
    apply: (_config, env) => env.command === 'serve' || env.isPreview === true,
    configureServer(server) {
      banner();
      server.middlewares.use(mock.handle);
    },
    configurePreviewServer(server) {
      banner();
      server.middlewares.use(mock.handle);
    },
  };
}
