// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * E2E 冒烟（ENG §11 的最小骨架；完整用例由各页面补充到 e2e/specs/）
 * --------------------------------------------------------------------------
 * 前置：npm run build。流程：
 *   vite preview（带模拟后端 + 生产 CSP）→ 系统 Chrome（项目内 profile）→
 *   API 登录 → 逐个打开路由 → 断言无 CSP 违规、无未捕获错误、标题正确
 * 环境：CHROME_PATH 覆盖浏览器路径；截图写到 .cache/shots/e2e-*.png
 * ========================================================================== */
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

const root = fileURLToPath(new URL('..', import.meta.url));
const CHROME = process.env.CHROME_PATH ?? 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const PASSWORD = 'E2e-Mock-Password-2026';
const BASE = 'http://127.0.0.1:4173';
const ROUTES = [
  ['/', '主页'],
  ['/activity', '动态'],
  ['/agent', 'AI 助手'],
  ['/apps', '应用中心'],
  ['/apps/install', '安装应用'],
  ['/apps/com.qwq.monitor', '系统监控'],
  ['/plugins/com.qwq.monitor', '系统监控'],
  ['/settings/account', '设置'],
  ['/settings/appearance', '设置'],
  ['/settings/users', '设置'],
  ['/settings/delegations', '设置'],
  ['/settings/ai', '设置'],
  ['/settings/system', '设置'],
  ['/nope', '找不到页面'],
];

if (!existsSync(`${root}/dist/index.html`)) {
  console.error('e2e：请先 npm run build');
  process.exit(1);
}
mkdirSync(`${root}/.cache/shots`, { recursive: true });

const preview = spawn(process.execPath, [`${root}/node_modules/vite/bin/vite.js`, 'preview'], {
  cwd: root,
  env: { ...process.env, QWQ_MOCK_PASSWORD: PASSWORD, VITE_CONFIG_NATIVE_IGNORE_WARNING: 'true' },
  stdio: ['ignore', 'pipe', 'inherit'],
});
await new Promise((resolve, reject) => {
  preview.stdout.on('data', (d) => String(d).includes('4173') && resolve());
  preview.on('exit', (code) => reject(new Error(`vite preview 退出：${code}`)));
});

const failures = [];
const ctx = await chromium.launchPersistentContext(`${root}/.cache/chrome-profile`, {
  executablePath: CHROME,
  headless: true,
  viewport: { width: 1440, height: 900 },
});
try {
  const page = ctx.pages()[0] ?? (await ctx.newPage());
  page.on('pageerror', (e) => failures.push(`未捕获错误：${e.message}`));
  /* 本机杀毒软件等可能向页面注入脚本并被 CSP 拦下：用 E2E_IGNORE_CSP_HOSTS=host1,host2 排除，其余一律算失败 */
  const ignored = (process.env.E2E_IGNORE_CSP_HOSTS ?? '').split(',').filter(Boolean);
  page.on('console', (m) => {
    const t = m.text();
    if (m.type() === 'error' && /Content Security Policy|Refused to/.test(t) && !ignored.some((h) => t.includes(h))) failures.push(`CSP：${t}`);
  });
  await page.addInitScript(() => {
    document.addEventListener('securitypolicyviolation', (e) => console.error(`Refused to: ${e.violatedDirective} ${e.blockedURI}`));
  });

  await page.goto(`${BASE}/login`);
  const login = await page.evaluate(async (password) => {
    const r = await fetch('/api/v1/sessions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'alice', password }) });
    return r.status;
  }, PASSWORD);
  if (login !== 200) failures.push(`登录失败：HTTP ${login}`);

  for (const [path, title] of ROUTES) {
    await page.goto(BASE + path);
    /* 标题以路由名开头即可：插件页与设置分项会追加「· 子页」 */
    await page.waitForFunction((t) => document.querySelector('#page-title')?.textContent?.startsWith(t), title, { timeout: 5000 }).catch(() => failures.push(`${path}：标题不是「${title}」`));
    await page.screenshot({ path: `${root}/.cache/shots/e2e${path.replace(/\//g, '_') || '_home'}.png` });
  }

  /* ---------------------------------------------------------------- AI 悬浮窗状态机（SPEC §4） */
  const expect = async (what, fn, arg) =>
    page.waitForFunction(fn, arg, { timeout: 8000 }).catch(() => failures.push(`悬浮窗：${what}`));
  const scenario = (name) =>
    page.evaluate((n) => fetch('/__mock/scenario', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: n }) }), name);

  await scenario('healthy');
  await page.goto(BASE + '/');
  await expect('待审批时球向左伸出胶囊', () => !!document.querySelector('.dock .reach'));
  await page.click('.dock .ball');
  await expect('点球展开 dialog 并列出审批卡', () => document.querySelector('dialog.sheet')?.open && !!document.querySelector('dialog.sheet .approval-tray [data-approval-id], dialog.sheet .approval-tray article, dialog.sheet .chat-body [data-approval-id]'));
  await expect('展开时有输入窗', () => !!document.querySelector('dialog.sheet .input textarea'));
  await page.keyboard.press('Escape');
  await expect('Esc 收回', () => !document.querySelector('dialog.sheet')?.open);
  await page.click('.dock .ball');
  await page.mouse.click(8, 8);
  await expect('点外部收回', () => !document.querySelector('dialog.sheet')?.open);

  await page.goto(BASE + '/agent');
  await page.click('.dock .ball');
  await expect('Agent 页展开只有待确认、没有输入窗', () => document.querySelector('dialog.sheet')?.open && !document.querySelector('dialog.sheet .input'));
  await page.keyboard.press('Escape');

  await scenario('agent-running');
  await page.goto(BASE + '/');
  await expect('Agent 运行中 → 球 working', () => !!document.querySelector('.dock .ball.working'));

  await scenario('offline');
  await expect('离线 → 球置灰并提示重连', () => !!document.querySelector('.dock.offline .tip'));
  await page
    .waitForFunction(() => document.querySelector('.server small')?.textContent === '连接中断', null, { timeout: 8000 })
    .catch(() => failures.push('侧栏：断线时仍显示节点在线'));

  /* ---------------------------------------------------------------- 冷启动遇 503：3 秒内给出离线态 */
  const t0 = Date.now();
  await page.goto(BASE + '/');
  await page
    .waitForFunction(() => document.body.textContent?.includes('连不上服务器'), null, { timeout: 3500 })
    .then(() => Date.now() - t0 > 3500 && failures.push(`冷启动：${Date.now() - t0}ms 才显示离线态`))
    .catch(() => failures.push('冷启动：3.5 秒内未显示「连不上服务器」'));
  await scenario('healthy');
} finally {
  await ctx.close();
  preview.kill();
}

if (failures.length) {
  console.error('e2e 失败：\n  ' + failures.join('\n  '));
  process.exit(1);
}
console.log(`e2e：${ROUTES.length} 个路由 + 悬浮窗状态机 + 断线 / 冷启动离线态通过（无 CSP 违规、无未捕获错误）`);
