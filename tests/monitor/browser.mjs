// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 真实监控浏览器验收：发布包内 Shell → 宿主桥 → HTTPS API → 已安装插件。
 * --------------------------------------------------------------------------
 * QWQ_MONITOR_ORIGIN 为 SSH 隧道的 HTTPS 回环地址；凭据只从环境读取。
 * 本脚本不提供模拟后端，必须与 TestMonitorEndToEnd 的就绪窗口协作。
 * ========================================================================== */
import fs from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../..', import.meta.url));
const require = createRequire(path.join(root, 'web/package.json'));
const { chromium } = require('playwright-core');
const origin = new URL(process.env.QWQ_MONITOR_ORIGIN ?? '');
const password = process.env.QWQ_E2E_PASSWORD;
const output = process.env.QWQ_MONITOR_REPORTS ?? path.join(root, '.cache/monitor-e2e/reports');
if (origin.protocol !== 'https:' || !['127.0.0.1', 'localhost'].includes(origin.hostname) || !password) {
  throw new Error('真实验收需要 HTTPS 回环隧道与环境凭据');
}
const base = origin.origin;
const errors = [];
const reads = [];
const startup = [];
const isRead = (response, name) => new URL(response.url()).pathname.endsWith(`/operations/${name}`);
let browser;
try {
  await fs.mkdir(output, { recursive: true });
  browser = await chromium.launch({
    executablePath: process.env.CHROME_PATH ?? 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    headless: true,
  });
  // 自签名安装夹具只经已认证 SSH 隧道连接，指纹由 Go 安装测试核对。
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 960 } });
  const page = await context.newPage();
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error' && /Content Security Policy|Refused to/.test(message.text()) && !message.text().includes('kaspersky-labs.com')) {
      errors.push(message.text());
    }
  });
  page.on('request', (request) => {
    const uri = new URL(request.url());
    if (uri.pathname.includes('/operations/monitor.')) reads.push(uri.pathname);
    if (uri.pathname.startsWith('/__mock')) errors.push('真实验收出现模拟后端请求');
  });

  // 首屏诊断只记录路径/状态及输入凭据前的页面，不采集请求头或 API 响应材料。
  page.on('response', (reply) => {
    const pathname = new URL(reply.url()).pathname;
    if (pathname === '/login' || pathname === '/boot.js' || pathname.startsWith('/assets/') ||
      pathname === '/api/v1/setup' || pathname === '/api/v1/sessions/current') {
      startup.push({ path: pathname, status: reply.status(), type: reply.headers()['content-type'] ?? '' });
    }
  });

  await page.goto(`${base}/login`);
  try {
    await page.getByLabel('用户名').waitFor({ timeout: 10000 });
  } catch {
    await fs.writeFile(path.join(output, 'monitor-real-startup.json'), JSON.stringify({
      source: 'installed-web-shell-before-login',
      path: new URL(page.url()).pathname,
      title: await page.title(),
      visible: (await page.locator('body').innerText()).slice(0, 4096),
      requests: startup,
      errors,
    }, null, 2) + '\n');
    await page.screenshot({ path: path.join(output, 'monitor-real-startup.png'), fullPage: true });
    throw new Error('真实登录页未就绪，首屏诊断已保存');
  }
  await page.getByLabel('用户名').fill('admin');
  await page.getByLabel('密码').fill(password);
  await page.getByRole('button', { name: '登录', exact: true }).click();
  await page.waitForURL(`${base}/`, { timeout: 15000 });

  const snapshotRead = page.waitForResponse((response) => isRead(response, 'monitor.snapshot'), { timeout: 15000 });
  await page.goto(`${base}/plugins/monitor.basic/monitor`);
  const response = await snapshotRead;
  if (response.status() !== 200) throw new Error('监控页面没有通过真实 API 读取快照');
  const snapshot = (await response.json()).result;
  if (snapshot?.status !== 'ready' || !snapshot.current || Date.now() - snapshot.current.t > 5000) {
    throw new Error('监控页面收到无效或过期的宿主采样');
  }
  const frame = page.frameLocator('iframe[title="基础监控"]');
  const expected = `${snapshot.current.cpu_pct.toFixed(1)}%`;
  await frame.locator('#cpu-value').filter({ hasText: expected }).waitFor({ timeout: 5000 });
  const sandbox = await page.locator('iframe[title="基础监控"]').getAttribute('sandbox');
  if (sandbox.includes('allow-same-origin')) throw new Error('插件 iframe 丢失了不透明源隔离');
  await page.screenshot({ path: path.join(output, 'monitor-real-desktop.png'), fullPage: true });

  await frame.locator('#pause').click();
  const pausedReads = reads.length;
  await page.waitForTimeout(2300);
  if (reads.length !== pausedReads || (await frame.locator('#pause').textContent()) !== '继续') {
    throw new Error('暂停后仍然轮询真实插件');
  }
  const resumed = page.waitForResponse((reply) => isRead(reply, 'monitor.snapshot'));
  await frame.locator('#pause').click();
  await resumed;
  const historyRead = page.waitForResponse((reply) => isRead(reply, 'monitor.history'));
  await frame.locator('[data-range="1h"]').click();
  const historyResponse = await historyRead;
  if (historyResponse.status() !== 200 || !Array.isArray((await historyResponse.json()).result?.points)) {
    throw new Error('历史切换未读取真实监控历史');
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: path.join(output, 'monitor-real-mobile.png'), fullPage: true });
  if (await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)) {
    throw new Error('监控页面出现移动端横向溢出');
  }

  await page.setViewportSize({ width: 1280, height: 960 });
  const widgetNames = ['monitor.stat.cpu', 'monitor.stat.mem', 'monitor.stat.disk', 'monitor.series.net', 'monitor.series.load'];
  const widgetReads = widgetNames.map((name) => page.waitForResponse((reply) => isRead(reply, name), { timeout: 15000 }));
  await page.goto(`${base}/`);
  const widgetResponses = await Promise.all(widgetReads);
  for (const reply of widgetResponses) {
    if (reply.status() !== 200 || (await reply.json()).status !== 'SUCCEEDED') {
      throw new Error('概览小组件没有从真实插件取得有效结果');
    }
  }
  await page.screenshot({ path: path.join(output, 'monitor-real-widgets.png'), fullPage: true });
  if (errors.length) throw new Error(`页面脚本或 CSP 失败：${errors.join('; ')}`);
  await fs.writeFile(path.join(output, 'monitor-real-browser.json'), JSON.stringify({
    source: 'installed-monitor-host-metrics',
    collected_at: new Date().toISOString(),
    snapshot_sample_at: new Date(snapshot.current.t).toISOString(),
    read_requests: reads.length,
    widgets: widgetNames,
    checks: ['real-login', 'opaque-iframe', 'snapshot', 'pause-resume', 'history', 'mobile', 'five-widgets', 'csp'],
  }, null, 2) + '\n');
  process.stdout.write('真实监控浏览器验收通过：登录、快照、历史、暂停/继续、移动布局与五个小组件。\n');
} finally {
  await browser?.close();
}
