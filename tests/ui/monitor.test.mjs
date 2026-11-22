// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

/* ======================== 运行实际页面脚本，宿主响应由测试控制 ======================== */

const pageRoot = new URL('../../plugins/builtin/monitor/ui/', import.meta.url);
const [script, markup] = await Promise.all([
  readFile(new URL('monitor.js', pageRoot), 'utf8'),
  readFile(new URL('index.html', pageRoot), 'utf8'),
]);
const flush = () => new Promise((resolve) => setImmediate(resolve));

class Element {
  constructor(id, tag = 'div') {
    this.id = id;
    this.tag = tag;
    this.dataset = {};
    this.attributes = new Map();
    this.handlers = new Map();
    this.textContent = '';
    this.lines = [];
    this.style = { setProperty: (name, value) => this.attributes.set(name, value) };
  }
  setAttribute(name, value) { this.attributes.set(name, value); }
  removeAttribute(name) { this.attributes.delete(name); }
  addEventListener(name, handler) { this.handlers.set(name, handler); }
  click() { this.handlers.get('click')?.(); }
  getBoundingClientRect() { return { height: 600 }; }
  querySelectorAll(selector) {
    return this.lines.filter((line) => line.tag === (selector === 'path.line' ? 'path' : selector));
  }
}

function monitorPage(t) {
  const elements = new Map([...markup.matchAll(/\bid="([^"]+)"/g)].map((match) => [match[1], new Element(match[1])]));
  for (const match of markup.matchAll(/<svg[^>]*\bid="([^"]+)"[^>]*>([\s\S]*?)<\/svg>/g)) {
    elements.get(match[1]).lines = [...match[2].matchAll(/<(path|polyline)\b[^>]*\bclass="line [^"]*"/g)]
      .map((line) => new Element('', line[1]));
  }
  const buttons = [...markup.matchAll(/<button[^>]*\bdata-range="([^"]+)"/g)].map((match) => {
    const button = new Element('');
    button.dataset.range = match[1];
    return button;
  });
  assert.equal(buttons.length, 2, '实际页面必须保留两个范围按钮');
  const timers = new Map(), handlers = new Map(), sent = [], replied = new Set();
  let timerID = 0, disconnected = false;
  const root = new Element('root');
  const port = { closed: false, postMessage: (message) => sent.push(message), close() { this.closed = true; } };
  const parent = { postMessage() {} };
  const context = vm.createContext({
    URLSearchParams, location: { hash: '' },
    document: { documentElement: root, getElementById: (id) => elements.get(id), querySelectorAll: () => buttons },
    window: { parent, addEventListener: (name, handler) => handlers.set(name, handler) },
    ResizeObserver: class { observe() {} disconnect() { disconnected = true; } },
    setTimeout: (callback, delay) => { timers.set(++timerID, { callback, delay }); return timerID; },
    clearTimeout: (id) => timers.delete(id),
  });
  vm.runInContext(script, context, { filename: 'monitor.js', timeout: 1000 });
  const dispatch = (name, event) => handlers.get(name)?.(event);
  const close = async () => { dispatch('pagehide'); await flush(); };
  t.after(close);
  return {
    elements, timers, port,
    disconnected: () => disconnected,
    requests: () => sent.filter((message) => message.t === 'api.invoke'),
    range: (name) => buttons.find((button) => button.dataset.range === name).click(),
    line: (id, index = 0) => elements.get(id).lines[index].attributes.get('d'),
    async start() {
      dispatch('message', { source: parent, data: { t: 'plugin.port' }, ports: [port] });
      await flush();
    },
    async reply(request, data, ok = true) {
      assert.ok(request && !replied.has(request.id), '每个宿主请求只响应一次');
      replied.add(request.id);
      port.onmessage({ data: { t: 'api.result', id: request.id, ok, data } });
      await flush();
    },
    async visibility(visible) { port.onmessage({ data: { t: 'ui.settings', visible } }); await flush(); },
    async fire(delay) {
      for (const [id, entry] of [...timers]) {
        if (entry.delay === delay) { timers.delete(id); entry.callback(); }
      }
      await flush();
    },
    close,
  };
}

function point(t, amount = 25) {
  return { t, cpu_pct: amount, mem_pct: amount, disk_pct: 80,
    net_rx_bps: amount * 1e6, net_tx_bps: amount * 1e6 };
}
function snapshot(points) { return { current: points.at(-1) ?? {}, points, status: 'ready' }; }

/* ======================== 空值分段，不能跨失效区间拼接曲线 ======================== */

test('监控曲线在每条指标的空值处断开，下一有效点重新起笔', async (t) => {
  const page = monitorPage(t);
  await page.start();
  const missing = { ...point(2000), cpu_pct: null, net_rx_bps: null };
  await page.reply(page.requests()[0], snapshot([point(1000), missing, point(3000), point(4000)]));
  assert.equal(typeof page.line('net-chart'), 'string', '趋势必须使用可分段的 SVG path');
  assert.deepEqual(page.line('net-chart').match(/[ML]/g), ['M', 'M', 'L']);
  assert.deepEqual(page.line('net-chart', 1).match(/[ML]/g), ['M', 'L', 'L', 'L']);
  assert.deepEqual(page.line('resource-chart').match(/[ML]/g), ['M', 'M', 'L']);
});

test('整条指标不可用时清空曲线并保留空值显示', async (t) => {
  const page = monitorPage(t);
  await page.start();
  const missing = { ...point(1000), cpu_pct: null, mem_pct: null, net_rx_bps: null, net_tx_bps: null };
  await page.reply(page.requests()[0], snapshot([missing]));
  assert.equal(page.line('resource-chart'), '');
  assert.equal(page.line('net-chart'), '');
  assert.equal(page.elements.get('cpu-value').textContent, '—');
  assert.equal(page.elements.get('cpu-meter').attributes.has('aria-valuenow'), false);
});

/* ======================== 慢响应和连续切换只补一次最新范围 ======================== */

test('快照正在返回时切换范围，立即补读最新范围', async (t) => {
  const page = monitorPage(t);
  await page.start();
  page.range('1h');
  await page.reply(page.requests()[0], snapshot([point(1000, 10)]));
  assert.equal(page.requests().length, 2, '忙碌时的范围切换必须排队');
  assert.equal(page.requests()[1].operation, 'monitor.snapshot');
  await page.reply(page.requests()[1], snapshot([point(2000, 90)]));
  assert.equal(page.requests()[2].operation, 'monitor.history');
  assert.equal(page.requests()[2].payload.range, '1h');
  await page.reply(page.requests()[2], { points: [point(2000, 90)] });
  assert.equal(page.elements.get('cpu-value').textContent, '90.0%');
  assert.equal(page.requests().length, 3, '完成最新范围后不能继续堆积请求');
});

test('一小时历史返回前切回五分钟，旧历史不能覆盖当前范围', async (t) => {
  const page = monitorPage(t);
  await page.start();
  await page.reply(page.requests()[0], snapshot([point(1000, 25)]));
  const original = page.line('resource-chart');
  page.range('1h');
  await page.reply(page.requests()[1], snapshot([point(2000, 50)]));
  assert.equal(page.requests()[2].operation, 'monitor.history');
  page.range('5m');
  await page.reply(page.requests()[2], { points: [point(3000, 99)] });
  assert.equal(page.line('resource-chart'), original, '已过期的范围响应不能重绘');
  assert.equal(page.requests()[3].operation, 'monitor.snapshot');
  await page.reply(page.requests()[3], snapshot([point(4000, 60)]));
  assert.equal(page.elements.get('cpu-value').textContent, '60.0%');
  assert.equal(page.requests().length, 4);
});

test('连续十次切换合并成一次补读，使用最后选择的范围', async (t) => {
  const page = monitorPage(t);
  await page.start();
  for (let index = 0; index < 10; index++) page.range(index % 2 ? '5m' : '1h');
  assert.equal(page.requests().length, 1, '忙碌时不能发出并行堆积请求');
  await page.reply(page.requests()[0], snapshot([point(1000)]));
  assert.equal(page.requests().length, 2, '连续点击必须留下一个补读');
  await page.reply(page.requests()[1], snapshot([point(2000)]));
  assert.equal(page.requests().length, 2, '最新五分钟范围不需要额外历史请求');
});

test('暂停后到达的响应不覆盖暂停状态，继续时读取最新范围', async (t) => {
  const page = monitorPage(t);
  await page.start();
  page.elements.get('pause').click();
  page.range('1h');
  await page.reply(page.requests()[0], snapshot([point(1000)]));
  assert.equal(page.elements.get('status').textContent, '已暂停');
  assert.equal(page.requests().length, 1);
  page.elements.get('pause').click();
  assert.equal(page.requests()[1].operation, 'monitor.snapshot');
  await page.reply(page.requests()[1], snapshot([point(2000)]));
  assert.equal(page.requests()[2].payload.range, '1h');
});

test('隐藏页面停止补读，恢复可见后按有限轮询继续', async (t) => {
  const page = monitorPage(t);
  await page.start();
  await page.visibility(false);
  page.range('1h');
  await page.reply(page.requests()[0], snapshot([point(1000)]));
  assert.equal(page.requests().length, 1);
  assert.equal(page.timers.size, 0);
  await page.visibility(true);
  await page.fire(1500);
  assert.equal(page.requests()[1].operation, 'monitor.snapshot');
});

test('主磁盘名称使用宿主快照，不在页面重新选择挂载点', async (t) => {
  const page = monitorPage(t);
  await page.start();
  await page.reply(page.requests()[0], { ...snapshot([point(1000)]), primary_disk_mount: '/data/archive' });
  assert.equal(page.elements.get('disk-title').textContent, '磁盘');
  assert.equal(page.elements.get('disk-note').textContent, '/data/archive 挂载点使用率');
  await page.fire(1500);
  await page.reply(page.requests()[1], { ...snapshot([point(2000)]), primary_disk_mount: '/' });
  assert.equal(page.elements.get('disk-title').textContent, '根盘');
  assert.equal(page.elements.get('disk-note').textContent, '/ 挂载点使用率');
});

test('超时后的最新范围补读保持有界，迟到响应不会重绘', async (t) => {
  const page = monitorPage(t);
  await page.start();
  page.range('1h');
  await page.fire(5000);
  assert.equal(page.requests().length, 2, '超时必须释放旧请求并消费一个补读');
  await page.reply(page.requests()[0], snapshot([point(1000, 99)]));
  assert.equal(page.line('resource-chart'), undefined, '已超时的旧响应不能重绘');
  await page.reply(page.requests()[1], snapshot([point(2000, 50)]));
  assert.equal(page.requests()[2].payload.range, '1h');
  await page.reply(page.requests()[2], { points: [point(2000, 50)] });
  assert.equal(page.elements.get('cpu-value').textContent, '50.0%');
  assert.equal(page.requests().length, 3);
});

test('关闭页面回收响应超时、轮询和桥接端口', async (t) => {
  const page = monitorPage(t);
  await page.start();
  assert.equal(page.requests().length, 1);
  await page.close();
  assert.equal(page.timers.size, 0);
  assert.equal(page.port.closed, true);
  assert.equal(page.disconnected(), true);
});
