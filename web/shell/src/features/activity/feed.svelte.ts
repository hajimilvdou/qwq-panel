// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 动态时间线的数据：cursor 翻页 + since_revision 增量（SPEC §3.2）
 * --------------------------------------------------------------------------
 *   const feed = new OpsFeed(load);        load = (q) => operations.list({...filters, ...q})
 *   feed.reload()     全量重取（筛选变化、resync）
 *   feed.more()       下一页（cursor）
 *   feed.sync()       增量（operation.updated / resource.changed 合并后调用）
 *
 * 过期响应一律丢弃：每次 reload 自增 generation，旧请求回来时不落地。
 * 增量合并后按 created_at 倒序，deleted_ids（OPS-05 保留期清理）直接移除。
 * ========================================================================== */
import type { Op } from '$api/endpoints';
import type { Page } from '$api/types';
import { mergeDelta } from '$lib/resource.svelte';

export type FeedQuery = { cursor?: string; since_revision?: string; limit?: number };
export type FeedLoader = (q: FeedQuery) => Promise<Page<Op>>;

const PAGE = 30;
const byNewest = (a: Op, b: Op) => b.created_at.localeCompare(a.created_at);

export class OpsFeed {
  items = $state<Op[]>([]);
  status = $state<'loading' | 'ready' | 'error'>('loading');
  error = $state<unknown>(null);
  next = $state<string | undefined>(undefined);
  loadingMore = $state(false);
  moreError = $state<unknown>(null);

  #revision: string | undefined;
  #gen = 0;
  #syncing: Promise<void> | null = null;

  constructor(private readonly load: FeedLoader) {}

  reload = async (): Promise<void> => {
    const gen = ++this.#gen;
    if (!this.items.length) this.status = 'loading';
    try {
      const page = await this.load({ limit: PAGE });
      if (gen !== this.#gen) return;
      this.items = page.items.slice().sort(byNewest);
      this.next = page.next_cursor;
      this.#revision = page.revision;
      this.status = 'ready';
      this.error = null;
    } catch (err) {
      if (gen !== this.#gen) return;
      this.error = err;
      /* 已有数据时保留，错误只用于提示 */
      this.status = this.items.length ? 'ready' : 'error';
    }
  };

  more = async (): Promise<void> => {
    if (!this.next || this.loadingMore) return;
    const gen = this.#gen;
    this.loadingMore = true;
    this.moreError = null;
    try {
      const page = await this.load({ cursor: this.next, limit: PAGE });
      if (gen !== this.#gen) return;
      const seen = new Set(this.items.map((o) => o.operation_id));
      this.items = [...this.items, ...page.items.filter((o) => !seen.has(o.operation_id))];
      this.next = page.next_cursor;
    } catch (err) {
      if (gen === this.#gen) this.moreError = err;
    } finally {
      if (gen === this.#gen) this.loadingMore = false;
    }
  };

  /** 增量同步；并发调用合并为一次 */
  sync = (): Promise<void> => {
    if (!this.#revision) return this.reload();
    this.#syncing ??= this.#doSync().finally(() => (this.#syncing = null));
    return this.#syncing;
  };

  async #doSync(): Promise<void> {
    const gen = this.#gen;
    try {
      const page = await this.load({ since_revision: this.#revision, limit: 100 });
      if (gen !== this.#gen) return;
      this.items = mergeDelta(this.items, page, (o) => o.operation_id).sort(byNewest);
      this.#revision = page.revision;
    } catch {
      /* 增量失败不打扰：下一次事件或 resync 会再来 */
    }
  }
}
