<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  ActionRunner · ⌘K 选中操作后的参数表单 → 预览 → 执行（SPEC §5 / §8）
  ───────────────────────────────────────────────────────────────
  1 取详情（request_schema）；有 ui_route 的已在上层直接跳页
  2 SchemaForm 填参数（类型 + 必填在前端校验，pattern 交给后端）
  3 POST /plans：plannable 时展示变化与警告；不可执行时列出原因
  4 执行：runIntent(plans.execute) —— 进审批则自动打开悬浮窗定位审批卡
  可达性动作显示与审批卡相同的警示。
-->
<script lang="ts">
  import { Button, Chip, Icon, SchemaForm, Skeleton, ErrorState, fieldsOf, initialValues, toPayload, validate } from '$ui';
  import type { FormValues } from '$ui';
  import { actions as actionsApi, plans } from '$api/endpoints';
  import type { ActionDetail } from '$api/additions';
  import type { Plan } from '$api/types';
  import { describeError } from '$lib/errors';
  import { createIntent, runIntent } from '$lib/ops';
  import { RISK_META } from '$lib/ai/decide';
  import { gradeOf } from './items';

  interface Props {
    actionId: string;
    onback: () => void;
    ondone: () => void;
  }
  let { actionId, onback, ondone }: Props = $props();

  let detail = $state<ActionDetail | null>(null);
  let loadError = $state<unknown>(null);
  let values = $state<FormValues>({});
  let errors = $state<Record<string, string>>({});
  let plan = $state<Plan | null>(null);
  let busy = $state(false);
  let errorText = $state<string>();
  let intent = createIntent();

  const fields = $derived(detail ? fieldsOf(detail.request_schema ?? {}) : []);
  const grade = $derived(detail ? gradeOf(detail) : null);
  const risk = $derived(detail ? (RISK_META[detail.risk] ?? RISK_META.medium) : null);
  const dangerous = $derived(!!detail && (detail.effect === 'destructive' || detail.risk === 'high'));

  $effect(() => {
    const id = actionId;
    let live = true;
    actionsApi
      .describe(id)
      .then((d) => {
        if (!live) return;
        detail = d;
        values = initialValues(fieldsOf(d.request_schema ?? {}));
      })
      .catch((e) => live && (loadError = e));
    return () => (live = false);
  });

  /* 表单改动后旧预览作废 */
  function edited() {
    plan = null;
  }

  /** 后端 violations 指针可能带 /args 前缀 */
  const toFieldErrors = (list: { pointer: string; message: string }[]) =>
    Object.fromEntries(list.map((v) => [v.pointer.replace(/^\/args(?=\/)/, ''), v.message]));

  async function preview() {
    if (!detail) return;
    errors = validate(fields, values);
    if (Object.keys(errors).length) return;
    busy = true;
    errorText = undefined;
    try {
      const p = await plans.create({ action: detail.id, args: toPayload(fields, values) as Record<string, unknown> });
      errors = toFieldErrors(p.violations);
      /* 无可展示的变化：直接执行，省一步 */
      if (p.executable && !p.plannable && !p.warnings.length) await execute(p);
      else plan = p;
    } catch (err) {
      const v = describeError(err);
      errors = Object.fromEntries(Object.entries(v.fields).map(([k, m]) => [k.replace(/^\/args(?=\/)/, ''), m]));
      errorText = v.message;
    } finally {
      busy = false;
    }
  }

  async function execute(p: Plan) {
    if (!detail) return;
    busy = true;
    errorText = undefined;
    try {
      await runIntent(intent, (key) => plans.execute(p.plan_id, key), { label: detail.summary });
      intent = createIntent();
      ondone();
    } catch (err) {
      const v = describeError(err);
      errorText = v.message;
      /* 预览过期：回到表单重新预览 */
      if (v.code === 'PLAN_EXPIRED' || v.code === 'PRECONDITION_FAILED') plan = null;
    } finally {
      busy = false;
    }
  }

  const CHANGE_KIND = { create: '新增', update: '修改', delete: '删除' } as const;
</script>

<div class="runner">
  <button type="button" class="back" onclick={onback}><Icon name="chevron" size={14} />返回搜索</button>

  {#if loadError}
    <ErrorState compact message={describeError(loadError).message} />
  {:else if !detail}
    <Skeleton lines={3} height={36} />
  {:else}
    <header>
      <h3>{detail.summary}</h3>
      <div class="chips">
        {#if risk}<Chip size="sm" tone={risk.tone}>{risk.label}</Chip>{/if}
        {#if detail.source === 'plugin'}<Chip size="sm" dot={false}>来自插件</Chip>{/if}
        {#if grade}<span class="grade">{grade.label}</span>{/if}
      </div>
      <code class="id">{detail.id}</code>
    </header>

    {#if detail.reachability}
      <p class="reach" role="note">
        <Icon name="alert" size={18} />
        <span><strong>可能导致无法连接服务器。</strong>执行前请确认你还有其它方式登录。</span>
      </p>
    {/if}

    <form
      onsubmit={(e) => {
        e.preventDefault();
        if (plan?.executable) void execute(plan);
        else void preview();
      }}
      oninput={edited}
    >
      {#if fields.length}
        <SchemaForm {fields} bind:values {errors} disabled={busy} />
      {:else}
        <p class="none">这个操作不需要填写参数。</p>
      {/if}

      {#if plan}
        <section class="plan" aria-label="预览">
          {#if plan.changes.length}
            <p class="sub">将发生的变化</p>
            <ul>
              {#each plan.changes as c, i (i)}
                <li>
                  <span class="kind {c.kind}">{CHANGE_KIND[c.kind]}</span>
                  <span class="mono">{(c as { description?: string }).description ?? c.subject + (c.pointer ?? '')}</span>
                  {#if c.source === 'plugin'}<span class="src">来自插件</span>{/if}
                </li>
              {/each}
            </ul>
            {#if plan.changes_truncated}<p class="note">还有更多变化未列出</p>{/if}
          {/if}
          {#each plan.warnings as w, i (i)}
            <p class="warn"><Icon name="alert" size={16} />{w.message}</p>
          {/each}
          {#if !plan.executable}
            <p class="bad">现在不能执行：{plan.violations.map((v) => v.message).join('；') || '条件不满足'}</p>
          {:else if plan.requires_approval}
            <p class="note">提交后会出现在 AI 悬浮窗里等你确认{plan.requires_mfa ? '，需要两步验证码' : ''}。</p>
          {/if}
        </section>
      {/if}

      {#if errorText}<p class="bad" role="alert">{errorText}</p>{/if}

      <footer>
        {#if plan?.executable}
          <Button type="submit" variant={dangerous ? 'danger' : 'primary'} loading={busy}>执行</Button>
          <Button variant="ghost" onclick={() => (plan = null)} disabled={busy}>改参数</Button>
        {:else}
          <Button type="submit" variant="primary" loading={busy} disabled={!!plan && !plan.executable}>
            {detail.plannable ? '预览' : '执行'}
          </Button>
        {/if}
      </footer>
    </form>
  {/if}
</div>

<style>
  .runner {
    display: grid;
    gap: var(--s-4);
    padding: var(--s-4) var(--s-5) var(--s-5);
    max-height: min(70vh, 640px);
    overflow-y: auto;
  }
  .back {
    justify-self: start;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    min-height: 32px;
    padding: 0 var(--s-2) 0 0;
    border: 0;
    background: none;
    color: var(--text-2);
    font: inherit;
    font-size: var(--fs-sm);
    cursor: pointer;
  }
  .back :global(svg) {
    transform: rotate(180deg);
  }
  header {
    display: grid;
    gap: var(--s-2);
  }
  h3 {
    margin: 0;
    font-size: var(--fs-lg);
    font-weight: var(--fw-semibold);
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s-2);
  }
  .grade {
    font-size: var(--fs-sm);
    color: var(--text-2);
  }
  .id,
  .mono {
    font-family: var(--font-mono);
    font-size: var(--fs-xs);
    color: var(--text-3);
    overflow-wrap: anywhere;
  }
  .reach {
    display: flex;
    gap: var(--s-2);
    margin: 0;
    padding: var(--s-3);
    border-radius: var(--r-md);
    background: var(--warn-soft);
    color: var(--warn-text);
    font-size: var(--fs-sm);
  }
  .reach :global(svg) {
    flex: none;
  }
  form {
    display: grid;
    gap: var(--s-4);
  }
  .none,
  .note {
    margin: 0;
    font-size: var(--fs-sm);
    color: var(--text-3);
  }
  .plan {
    display: grid;
    gap: var(--s-2);
    padding: var(--s-3);
    border-radius: var(--r-md);
    background: var(--surface-2);
  }
  .sub {
    margin: 0;
    font-size: var(--fs-sm);
    font-weight: var(--fw-medium);
  }
  ul {
    display: grid;
    gap: 6px;
    margin: 0;
    padding: 0;
    list-style: none;
    font-size: var(--fs-sm);
  }
  li {
    display: flex;
    gap: var(--s-2);
    align-items: baseline;
  }
  .kind {
    flex: none;
    padding: 0 6px;
    border-radius: var(--r-xs);
    font-size: var(--fs-xs);
    background: var(--info-soft);
    color: var(--info-text);
  }
  .kind.create {
    background: var(--ok-soft);
    color: var(--ok-text);
  }
  .kind.delete {
    background: var(--bad-soft);
    color: var(--bad-text);
  }
  .src {
    font-size: var(--fs-xs);
    color: var(--text-3);
  }
  .warn {
    display: flex;
    gap: 6px;
    align-items: center;
    margin: 0;
    font-size: var(--fs-sm);
    color: var(--warn-text);
  }
  .bad {
    margin: 0;
    font-size: var(--fs-sm);
    color: var(--bad-text);
  }
  footer {
    display: flex;
    gap: var(--s-2);
  }
</style>
