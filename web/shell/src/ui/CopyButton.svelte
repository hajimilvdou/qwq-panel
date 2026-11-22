<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  CopyButton · 复制到剪贴板（request_id、指纹、令牌）
  <CopyButton text={requestId} label="复制请求编号" />
-->
<script lang="ts">
  import IconButton from './IconButton.svelte';

  interface Props {
    text: string;
    label?: string;
  }
  let { text, label = '复制' }: Props = $props();

  let done = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      done = true;
      clearTimeout(timer);
      timer = setTimeout(() => (done = false), 1600);
    } catch {
      /* 非安全上下文或被拒绝：保持原样，用户可手动选中 */
    }
  }
  $effect(() => () => clearTimeout(timer));
</script>

<IconButton icon={done ? 'check' : 'copy'} label={done ? '已复制' : label} size="sm" onclick={copy} />
