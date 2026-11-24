<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  CopyButton · 复制到剪贴板（request_id、指纹、令牌）
  <CopyButton text={requestId} label="复制请求编号" />
-->
<script lang="ts">
  import { copyTextWithFallback } from './clipboard';
  import IconButton from './IconButton.svelte';

  interface Props {
    text: string;
    label?: string;
  }
  let { text, label = '复制' }: Props = $props();

  let done = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;

  async function copy() {
    if (await copyTextWithFallback(text)) {
      done = true;
      clearTimeout(timer);
      timer = setTimeout(() => (done = false), 1600);
    }
  }
  $effect(() => () => clearTimeout(timer));
</script>

<IconButton icon={done ? 'check' : 'copy'} label={done ? '已复制' : label} size="sm" onclick={copy} />
