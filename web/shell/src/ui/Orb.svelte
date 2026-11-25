<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Orb · AI 表情头像球（悬浮窗、AI 消息、审批卡、新建页）
  ───────────────────────────────────────────────────────────────
  每个 AI 状态都有专属的表情与配色：
    idle / rest / still  常驻开心微笑 (^‿^)
    thinking / working   思考推演 (•̀ᴗ•́) + 旋转光环
    streaming            正在回复输出 (◕‿◕)
    tool                 工具执行中 (>ᴗ<) + 青色执行环
    approval             等待确认 (⊙_⊙)? 琥珀提醒
    error                API 或执行出错 (×_×) 红色告警
    offline              连接断开 (-_- )z 静默灰蓝
    paused               已暂停/取消 (・_・) 柔紫灰
    done                 完成开心 (★‿★) 翡翠绿
-->
<script lang="ts">
  export type OrbState =
    | 'rest'
    | 'still'
    | 'idle'
    | 'working'
    | 'thinking'
    | 'streaming'
    | 'tool'
    | 'approval'
    | 'error'
    | 'offline'
    | 'paused'
    | 'done';

  interface Props {
    size?: number;
    state?: OrbState;
    label?: string;
  }
  let { size = 24, state = 'still', label }: Props = $props();

  type FaceKind = 'idle' | 'thinking' | 'streaming' | 'tool' | 'approval' | 'error' | 'offline' | 'paused' | 'done';

  const face = $derived.by<FaceKind>(() => {
    switch (state) {
      case 'working':
      case 'thinking':
        return 'thinking';
      case 'streaming':
        return 'streaming';
      case 'tool':
        return 'tool';
      case 'approval':
        return 'approval';
      case 'error':
        return 'error';
      case 'offline':
        return 'offline';
      case 'paused':
        return 'paused';
      case 'done':
        return 'done';
      default:
        return 'idle';
    }
  });

  const animated = $derived(state !== 'still' && face !== 'offline' && face !== 'paused');
</script>

<span
  class="orb face-{face}"
  class:animated
  class:breathe={state === 'rest' || state === 'idle'}
  style:--size="{size}px"
  role={label ? 'img' : undefined}
  aria-label={label}
  aria-hidden={label ? undefined : 'true'}
>
  <svg viewBox="0 0 40 40" fill="none" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    {#if face === 'thinking'}
      <!-- 思考中：眯眼上望 + 波浪思考嘴 + 思绪小点 -->
      <path d="M11 16.5q3-2.5 5.5 0" stroke="currentColor" stroke-width="2.4" />
      <path d="M23.5 16.5q3-2.5 5.5 0" stroke="currentColor" stroke-width="2.4" />
      <circle cx="14.6" cy="18.6" r="1.7" fill="currentColor" />
      <circle cx="27.1" cy="18.6" r="1.7" fill="currentColor" />
      <path d="M16.5 26.8q1.7-1.6 3.5 0t3.5 0" stroke="currentColor" stroke-width="2.2" />
      <circle class="spark" cx="31.5" cy="9.5" r="2" fill="currentColor" opacity="0.9" />
      <circle class="spark d2" cx="27.5" cy="12" r="1.2" fill="currentColor" opacity="0.7" />
    {:else if face === 'streaming'}
      <!-- 流式回复：亮晶晶圆眼 + 开心说话张嘴 + 腮红 -->
      <circle cx="13.5" cy="17.5" r="2.7" fill="currentColor" />
      <circle cx="26.5" cy="17.5" r="2.7" fill="currentColor" />
      <circle cx="12.5" cy="16.4" r="0.9" fill="#ffffff" opacity="0.85" />
      <circle cx="25.5" cy="16.4" r="0.9" fill="#ffffff" opacity="0.85" />
      <path d="M15.8 24.5a4.4 4.2 0 0 0 8.4 0z" fill="currentColor" />
      <ellipse cx="9.2" cy="22.5" rx="2.3" ry="1.3" fill="#fff" opacity="0.32" />
      <ellipse cx="30.8" cy="22.5" rx="2.3" ry="1.3" fill="#fff" opacity="0.32" />
    {:else if face === 'tool'}
      <!-- 工具执行中：专注干活表情 (>‿<) -->
      <path d="M11.5 14.5 16 17.5 11.5 20.5" stroke="currentColor" stroke-width="2.5" />
      <path d="M28.5 14.5 24 17.5 28.5 20.5" stroke="currentColor" stroke-width="2.5" />
      <path d="M16 25.5q4 3.5 8 0" stroke="currentColor" stroke-width="2.4" />
    {:else if face === 'approval'}
      <!-- 等待确认：睁大眼睛询问 + 右上小问号圆点 -->
      <circle cx="14" cy="18.2" r="3.4" stroke="currentColor" stroke-width="2.2" />
      <circle cx="26" cy="18.2" r="3.4" stroke="currentColor" stroke-width="2.2" />
      <circle cx="14" cy="18.2" r="1.3" fill="currentColor" />
      <circle cx="26" cy="18.2" r="1.3" fill="currentColor" />
      <circle cx="20" cy="26.8" r="2.1" stroke="currentColor" stroke-width="2.1" />
      <path d="M30 9.2c1.2-.9 3-.2 2.4 1.3-.3.7-1.1 1-1.3 1.7" stroke="currentColor" stroke-width="1.9" />
      <circle cx="31.1" cy="14.5" r="0.9" fill="currentColor" />
    {:else if face === 'error'}
      <!-- API / 执行错误：晕眩叉叉眼 + 委屈波浪嘴 -->
      <path d="M11 14.5 16.5 20M16.5 14.5 11 20" stroke="currentColor" stroke-width="2.5" />
      <path d="M23.5 14.5 29 20M29 14.5 23.5 20" stroke="currentColor" stroke-width="2.5" />
      <path d="M14.5 27.2q2.7-2.6 5.5 0t5.5 0" stroke="currentColor" stroke-width="2.3" />
    {:else if face === 'offline'}
      <!-- 离线断连：闭眼休眠 + z -->
      <path d="M10.8 19h5.8M23.4 19h5.8" stroke="currentColor" stroke-width="2.4" />
      <path d="M17.2 26.2h5.6" stroke="currentColor" stroke-width="2.2" />
      <path d="M28.5 9.5h4.2l-4.2 4.2h4.2" stroke="currentColor" stroke-width="1.8" opacity="0.88" />
    {:else if face === 'paused'}
      <!-- 暂停/已取消：淡定小点眼 + 平嘴 -->
      <circle cx="14" cy="18.5" r="2.1" fill="currentColor" />
      <circle cx="26" cy="18.5" r="2.1" fill="currentColor" />
      <path d="M16.2 26h7.6" stroke="currentColor" stroke-width="2.3" />
    {:else if face === 'done'}
      <!-- 完成开心：星星闪亮眼 + 大微笑 -->
      <path d="M14 14v6M11 17h6" stroke="currentColor" stroke-width="2.3" />
      <path d="M26 14v6M23 17h6" stroke="currentColor" stroke-width="2.3" />
      <path d="M14.2 24.4q5.8 5.4 11.6 0" stroke="currentColor" stroke-width="2.5" />
    {:else}
      <!-- 常驻正常状态：温柔开心笑眼 (^‿^) + 浅腮红 -->
      <path d="M10.8 18.8q3.1-4.1 6.2 0" stroke="currentColor" stroke-width="2.5" />
      <path d="M23 18.8q3.1-4.1 6.2 0" stroke="currentColor" stroke-width="2.5" />
      <path d="M15.4 24.4q4.6 4.2 9.2 0" stroke="currentColor" stroke-width="2.4" />
      <ellipse cx="9.4" cy="22.4" rx="2.2" ry="1.2" fill="#fff" opacity="0.32" />
      <ellipse cx="30.6" cy="22.4" rx="2.2" ry="1.2" fill="#fff" opacity="0.32" />
    {/if}
  </svg>
</span>

<style>
  .orb {
    position: relative;
    display: inline-grid;
    place-items: center;
    flex: none;
    width: var(--size);
    height: var(--size);
    border-radius: 50%;
    color: #ffffff;
    box-shadow: 0 4px 14px var(--orb-glow, rgb(99 102 241 / 0.3));
    transition:
      background var(--dur-2) var(--ease),
      box-shadow var(--dur-2) var(--ease),
      transform var(--dur-2) var(--ease);
  }
  .orb svg {
    width: 82%;
    height: 82%;
    display: block;
  }

  /* 各状态专属清新配色（彻底告别纯棕色） */
  .face-idle {
    --orb-glow: rgb(236 72 153 / 0.32);
    background:
      radial-gradient(circle at 28% 24%, rgb(255 255 255 / 0.36), transparent 46%),
      linear-gradient(135deg, #fb7185, #8b5cf6 86%);
  }
  .face-thinking {
    --orb-glow: rgb(99 102 241 / 0.38);
    background:
      radial-gradient(circle at 28% 24%, rgb(255 255 255 / 0.34), transparent 46%),
      linear-gradient(135deg, #6366f1, #06b6d4 88%);
  }
  .face-streaming {
    --orb-glow: rgb(168 85 247 / 0.38);
    background:
      radial-gradient(circle at 28% 24%, rgb(255 255 255 / 0.36), transparent 46%),
      linear-gradient(135deg, #ec4899, #6366f1 85%);
  }
  .face-tool {
    --orb-glow: rgb(20 184 166 / 0.36);
    background:
      radial-gradient(circle at 28% 24%, rgb(255 255 255 / 0.34), transparent 46%),
      linear-gradient(135deg, #14b8a6, #2563eb 88%);
  }
  .face-approval {
    --orb-glow: rgb(245 158 11 / 0.4);
    color: #3b2000;
    background:
      radial-gradient(circle at 28% 24%, rgb(255 255 255 / 0.45), transparent 46%),
      linear-gradient(135deg, #fcd34d, #f59e0b 84%);
  }
  .face-error {
    --orb-glow: rgb(239 68 68 / 0.42);
    background:
      radial-gradient(circle at 28% 24%, rgb(255 255 255 / 0.3), transparent 46%),
      linear-gradient(135deg, #f43f5e, #dc2626 85%);
  }
  .face-offline {
    --orb-glow: rgb(100 116 139 / 0.24);
    background:
      radial-gradient(circle at 28% 24%, rgb(255 255 255 / 0.24), transparent 46%),
      linear-gradient(135deg, #94a3b8, #475569 86%);
  }
  .face-paused {
    --orb-glow: rgb(129 140 248 / 0.24);
    background:
      radial-gradient(circle at 28% 24%, rgb(255 255 255 / 0.28), transparent 46%),
      linear-gradient(135deg, #a5b4fc, #64748b 86%);
  }
  .face-done {
    --orb-glow: rgb(16 185 129 / 0.36);
    background:
      radial-gradient(circle at 28% 24%, rgb(255 255 255 / 0.36), transparent 46%),
      linear-gradient(135deg, #34d399, #059669 86%);
  }

  /* 动态微交互 */
  .breathe.animated {
    animation: orb-breathe 3.6s var(--ease) infinite;
  }
  .face-thinking.animated::after,
  .face-tool.animated::after {
    content: '';
    position: absolute;
    inset: -4px;
    border-radius: 50%;
    border: 2px solid transparent;
    border-top-color: currentColor;
    border-right-color: color-mix(in oklab, currentColor 55%, transparent);
    opacity: 0.85;
    animation: qwq-spin 1.1s linear infinite;
  }
  .face-thinking.animated::after {
    border-top-color: #6366f1;
    border-right-color: #06b6d4;
  }
  .face-tool.animated::after {
    border-top-color: #14b8a6;
    border-right-color: #2563eb;
  }
  .face-streaming.animated {
    animation: orb-speak 1.4s var(--ease) infinite;
  }
  .face-approval.animated {
    animation: orb-nudge 2.2s var(--ease) infinite;
  }
  .face-error.animated {
    animation: orb-shake 0.45s var(--ease) 1;
  }
  .spark {
    animation: spark-blink 1.2s ease-in-out infinite;
  }
  .spark.d2 {
    animation-delay: 0.4s;
  }

  :global(:root[data-motion='reduced']) .orb,
  :global(:root[data-motion='off']) .orb,
  :global(:root[data-motion='reduced']) .orb::after,
  :global(:root[data-motion='off']) .orb::after,
  :global(:root[data-motion='reduced']) .spark,
  :global(:root[data-motion='off']) .spark {
    animation: none;
  }

  @keyframes orb-breathe {
    50% {
      box-shadow: 0 5px 20px var(--orb-glow);
    }
  }
  @keyframes orb-speak {
    0%,
    100% {
      transform: scale(1);
    }
    50% {
      transform: scale(1.06);
    }
  }
  @keyframes orb-nudge {
    0%,
    84%,
    100% {
      transform: rotate(0deg);
    }
    88% {
      transform: rotate(-7deg);
    }
    93% {
      transform: rotate(7deg);
    }
  }
  @keyframes orb-shake {
    0%,
    100% {
      transform: translateX(0);
    }
    20% {
      transform: translateX(-3px);
    }
    40% {
      transform: translateX(3px);
    }
    60% {
      transform: translateX(-2px);
    }
    80% {
      transform: translateX(2px);
    }
  }
  @keyframes spark-blink {
    0%,
    100% {
      opacity: 0.3;
    }
    50% {
      opacity: 1;
    }
  }
</style>
