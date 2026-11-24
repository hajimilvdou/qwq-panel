// SPDX-License-Identifier: Apache-2.0
/* ==========================================================================
 * @qwq/kit v2 · 插件沙箱 UI SDK 公开出口
 * --------------------------------------------------------------------------
 * 插件打包自带，受 manifest ui.kit_major 约束；不得引用 shell（AGPL）代码。
 * ========================================================================== */

export {
  KIT_MAJOR,
  PluginHostError,
  PluginInvokeError,
  QwqPluginBridge,
  applyHostSettings,
  createPluginBridge,
  parseInitialFragment,
  unwrapInvokeOutcome,
  type BridgeConnectOptions,
  type HostProblem,
  type InvokeOutcome,
  type KitConfirmOptions,
  type KitEnsurePluginsFailure,
  type KitEnsurePluginsResult,
  type KitEvent,
  type KitHostSettings,
  type KitInvokeOptions,
  type PluginBridgeClient,
} from './bridge';

export {
  generateOpenSSHEd25519KeyPair,
  h,
  invokeWithApprovalFollowup,
  mountAutoResize,
  type ChildSpec,
  type TrackedInvokeOptions,
} from './followup_and_dom';
