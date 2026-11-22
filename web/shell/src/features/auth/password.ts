// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 口令策略提示（SPEC §6：≥12 位；不足 20 位时需含 3 类字符）
 * --------------------------------------------------------------------------
 * 仅用于实时提示，后端是唯一裁决（VALIDATION_FAILED 的 /password 仍要展示）。
 * ========================================================================== */

export interface PasswordCheck {
  ok: boolean;
  /** 逐条规则（界面列出并打勾） */
  rules: { label: string; ok: boolean }[];
}

const CLASSES = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/];

export function classCount(pw: string): number {
  return CLASSES.filter((re) => re.test(pw)).length;
}

export function checkPassword(pw: string): PasswordCheck {
  const len = [...pw].length;
  const long = len >= 20;
  const rules = [
    { label: '至少 12 位', ok: len >= 12 },
    { label: long ? '20 位以上，字符种类不限' : '含大写、小写、数字、符号中的 3 类（或 20 位以上）', ok: long || classCount(pw) >= 3 },
  ];
  return { ok: rules.every((r) => r.ok), rules };
}
