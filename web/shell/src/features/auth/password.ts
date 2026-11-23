// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 口令策略提示（SPEC §6：≥12 位；不足 20 位时需含 3 类字符）
 * --------------------------------------------------------------------------
 * 仅用于实时提示，后端是唯一裁决（VALIDATION_FAILED 的 /password 仍要展示）。
 * ========================================================================== */

export interface PasswordClassStatus {
  id: 'upper' | 'lower' | 'digit' | 'symbol';
  label: string;
  ok: boolean;
}

export interface PasswordCheck {
  ok: boolean;
  /** 逐条规则（界面列出并打勾） */
  rules: { label: string; ok: boolean }[];
  /** 4 类字符各自的实时命中状态（4 选 3，不强制含大写） */
  classes: PasswordClassStatus[];
  /** 是否已达到 20 位长口令免字符种类规则 */
  long: boolean;
}

const CLASS_SPECS: readonly { id: PasswordClassStatus['id']; label: string; re: RegExp }[] = [
  { id: 'upper', label: '大写字母', re: /[A-Z]/ },
  { id: 'lower', label: '小写字母', re: /[a-z]/ },
  { id: 'digit', label: '数字', re: /[0-9]/ },
  { id: 'symbol', label: '符号', re: /[^A-Za-z0-9]/ },
];

export function classCount(pw: string): number {
  return CLASS_SPECS.filter((c) => c.re.test(pw)).length;
}

export function checkPassword(pw: string): PasswordCheck {
  const len = [...pw].length;
  const long = len >= 20;
  const classes: PasswordClassStatus[] = CLASS_SPECS.map((c) => ({
    id: c.id,
    label: c.label,
    ok: c.re.test(pw),
  }));
  const matched = classes.filter((c) => c.ok);
  const count = matched.length;
  let classLabel: string;
  if (long) {
    classLabel = '已满 20 位长口令，字符种类不限';
  } else if (count >= 3) {
    classLabel = `4 类字符中任选 3 类（已满足 ${count}/4 类：${matched.map((c) => c.label).join('、')}）`;
  } else if (count > 0) {
    classLabel = `4 类字符中任选 3 类（当前 ${count}/3 类，再补 ${3 - count} 类或满 20 位）`;
  } else {
    classLabel = '大写、小写、数字、符号中任选 3 类（无需全含，或满 20 位）';
  }
  const rules = [
    { label: '至少 12 位', ok: len >= 12 },
    { label: classLabel, ok: long || count >= 3 },
  ];
  return { ok: rules.every((r) => r.ok), rules, classes, long };
}
