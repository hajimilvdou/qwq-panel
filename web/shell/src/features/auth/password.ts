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

const UPPER_RE = /\p{Lu}/u;
const LOWER_RE = /\p{Ll}/u;
const DIGIT_RE = /\p{Nd}/u;

function hasUnicodeSymbol(runes: readonly string[]): boolean {
  return runes.some((ch) => !UPPER_RE.test(ch) && !LOWER_RE.test(ch) && !DIGIT_RE.test(ch));
}

export function classCount(pw: string): number {
  const runes = [...pw];
  return [UPPER_RE.test(pw), LOWER_RE.test(pw), DIGIT_RE.test(pw), hasUnicodeSymbol(runes)].filter(Boolean).length;
}

export function checkPassword(pw: string, username = ''): PasswordCheck {
  const runes = [...pw];
  const len = runes.length;
  const nonBlank = pw.trim().length > 0;
  const notAllSame = len < 2 || new Set(runes).size > 1;
  const withinMax = len <= 256;
  const cleanUser = username.trim().toLowerCase();
  const containsUser = cleanUser.length >= 3 && pw.toLowerCase().includes(cleanUser);

  const long = len >= 20;
  const classes: PasswordClassStatus[] = [
    { id: 'upper', label: '大写字母', ok: UPPER_RE.test(pw) },
    { id: 'lower', label: '小写字母', ok: LOWER_RE.test(pw) },
    { id: 'digit', label: '数字', ok: DIGIT_RE.test(pw) },
    { id: 'symbol', label: '符号', ok: hasUnicodeSymbol(runes) },
  ];
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
  const rules: { label: string; ok: boolean }[] = [
    { label: len > 256 ? `长度 12 ~ 256 位（当前 ${len} 位，已超上限）` : '长度 12 ~ 256 位', ok: len >= 12 && withinMax && nonBlank },
    { label: classLabel, ok: (long || count >= 3) && nonBlank },
  ];
  if (len >= 12 && !notAllSame) {
    rules.push({ label: '不能全部为同一个重复字符', ok: false });
  }
  if (cleanUser.length >= 3) {
    rules.push({ label: `不能包含用户名「${username.trim()}」`, ok: !containsUser && len > 0 });
  }
  return {
    ok: len >= 12 && withinMax && nonBlank && notAllSame && !containsUser && (long || count >= 3),
    rules,
    classes,
    long,
  };
}
