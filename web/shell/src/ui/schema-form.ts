// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * SchemaForm 模型（纯函数，无 DOM）
 * --------------------------------------------------------------------------
 * 把一份"扁平 object" JSON Schema 翻成字段描述，并负责：
 *
 *   fieldsOf(schema)                 → SchemaField[]（按 properties 顺序）
 *   initialValues(fields, current)   → 表单内部值（全部是字符串/布尔，便于绑定）
 *   validate(fields, values)         → { '/pointer': 文案 }（类型 + 必填 + 范围）
 *   toPayload(fields, values)        → 提交用对象（数字转回 number，密文按规则处理）
 *
 * 密文字段（x-qwq-secret / format=password / writeOnly）：
 *   服务端返回值是 { $secret: ref }（或缺省）→ 表单显示"已设置 · 替换"；
 *   不替换时提交原引用对象，服务端不变；替换时提交新明文。
 *   密文值绝不进入草稿（drafts.ts 已按字段名剔除，这里另以 SECRET 前缀标记）。
 *
 * 不支持的形状（嵌套 object、oneOf…）退化为 JSON 文本域，并在提交时解析。
 * pattern 交给后端校验（SPEC §5）。
 * ========================================================================== */

export type SchemaFieldKind = 'string' | 'text' | 'integer' | 'number' | 'boolean' | 'enum' | 'secret' | 'json';

export interface SchemaField {
  /** 属性名 */
  name: string;
  /** JSON Pointer：/name（与 VALIDATION_FAILED 的 violations[].pointer 对齐） */
  pointer: string;
  kind: SchemaFieldKind;
  label: string;
  hint?: string;
  group?: string;
  groupDesc?: string;
  placeholder?: string;
  required: boolean;
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  options?: { value: string; label: string }[];
  format?: string;
  default?: unknown;
}

export interface SchemaFieldGroup {
  title?: string;
  desc?: string;
  fields: SchemaField[];
}

/** 表单内部值：一律可绑定的原始类型；密文字段为 SecretValue */
export interface SecretValue {
  /** 服务端已有值（引用对象或 true），不替换时原样提交 */
  existing: unknown;
  /** 用户是否点了"替换" */
  replacing: boolean;
  /** 新明文 */
  next: string;
}
export type FormValue = string | boolean | SecretValue;
export type FormValues = Record<string, FormValue>;

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown): string | undefined => (typeof v === 'string' && v.trim() ? v : undefined);
const num = (v: unknown): number | undefined => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);

/* ------------------------------------------------------------------ schema → 字段 */

function kindOf(p: Json): SchemaFieldKind {
  if (p['x-qwq-secret'] === true || p['x-secret'] === true || p.writeOnly === true || p.format === 'password') return 'secret';
  if (Array.isArray(p.enum) && p.enum.every((x) => typeof x === 'string')) return 'enum';
  switch (p.type) {
    case 'integer':
      return 'integer';
    case 'number':
      return 'number';
    case 'boolean':
      return 'boolean';
    case 'string':
      return (num(p.maxLength) ?? 0) > 1000 || p.format === 'textarea' || p['x-multiline'] === true ? 'text' : 'string';
    default:
      return 'json';
  }
}

export function fieldsOf(schema: unknown): SchemaField[] {
  if (!isObj(schema) || !isObj(schema.properties)) return [];
  const required = new Set(Array.isArray(schema.required) ? schema.required.filter((x) => typeof x === 'string') : []);
  return Object.entries(schema.properties)
    .filter((e): e is [string, Json] => isObj(e[1]))
    .map(([name, p]) => {
      const kind = kindOf(p);
      const titles = isObj(p['x-qwq-enum-titles']) ? p['x-qwq-enum-titles'] : {};
      return {
        name,
        pointer: '/' + name.replace(/~/g, '~0').replace(/\//g, '~1'),
        kind,
        label: str(p.title) ?? name,
        hint: str(p.description),
        group: str(p['x-group']),
        groupDesc: str(p['x-group-desc']),
        placeholder: str(p['x-placeholder']),
        required: required.has(name),
        minimum: num(p.minimum),
        maximum: num(p.maximum),
        minLength: num(p.minLength),
        maxLength: num(p.maxLength),
        format: str(p.format),
        default: p.default,
        options:
          kind === 'enum'
            ? (p.enum as string[]).map((v) => ({ value: v, label: str(titles[v]) ?? (v === '' ? '默认（自动）' : v) }))
            : undefined,
      } satisfies SchemaField;
    });
}

/** 按 x-group 聚合字段为清晰卡片分区，保持声明顺序 */
export function groupFields(fields: readonly SchemaField[]): SchemaFieldGroup[] {
  const byTitle = new Map<string, SchemaFieldGroup>();
  const out: SchemaFieldGroup[] = [];
  for (const f of fields) {
    const key = f.group ?? '';
    let grp = byTitle.get(key);
    if (!grp) {
      grp = { title: f.group, desc: f.groupDesc, fields: [] };
      byTitle.set(key, grp);
      out.push(grp);
    } else if (!grp.desc && f.groupDesc) {
      grp.desc = f.groupDesc;
    }
    grp.fields.push(f);
  }
  return out;
}

/** schema 顶层 x-qwq-hot-apply（缺省 true）：false 时保存后需重启生效 */
export function hotApply(schema: unknown): boolean {
  return !(isObj(schema) && schema['x-qwq-hot-apply'] === false);
}

/* ------------------------------------------------------------------ 值 ↔ 表单 */

function present(v: unknown): boolean {
  return v !== undefined && v !== null && v !== '' && v !== false;
}

export function initialValues(fields: readonly SchemaField[], current: Json = {}): FormValues {
  const out: FormValues = {};
  for (const f of fields) {
    const has = Object.prototype.hasOwnProperty.call(current, f.name);
    const v = has ? current[f.name] : f.default;
    switch (f.kind) {
      case 'secret':
        out[f.name] = { existing: has && present(v) ? v : undefined, replacing: !(has && present(v)), next: '' };
        break;
      case 'boolean':
        out[f.name] = v === true;
        break;
      case 'json':
        out[f.name] = v === undefined ? '' : JSON.stringify(v, null, 2);
        break;
      default:
        out[f.name] = v === undefined || v === null ? '' : String(v);
    }
  }
  return out;
}

export const isSecret = (v: FormValue | undefined): v is SecretValue => isObj(v) && 'replacing' in v;

/* ------------------------------------------------------------------ 校验 */

export function validate(fields: readonly SchemaField[], values: FormValues): Record<string, string> {
  const errs: Record<string, string> = {};
  for (const f of fields) {
    const v = values[f.name];
    if (f.kind === 'boolean') continue;
    if (isSecret(v)) {
      if (f.required && v.replacing && !v.next && v.existing === undefined) errs[f.pointer] = '必填';
      continue;
    }
    const s = typeof v === 'string' ? v.trim() : '';
    if (!s) {
      if (f.required) errs[f.pointer] = '必填';
      continue;
    }
    if (f.kind === 'integer' || f.kind === 'number') {
      const n = Number(s);
      if (!Number.isFinite(n) || (f.kind === 'integer' && !Number.isInteger(n))) {
        errs[f.pointer] = f.kind === 'integer' ? '请填写整数' : '请填写数字';
      } else if (f.minimum !== undefined && n < f.minimum) errs[f.pointer] = `不能小于 ${f.minimum}`;
      else if (f.maximum !== undefined && n > f.maximum) errs[f.pointer] = `不能大于 ${f.maximum}`;
    } else if (f.kind === 'json') {
      try {
        JSON.parse(s);
      } catch {
        errs[f.pointer] = '不是合法的 JSON';
      }
    } else {
      if (f.minLength !== undefined && s.length < f.minLength) errs[f.pointer] = `至少 ${f.minLength} 个字符`;
      else if (f.maxLength !== undefined && s.length > f.maxLength) errs[f.pointer] = `最多 ${f.maxLength} 个字符`;
      else if (f.kind === 'enum' && !f.options?.some((o) => o.value === s)) errs[f.pointer] = '请从列表中选择';
    }
  }
  return errs;
}

/* ------------------------------------------------------------------ 提交 */

/** 只在 validate() 通过后调用；空的非必填字段省略 */
export function toPayload(fields: readonly SchemaField[], values: FormValues): Json {
  const out: Json = {};
  for (const f of fields) {
    const v = values[f.name];
    if (isSecret(v)) {
      if (v.replacing && v.next) out[f.name] = v.next;
      else if (v.existing !== undefined) out[f.name] = v.existing;
      continue;
    }
    if (typeof v === 'boolean') {
      out[f.name] = v;
      continue;
    }
    const s = (v ?? '').trim();
    if (!s) continue;
    if (f.kind === 'integer' || f.kind === 'number') out[f.name] = Number(s);
    else if (f.kind === 'json') out[f.name] = JSON.parse(s);
    else out[f.name] = s;
  }
  return out;
}

/** 草稿用：去掉全部密文字段 */
export function draftOf(fields: readonly SchemaField[], values: FormValues): Json {
  const out: Json = {};
  for (const f of fields) if (f.kind !== 'secret') out[f.name] = values[f.name];
  return out;
}
