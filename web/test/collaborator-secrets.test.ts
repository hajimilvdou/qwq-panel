// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 协作者小修集成门禁：秘密字段不能进入会话草稿，普通值与原引用保持。
 * ========================================================================== */
import { describe, expect, it } from 'vitest';
import { stripSecrets } from '$lib/drafts';
import { draftOf, fieldsOf, initialValues, isSecret, toPayload } from '$ui/schema-form';

describe('协作者秘密字段兼容', () => {
  it('逐层剔除数组内秘密，同时保留结构、普通值与原始输入', () => {
    const input = {
      name: 'example',
      rows: [
        { tag: 'first', private_key: 'fixture-key', nested: { token: 'fixture-token', port: 443 } },
        [{ password: 'fixture-password', note: 'keep' }, null, false, 0, 'plain'],
      ],
      empty: [],
    };
    const original = structuredClone(input);

    expect(stripSecrets(input)).toEqual({
      name: 'example',
      rows: [{ tag: 'first', nested: { port: 443 } }, [{ note: 'keep' }, null, false, 0, 'plain']],
      empty: [],
    });
    expect(input).toEqual(original);
  });

  it('x-secret 任意字段名不入草稿，未替换保留引用，显式替换才提交新值', () => {
    const fields = fieldsOf({
      type: 'object',
      properties: {
        credential: { type: 'string', 'x-secret': true },
        legacy: { type: 'string', 'x-qwq-secret': true },
        ordinary: { type: 'string' },
      },
    });
    const reference = { $secret: 'fixture-reference' };
    const values = initialValues(fields, { credential: reference, ordinary: 'keep' });

    expect(fields.map((f) => f.kind)).toEqual(['secret', 'secret', 'string']);
    expect(draftOf(fields, values)).toEqual({ ordinary: 'keep' });
    expect(toPayload(fields, values)).toEqual({ credential: reference, ordinary: 'keep' });

    const credential = values.credential;
    expect(isSecret(credential)).toBe(true);
    if (!isSecret(credential)) throw new Error('秘密字段未进入替换状态模型');
    credential.replacing = true;
    credential.next = 'fixture-replacement';
    expect(toPayload(fields, values)).toEqual({ credential: 'fixture-replacement', ordinary: 'keep' });
  });
});
