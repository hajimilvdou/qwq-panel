#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""manifest.json 校验（标准库实现，规则与 sdk/manifest 的 Go 校验器一致）。

用法（在仓库根目录）：
    PYTHONDONTWRITEBYTECODE=1 python tools/manifest_check.py            # 校验 examples/ 并跑共享夹具
    PYTHONDONTWRITEBYTECODE=1 python tools/manifest_check.py FILE...    # 校验指定文件

阶段与 Go 相同，前一阶段失败即停止：大小 → 严格解码（UTF-8、任意层级的重复键、孤立代理、
深度、数字必须是 ±(2^53-1) 内的整数、多余数据、顶层对象）→ JSON Schema → 安装器规则。
Schema 只实现本 schema 用到的关键字，加载时遇到未实现的关键字直接报错；pattern 按 RE2 语义
执行（见 re2_to_python）。共享夹具：api/manifest/v1/testdata/cases.json。需兼容 Python 3.8。
"""
import base64
import bisect
import collections
import copy
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / 'api/manifest/v1/manifest.schema.json'
EXAMPLES = ROOT / 'api/manifest/v1/examples'
CASES = ROOT / 'api/manifest/v1/testdata/cases.json'
SCHEMA_ID = 'urn:qwq:plugin-manifest:v1'

MAX_SIZE = 256 * 1024
MAX_DEPTH = 64
MAX_SAFE_INTEGER = 2 ** 53 - 1
MAX_VIOLATIONS = 100
MAX_POINTER_BYTES = 512
SUPPORTED_SCHEMA_MINOR = 3
PERMISSION_RULES_MINOR = 2
WIDGETS_MINOR = 3  # ui.widgets 与 operations[].reachability（ADR-0018）
READ_ONLY_ACTIONS = {'read', 'list', 'get', 'export', 'describe', 'watch'}
RESERVED_PLUGIN_ID_ROOTS = ('host', 'qwq')

Violation = collections.namedtuple('Violation', 'pointer code message')


class Reject(Exception):
    """解码阶段的失败：与 Go 一样只报告第一个问题。"""

    def __init__(self, pointer, code, message):
        super().__init__(message)
        self.violation = Violation(pointer, code, message)


def pointer(tokens):
    """RFC 6901 JSON Pointer；超过 512 字节时截到能放下的祖先（与 Go 的 pointer() 相同）。"""
    out, size = '', 0
    for t in tokens:
        e = t.replace('~', '~0').replace('/', '~1')
        n = len(e.encode('utf-8', 'surrogatepass'))
        if size + 1 + n > MAX_POINTER_BYTES:
            break
        out, size = out + '/' + e, size + 1 + n
    return out
def excerpt(s, limit=64):
    """消息里只引用不可信输入的短前缀（ASCII 转义）。"""
    b = s.encode('utf-8', 'surrogatepass')
    if len(b) <= limit:
        return json.dumps(s)
    return json.dumps(b[:limit].decode('utf-8', 'ignore')) + '...'


def check_depth(text):
    """字符串感知的括号计数，在 json 模块递归之前拒绝过深的嵌套（Go 解析器在第 65 层报错）。"""
    depth, in_str, esc = 0, False, False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in '[{':
            depth += 1
            if depth > MAX_DEPTH:
                raise Reject('', 'TOO_DEEP', 'nesting deeper than %d levels' % MAX_DEPTH)
        elif ch in ']}':
            depth -= 1


class BadNumber:
    __slots__ = ('code',)

    def __init__(self, code):
        self.code = code


def classify_number(tok):
    """与 Go 的 classifyNumber 相同：返回 int，或 NUMBER_NOT_INTEGER / NUMBER_OUT_OF_RANGE。
    只处理数字串，巨大的指数不需要大数运算。"""
    neg = tok.startswith('-')
    tok = tok.lstrip('-')
    mant, _, exp = tok.replace('E', 'e').partition('e')
    int_part, _, frac = mant.partition('.')
    digits = (int_part + frac).lstrip('0')
    if not digits:
        return 0
    trimmed = digits.rstrip('0')
    shift = (len(digits) - len(trimmed)) - len(frac)
    exp_neg = exp.startswith('-')
    exp = exp.lstrip('+-').lstrip('0')
    if len(exp) > 7:
        return 'NUMBER_NOT_INTEGER' if exp_neg else 'NUMBER_OUT_OF_RANGE'
    if exp:
        shift += -int(exp) if exp_neg else int(exp)
    if shift < 0:
        return 'NUMBER_NOT_INTEGER'
    if len(trimmed) + shift > 16:
        return 'NUMBER_OUT_OF_RANGE'
    v = int(trimmed + '0' * shift)
    if v > MAX_SAFE_INTEGER:
        return 'NUMBER_OUT_OF_RANGE'
    return -v if neg else v


def parse_number(tok):
    r = classify_number(tok)
    return BadNumber(r) if isinstance(r, str) else r


class InvalidConstant(ValueError):
    pass


def reject_constant(name):
    # NaN、Infinity、-Infinity 不是 JSON（Go 的解析器同样拒绝）
    raise InvalidConstant(name)


class Obj(dict):
    """保留原始键值对，以便按文档顺序检查重复键。"""
    __slots__ = ('pairs',)


def object_pairs(pairs):
    o = Obj()
    o.pairs = pairs
    return o


DECODER = json.JSONDecoder(object_pairs_hook=object_pairs, parse_float=parse_number,
                           parse_int=parse_number, parse_constant=reject_constant, strict=True)
SURROGATE = re.compile('[\ud800-\udfff]')
WS = ' \t\n\r'
def decode_strict(raw):
    """严格解码，返回由 dict/list/str/int/bool/None 组成的树；失败抛出 Reject。"""
    try:
        text = raw.decode('utf-8')  # strict：拒绝过长编码、编码后的代理、截断序列
    except UnicodeDecodeError as e:
        raise Reject('', 'INVALID_UTF8', 'not valid UTF-8 at byte offset %d' % e.start)
    check_depth(text)
    start = 0
    while start < len(text) and text[start] in WS:
        start += 1
    try:
        value, end = DECODER.raw_decode(text, start)
    except InvalidConstant as e:
        raise Reject('', 'INVALID_JSON', 'invalid literal %s' % e)
    except json.JSONDecodeError as e:
        raise Reject('', 'INVALID_JSON', '%s at offset %d' % (e.msg, e.pos))
    if text[end:].strip(WS):
        raise Reject('', 'TRAILING_DATA', 'unexpected data after the top-level value at offset %d' % end)
    return walk(value, [])


def walk(v, path):
    """按文档顺序检查（与 Go 流式解析器的顺序一致），并转换为普通 dict/list。"""
    if isinstance(v, Obj):
        out = {}
        for k, item in v.pairs:
            if SURROGATE.search(k):
                raise Reject(pointer(path), 'LONE_SURROGATE', 'unpaired UTF-16 surrogate escape in string')
            if k in out:
                raise Reject(pointer(path + [k]), 'DUPLICATE_KEY', 'duplicate key ' + excerpt(k))
            out[k] = walk(item, path + [k])
        return out
    if isinstance(v, list):
        return [walk(item, path + [str(i)]) for i, item in enumerate(v)]
    if isinstance(v, str):
        if SURROGATE.search(v):
            raise Reject(pointer(path), 'LONE_SURROGATE', 'unpaired UTF-16 surrogate escape in string')
        return v
    if isinstance(v, BadNumber):
        if v.code == 'NUMBER_NOT_INTEGER':
            raise Reject(pointer(path), v.code, 'numbers in a manifest must be integers')
        raise Reject(pointer(path), v.code, 'number outside +-%d' % MAX_SAFE_INTEGER)
    return v


def json_type(x):
    if x is None:
        return 'null'
    if isinstance(x, bool):
        return 'boolean'
    if isinstance(x, int):
        return 'number'
    if isinstance(x, str):
        return 'string'
    if isinstance(x, list):
        return 'array'
    return 'object'


def type_ok(want, x):
    t = json_type(x)
    return t == want or (want == 'integer' and t == 'number')  # 只有整数（解码阶段已保证）


def equal(a, b):
    """JSON 值相等：true 不等于 1（Python 的 True == 1 不能用）。"""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, dict):
        return isinstance(b, dict) and a.keys() == b.keys() and all(equal(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return isinstance(b, list) and len(a) == len(b) and all(equal(p, q) for p, q in zip(a, b))
    return type(a) is type(b) and a == b
RE2_CLASSES = {'s': r'\t\n\f\r ', 'd': '0-9', 'w': '0-9A-Za-z_'}


def re2_to_python(p):
    """把 schema 中的 RE2 pattern 改写成语义相同的 Python 正则。
    差异：Python 的 $ 也匹配末尾换行之前的位置（RE2 只匹配输入末尾，改写为 \\Z）；
    Python 的 \\s \\d \\w 包含 Unicode 字符与 \\v（RE2 只含 ASCII，改写为显式字符类）。
    其他无法保证语义一致的写法直接报错。"""
    out, i, in_class = [], 0, False
    while i < len(p):
        ch = p[i]
        if ch == '\\':
            if i + 1 >= len(p):
                raise ValueError('pattern ends with a backslash: %r' % p)
            nxt = p[i + 1]
            i += 2
            if nxt.lower() in RE2_CLASSES:
                body = RE2_CLASSES[nxt.lower()]
                if nxt.islower():
                    out.append(body if in_class else '[' + body + ']')
                elif in_class:
                    raise ValueError('negated class escape inside a class: %r' % p)
                else:
                    out.append('[^' + body + ']')
            elif nxt in '.\\/+*?()[]{}|^$-':
                out.append('\\' + nxt)
            else:
                raise ValueError('unsupported escape \\%s in pattern %r' % (nxt, p))
            continue
        if in_class:
            if ch == '[':
                raise ValueError('nested or POSIX class in pattern %r' % p)
            if ch == ']':
                in_class = False
        elif ch == '[':
            in_class = True
            out.append(ch)
            i += 1
            if p.startswith('^', i):
                out.append('^')
                i += 1
            if p.startswith(']', i):
                raise ValueError('class starting with ] in pattern %r' % p)
            continue
        elif ch == '$':
            ch = r'\Z'
        elif ch == '(' and p.startswith('(?', i):
            raise ValueError('group flags and lookaround are not RE2-compatible: %r' % p)
        out.append(ch)
        i += 1
    if in_class:
        raise ValueError('unterminated class in pattern %r' % p)
    return re.compile(''.join(out))


KEYWORD_CODES = {
    'type': 'SCHEMA_TYPE', 'const': 'SCHEMA_CONST', 'enum': 'SCHEMA_ENUM', 'pattern': 'SCHEMA_PATTERN',
    'minLength': 'SCHEMA_MIN_LENGTH', 'maxLength': 'SCHEMA_MAX_LENGTH', 'minimum': 'SCHEMA_MINIMUM',
    'maximum': 'SCHEMA_MAXIMUM', 'minItems': 'SCHEMA_MIN_ITEMS', 'maxItems': 'SCHEMA_MAX_ITEMS',
    'uniqueItems': 'SCHEMA_UNIQUE_ITEMS', 'minProperties': 'SCHEMA_MIN_PROPERTIES',
    'maxProperties': 'SCHEMA_MAX_PROPERTIES', 'required': 'SCHEMA_REQUIRED',
    'additionalProperties': 'SCHEMA_ADDITIONAL_PROPERTIES', 'propertyNames': 'SCHEMA_PROPERTY_NAMES',
}
STRUCTURAL = {'$ref', 'properties', 'items', 'allOf', 'if', 'then'}
ANNOTATIONS = {'$schema', '$id', 'title', 'description', 'default', '$defs', 'examples'}
class Validator:
    """Draft 2020-12 子集，错误树展平方式与 Go（jsonschema/v6 + walkValidation）相同。"""

    def __init__(self, schema):
        if schema.get('$id') != SCHEMA_ID:
            raise ValueError('schema $id must be ' + SCHEMA_ID)
        self.root = schema
        self.regex = {}
        self._check(schema, '#')

    def _check(self, s, at):
        if not isinstance(s, dict):
            raise ValueError('%s: schema must be an object' % at)
        for kw, arg in s.items():
            if kw not in KEYWORD_CODES and kw not in STRUCTURAL and kw not in ANNOTATIONS:
                raise ValueError('%s: schema uses unsupported keyword %s' % (at, kw))
            if kw == '$ref' and not arg.startswith('#/'):
                raise ValueError('%s: only local $ref is allowed: %s' % (at, arg))  # 不加载外部 schema
            if kw == 'pattern':
                self.regex[arg] = re2_to_python(arg)
            if kw in ('properties', '$defs'):
                for k, sub in arg.items():
                    self._check(sub, '%s/%s/%s' % (at, kw, k))
            elif kw == 'allOf':
                for n, sub in enumerate(arg):
                    self._check(sub, '%s/allOf/%d' % (at, n))
            elif kw in ('items', 'if', 'then', 'propertyNames') or (kw == 'additionalProperties' and isinstance(arg, dict)):
                self._check(arg, '%s/%s' % (at, kw))
        if '$ref' in s:
            self.resolve(s['$ref'])

    def resolve(self, ref):
        node = self.root
        for part in ref[2:].split('/'):
            node = node[part.replace('~1', '/').replace('~0', '~')]
        return node

    def valid(self, s, x):
        return not self.errors(s, x, [])

    def errors(self, s, x, path):
        """与库的 validate() 顺序相同：type、const、enum 失败时立即返回。"""
        def err(code, msg, extra=None):
            return Violation(pointer(path + [extra] if extra is not None else path), code, msg)
        if 'type' in s and not type_ok(s['type'], x):
            return [err('SCHEMA_TYPE', 'expected %s, got %s' % (s['type'], json_type(x)))]
        if 'const' in s and not equal(x, s['const']):
            return [err('SCHEMA_CONST', 'must be ' + json.dumps(s['const']))]
        if 'enum' in s and not any(equal(x, e) for e in s['enum']):
            return [err('SCHEMA_ENUM', 'must be one of ' + json.dumps(s['enum'], separators=(',', ':')))]
        out = []
        if '$ref' in s:
            out += self.errors(self.resolve(s['$ref']), x, path)
        if isinstance(x, dict):
            if 'minProperties' in s and len(x) < s['minProperties']:
                out.append(err('SCHEMA_MIN_PROPERTIES', 'has %d properties, fewer than %d' % (len(x), s['minProperties'])))
            if 'maxProperties' in s and len(x) > s['maxProperties']:
                out.append(err('SCHEMA_MAX_PROPERTIES', 'has %d properties, more than %d' % (len(x), s['maxProperties'])))
            for k in s.get('required', []):
                if k not in x:
                    out.append(err('SCHEMA_REQUIRED', 'required property is missing', k))
            props = s.get('properties', {})
            extra = s.get('additionalProperties', True)
            for k, v in x.items():
                if k in props:
                    out += self.errors(props[k], v, path + [k])
                elif extra is False:
                    out.append(err('SCHEMA_ADDITIONAL_PROPERTIES', 'property is not allowed', k))
                elif isinstance(extra, dict):
                    out += self.errors(extra, v, path + [k])
            if 'propertyNames' in s:
                for k in x:
                    if not self.valid(s['propertyNames'], k):
                        out.append(err('SCHEMA_PROPERTY_NAMES', 'property name is not allowed by the schema', k))
        elif isinstance(x, list):
            if 'minItems' in s and len(x) < s['minItems']:
                out.append(err('SCHEMA_MIN_ITEMS', 'has %d items, fewer than %d' % (len(x), s['minItems'])))
            if 'maxItems' in s and len(x) > s['maxItems']:
                out.append(err('SCHEMA_MAX_ITEMS', 'has %d items, more than %d' % (len(x), s['maxItems'])))
            if s.get('uniqueItems') and len(x) > 1:
                seen = {}
                for j, item in enumerate(x):
                    key = json.dumps(item, sort_keys=True)  # 只有整数，无浮点表示差异
                    if key in seen:
                        out.append(err('SCHEMA_UNIQUE_ITEMS', 'items %d and %d are equal' % (seen[key], j)))
                        break
                    seen[key] = j
            if 'items' in s:
                for j, item in enumerate(x):
                    out += self.errors(s['items'], item, path + [str(j)])
        elif isinstance(x, str):
            n = len(x)  # 码点数，与 Go 的 utf8.RuneCount 相同（解码阶段已拒绝孤立代理）
            if 'minLength' in s and n < s['minLength']:
                out.append(err('SCHEMA_MIN_LENGTH', 'length %d is less than %d' % (n, s['minLength'])))
            if 'maxLength' in s and n > s['maxLength']:
                out.append(err('SCHEMA_MAX_LENGTH', 'length %d is more than %d' % (n, s['maxLength'])))
            if 'pattern' in s and not self.regex[s['pattern']].search(x):
                # 加引号转义：有的 pattern 含控制字符与双向覆盖符
                out.append(err('SCHEMA_PATTERN', 'does not match pattern ' + json.dumps(s['pattern'])))
        elif json_type(x) == 'number':
            if 'minimum' in s and x < s['minimum']:
                out.append(err('SCHEMA_MINIMUM', 'must be >= %d' % s['minimum']))
            if 'maximum' in s and x > s['maximum']:
                out.append(err('SCHEMA_MAXIMUM', 'must be <= %d' % s['maximum']))
        for sub in s.get('allOf', []):
            out += self.errors(sub, x, path)
        if 'if' in s and self.valid(s['if'], x) and 'then' in s:
            out += self.errors(s['then'], x, path)
        return out


def check(v, inst):
    return v.errors(v.root, inst, [])


def installer_rules(m):
    """schema 表达不了、由安装器执行的规则（ARCHITECTURE §5.3），与 Go 的 installerRules 逐条对应。
    只在 schema 校验通过后运行。"""
    out = []

    def add(tokens, code, msg):
        out.append(Violation(pointer(tokens), code, msg))

    minor = m['schema_version'][2:]
    if len(minor) > 10 or int(minor) > SUPPORTED_SCHEMA_MINOR:
        add(['schema_version'], 'UNSUPPORTED_SCHEMA_VERSION',
            'schema_version minor is above the supported 1.%d' % SUPPORTED_SCHEMA_MINOR)

    # relpath 只允许 ASCII，所以 ASCII 小写化就是完整的大小写折叠，Unicode 规范化对 ASCII 是恒等变换。
    groups = {}
    for k in m['files']:
        if any(ord(ch) >= 0x80 for ch in k):
            add(['files', k], 'PATH_NOT_ASCII', 'file path must be ASCII')
            continue
        groups.setdefault(k.lower(), []).append(k)
    for g in groups.values():
        g.sort()
        if len(g) > 1:
            for j, k in enumerate(g):
                other = g[1] if j == 0 else g[0]
                add(['files', k], 'PATH_CASE_COLLISION', 'path collides with %s after case folding' % excerpt(other))
    # 保留名与"既是文件又是目录"同样按折叠后的路径比较，在大小写不敏感的文件系统上也成立
    folded = sorted(groups)
    for f, g in groups.items():
        if f == 'manifest.json' or f == 'signatures' or f.startswith('signatures/'):
            for k in g:
                add(['files', k], 'PATH_RESERVED', 'manifest.json and signatures/ are not part of files')
        j = bisect.bisect_left(folded, f + '/')  # 若有子路径，排序后第一个 >= f/ 的就是
        if j < len(folded) and folded[j].startswith(f + '/'):
            child = groups[folded[j]][0]
            for k in g:
                add(['files', k], 'PATH_FILE_DIR_CONFLICT', 'path is listed as a file but is also a directory of ' + excerpt(child))

    refs = [(['entrypoint'], m.get('entrypoint')), (['icon'], m.get('icon')),
            (['config', 'schema'], m['config'].get('schema')),
            (['provenance', 'sbom'], m['provenance'].get('sbom')), (['provenance', 'build'], m['provenance'].get('build'))]
    if 'ui' in m:
        refs.append((['ui', 'entry'], m['ui'].get('entry')))
    ops = m['operations']
    for j, op in enumerate(ops):
        for f in ('request_schema', 'response_schema', 'docs'):
            refs.append((['operations', str(j), f], op.get(f)))
    for tokens, r in refs:
        if r and r not in m['files']:
            add(tokens, 'FILE_NOT_LISTED', 'referenced file %s is not listed in files' % excerpt(r))

    names = set()
    for j, op in enumerate(ops):
        if op['name'] in names:
            add(['operations', str(j), 'name'], 'DUPLICATE_OPERATION',
                'operation %s is declared more than once' % excerpt(op['name']))
        names.add(op['name'])
    routes = set()
    for j, r in enumerate(m.get('ui', {}).get('routes', [])):
        if r['path'] in routes:
            add(['ui', 'routes', str(j), 'path'], 'UI_ROUTE_DUPLICATE', 'route %s is declared more than once' % excerpt(r['path']))
        routes.add(r['path'])
    declared = {(c['name'], c['scope']) for c in m['capabilities']}
    for j, op in enumerate(ops):
        for n, c in enumerate(op.get('capabilities', [])):
            if (c['name'], c['scope']) not in declared:
                add(['operations', str(j), 'capabilities', str(n)], 'OPERATION_CAPABILITY_UNDECLARED',
                    'capability %s is not declared in the top-level capabilities' % excerpt(c['name'] + ':' + c['scope']))
    for j, op in enumerate(ops):
        if op.get('undo') and op['undo'] not in names:
            add(['operations', str(j), 'undo'], 'UNDO_UNKNOWN', 'undo refers to undeclared operation ' + excerpt(op['undo']))
        if op.get('ui_route') and op['ui_route'] not in routes:
            add(['operations', str(j), 'ui_route'], 'UI_ROUTE_UNDECLARED',
                'ui_route %s is not declared in ui.routes' % excerpt(op['ui_route']))
    add_approval_rules(ops, add)
    add_permission_rules(m, ops, add)
    add_schema_minor_rules(m, ops, add)
    add_widget_rules(m, ops, add)
    return out


def add_schema_minor_rules(m, ops, add):
    """ADR-0018，与 Go 的 schemaMinorRules 逐条对应：1.3 新增的成员不得出现在声明更低 minor 的 manifest 里。
    只看成员是否存在，不看取值；minor 过大时已按 UNSUPPORTED_SCHEMA_VERSION 报告，这里不重复。"""
    minor = m['schema_version'][2:]
    if len(minor) > 10 or int(minor) >= WIDGETS_MINOR:
        return
    for j, op in enumerate(ops):
        if 'reachability' in op:
            add(['operations', str(j), 'reachability'], 'SCHEMA_VERSION_TOO_LOW',
                'reachability needs schema_version 1.%d or later' % WIDGETS_MINOR)
    if 'widgets' in m.get('ui', {}):
        add(['ui', 'widgets'], 'SCHEMA_VERSION_TOO_LOW', 'ui.widgets needs schema_version 1.%d or later' % WIDGETS_MINOR)


def add_widget_rules(m, ops, add):
    """ADR-0018，与 Go 的 widgetRules 逐条对应：id 不重复；operation 必须是本插件 effect=read、mode=invoke 的操作。"""
    by_name = {}
    for op in ops:
        by_name.setdefault(op['name'], op)  # 重名由 DUPLICATE_OPERATION 报告
    ids = set()
    for j, w in enumerate(m.get('ui', {}).get('widgets', [])):
        if w['id'] in ids:
            add(['ui', 'widgets', str(j), 'id'], 'UI_WIDGET_DUPLICATE', 'widget %s is declared more than once' % excerpt(w['id']))
        ids.add(w['id'])
        op = by_name.get(w['operation'])
        if op is None:
            add(['ui', 'widgets', str(j), 'operation'], 'UI_WIDGET_OPERATION_UNKNOWN',
                'widget refers to undeclared operation ' + excerpt(w['operation']))
        elif op['effect'] != 'read' or op['mode'] != 'invoke':
            add(['ui', 'widgets', str(j), 'operation'], 'UI_WIDGET_OPERATION_UNSUITABLE',
                'a widget operation must have effect read and mode invoke')


def add_permission_rules(m, ops, add):
    """ADR-0014，与 Go 的 permissionRules 逐条对应。"""
    for root in RESERVED_PLUGIN_ID_ROOTS:
        if m['id'] == root or m['id'].startswith(root + '.'):
            add(['id'], 'PLUGIN_ID_RESERVED', 'plugin id must not use the reserved namespace ' + root)
    minor = m['schema_version'][2:]
    if len(minor) > 10 or int(minor) < PERMISSION_RULES_MINOR:
        return

    def check_namespace(tokens, permission):
        res = permission.split(':', 1)[0]
        if res != m['id'] and not res.startswith(m['id'] + '.'):
            add(tokens, 'PERMISSION_NAMESPACE', 'permission resource must be the plugin id or start with it')

    for j, op in enumerate(ops):
        tokens = ['operations', str(j), 'permission']
        check_namespace(tokens, op['permission'])
        if op['effect'] != 'read' and op['permission'].split(':', 1)[1] in READ_ONLY_ACTIONS:
            add(tokens, 'PERMISSION_EFFECT_MISMATCH', 'a read-class action cannot guard a %s operation' % excerpt(op['effect']))
    for j, route in enumerate(m.get('ui', {}).get('routes', [])):
        check_namespace(['ui', 'routes', str(j), 'permission'], route['permission'])


def approval_text_ok(s, newlines):
    """An approval card text may not contain C0/C1 controls, DEL, bidi overrides/isolates
    or U+FFFD; \\n is allowed in the description (same rule as the Go validator)."""
    for ch in s:
        if newlines and ch == '\n':
            continue
        o = ord(ch)
        if o < 0x20 or 0x7f <= o <= 0x9f or 0x202a <= o <= 0x202e or 0x2066 <= o <= 0x2069 or o == 0xfffd:
            return False
    return True


def add_approval_rules(ops, add):
    """ADR-0010 operation approval metadata: the schema enforces the same rules, these
    guards keep them true for a decoded manifest (Go: manifest.approvalRules)."""
    for j, op in enumerate(ops):
        base = ['operations', str(j)]
        approval = op.get('approval', '')
        if approval not in ('', 'auto', 'confirm', 'ai_confirm'):
            add(base + ['approval'], 'APPROVAL_INVALID', 'approval must be auto, confirm or ai_confirm')
        summary = op.get('approval_summary', '')
        if not summary:
            if approval in ('confirm', 'ai_confirm'):
                add(base + ['approval_summary'], 'APPROVAL_SUMMARY_MISSING',
                    'approval %s needs an approval_summary' % approval)
        elif not summary.strip() or not approval_text_ok(summary, False) or len(summary) > 200:
            add(base + ['approval_summary'], 'APPROVAL_SUMMARY_INVALID',
                'approval_summary must be one non-blank line without control or bidi characters, at most 200 characters')
        description = op.get('approval_description', '')
        if description and (not approval_text_ok(description, True) or len(description) > 2000):
            add(base + ['approval_description'], 'APPROVAL_DESCRIPTION_INVALID',
                'approval_description must have no control or bidi characters other than newlines, at most 2000 characters')
def finish(vs):
    vs = sorted(vs)  # 指针、错误码、消息；码点序与 Go 的 UTF-8 字节序一致
    if len(vs) > MAX_VIOLATIONS:
        vs = vs[:MAX_VIOLATIONS] + [Violation('', '...', '%d more' % (len(vs) - MAX_VIOLATIONS))]
    return vs


def validate(v, raw):
    """与 Go 的 Parse 相同的阶段；返回 Violation 列表（空表示通过）。"""
    if len(raw) > MAX_SIZE:
        return [Violation('', 'TOO_LARGE', 'manifest is %d bytes, more than %d' % (len(raw), MAX_SIZE))]
    try:
        m = decode_strict(raw)
    except Reject as e:
        return [e.violation]
    if not isinstance(m, dict):
        return [Violation('', 'NOT_OBJECT', 'top-level value must be an object')]
    errs = check(v, m)
    if errs:
        return finish(errs)
    return finish(installer_rules(m))


def load(path):
    """读取受信 JSON（schema、示例、夹具），同样按严格规则解码。"""
    try:
        return decode_strict(pathlib.Path(path).read_bytes())
    except Reject as e:
        raise ValueError('%s: %s %s %s' % (path, e.violation.pointer or '/', e.violation.code, e.violation.message))


def unescape(tok):
    return tok.replace('~1', '/').replace('~0', '~')


def apply_patch(doc, ops):
    """RFC 6902 的 add / replace / remove。"""
    for op in ops:
        if set(op) - {'op', 'path', 'value'} or op['op'] not in ('add', 'replace', 'remove'):
            raise ValueError('unsupported patch operation %r' % op)
        tokens = [unescape(t) for t in op['path'].split('/')[1:]]
        if not op['path'].startswith('/') or not tokens:
            raise ValueError('bad patch path %r' % op['path'])
        parent = doc
        for t in tokens[:-1]:
            parent = parent[int(t)] if isinstance(parent, list) else parent[t]
        last = tokens[-1]
        if isinstance(parent, list):
            if op['op'] == 'add' and last == '-':
                parent.append(copy.deepcopy(op['value']))
                continue
            i = int(last)
            if not 0 <= i < len(parent) + (op['op'] == 'add'):
                raise ValueError('patch index out of range: %r' % op['path'])
            if op['op'] == 'add':
                parent.insert(i, copy.deepcopy(op['value']))
            elif op['op'] == 'replace':
                parent[i] = copy.deepcopy(op['value'])
            else:
                del parent[i]
        else:
            if op['op'] != 'add' and last not in parent:
                raise ValueError('patch path does not exist: %r' % op['path'])
            if op['op'] == 'remove':
                del parent[last]
            else:
                parent[last] = copy.deepcopy(op['value'])
    return doc
CASE_KEYS = {'name', 'expect', 'code', 'pointer', 'note', 'base', 'patch', 'edit', 'raw', 'raw_b64', 'raw_repeat'}


def build_input(case):
    """按夹具描述生成待校验的原始字节（Go 的 buildInput 做同样的事）。"""
    unknown = set(case) - CASE_KEYS
    sources = [k for k in ('patch', 'edit', 'raw', 'raw_b64', 'raw_repeat') if k in case]
    if unknown or len(sources) != 1 or (('base' in case) != (sources[0] in ('patch', 'edit'))):
        raise ValueError('case %r: bad fields' % case.get('name'))
    if 'raw' in case:
        return case['raw'].encode('utf-8')
    if 'raw_b64' in case:
        return base64.b64decode(case['raw_b64'], validate=True)
    if 'raw_repeat' in case:
        return ''.join(p['s'] * p['n'] for p in case['raw_repeat']).encode('utf-8')
    if not re.match(r'^[a-z0-9._-]+\.json\Z', case['base']):
        raise ValueError('case %r: bad base' % case['name'])
    base = (EXAMPLES / case['base']).read_bytes()
    if 'patch' in case:
        doc = apply_patch(decode_strict(base), case['patch'])
        return json.dumps(doc, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    edit = case['edit']
    if set(edit) - {'replace', 'append', 'pad_to'}:
        raise ValueError('case %r: bad edit' % case['name'])
    text = base.decode('utf-8')
    for find, repl in edit.get('replace', []):
        if text.count(find) != 1:
            raise ValueError('case %r: %r must occur exactly once' % (case['name'], find))
        text = text.replace(find, repl)
    raw = (text + edit.get('append', '')).encode('utf-8')
    if 'pad_to' in edit:
        if len(raw) > edit['pad_to']:
            raise ValueError('case %r: base is longer than pad_to' % case['name'])
        raw += b' ' * (edit['pad_to'] - len(raw))
    return raw


def check_case(v, case):
    """返回 (是否符合期望, 实际的 violations)。"""
    vs = validate(v, build_input(case))
    if case['expect'] == 'accept':
        return not vs, vs
    if case['expect'] != 'reject':
        raise ValueError('case %r: expect must be accept or reject' % case['name'])
    if not vs:
        return False, vs
    want_ptr = case.get('pointer')
    match = any(x.code == case['code'] and (want_ptr is None or x.pointer == want_ptr) for x in vs) \
        if 'code' in case else True
    return match, vs


def show(x):
    p = x.pointer or '/'
    if not p.isprintable():
        p = json.dumps(p)
    return '%s %s: %s' % (p, x.code, x.message)


def main(args):
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(errors='backslashreplace')
    v = Validator(load(SCHEMA_PATH))
    if args:
        targets = [(p, p) for p in args]
    else:
        targets = [(p, p.relative_to(ROOT).as_posix()) for p in sorted(EXAMPLES.glob('*.json'))]
    failed = 0
    for path, label in targets:
        errs = validate(v, pathlib.Path(path).read_bytes())
        print(('ok   ' if not errs else 'FAIL ') + str(label))
        for e in errs:
            print('     ', show(e))
        failed += bool(errs)
    if not args:
        cases = load(CASES)['cases']
        names = [c['name'] for c in cases]
        if len(names) != len(set(names)):
            raise ValueError('duplicate case names in ' + str(CASES))
        for case in cases:
            ok, vs = check_case(v, case)
            verb = 'rejects' if case['expect'] == 'reject' else 'accepts'
            print(('ok   ' if ok else 'FAIL ') + '%s: %s' % (verb, case['name']))
            if not ok:
                want = '%s at %s' % (case['code'], case.get('pointer', '(any)')) if 'code' in case else ''
                print('      expected', case['expect'], want)
                for e in vs:
                    print('     ', show(e))
            failed += not ok
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
