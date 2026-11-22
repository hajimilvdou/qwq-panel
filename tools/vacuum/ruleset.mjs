// SPDX-License-Identifier: AGPL-3.0-only
//
// vacuum ruleset for the public API (api/public/v1/openapi.yaml). Runs in vacuum's isolated JS
// runtime; no npm packages are installed, the @stoplight/* imports are vacuum's built-in shims.
//
// Command (build machine, after `bash scripts/remote.sh bootstrap`; P0-T6 scripts/check.sh calls it):
//   vacuum lint --no-update-check -b -q -d -n info -r tools/vacuum/ruleset.mjs api/public/v1/openapi.yaml
//
// Base: every built-in vacuum OpenAPI rule plus the OWASP rules (same as `vacuum lint --hard-mode`).
// Each built-in rule switched off below has its reason next to it. Project conventions are encoded
// as qwq-* rules; conventions that need a running server are left to the P0-T6 contract tests.
import { createRulesetFunction } from '@stoplight/spectral-core';
import { oas3_1 } from '@stoplight/spectral-formats';

const METHODS = ['get', 'put', 'post', 'delete', 'patch', 'options', 'head', 'trace'];
const MUTATING = new Set(['post', 'put', 'patch', 'delete']);
const AGENT_PREFIX = '/api/v1/agent/';
const AGENT_TOOLS = ['find_actions', 'describe_action', 'read', 'plan', 'execute', 'wait', 'cancel'];
// Unauthenticated endpoints. Adding one requires editing this list (reviewed change).
const PUBLIC_OPS = new Set([
  'get /healthz', 'get /readyz', 'get /api/v1/setup', 'post /api/v1/setup',
  'post /api/v1/sessions', 'post /api/v1/sessions/mfa', 'post /api/v1/enrollments',
]);
const ROOT_PATHS = new Set(['/healthz', '/readyz']);
const SNAKE = /^[a-z][a-z0-9]*(_[a-z0-9]+)*$/;
const KEBAB = /^[a-z][a-z0-9]*(-[a-z0-9]+)*$/;

function* operations(doc) {
  for (const [path, item] of Object.entries(doc.paths || {})) {
    if (!item || typeof item !== 'object') continue;
    for (const method of METHODS) {
      if (item[method]) yield { path, method, op: item[method], item, at: ['paths', path, method] };
    }
  }
}
function params(item, op) {
  return [...(item.parameters || []), ...(op.parameters || [])].filter(p => p && typeof p === 'object');
}
function findParam(item, op, where, name) {
  return params(item, op).find(p => p.in === where && String(p.name).toLowerCase() === name.toLowerCase());
}
function jsonSchemaOf(content) {
  return content && content['application/json'] && content['application/json'].schema;
}
function propsOf(schema) {
  // Merge properties and required across allOf (resolved document).
  const out = { properties: {}, required: [] };
  const visit = s => {
    if (!s || typeof s !== 'object') return;
    Object.assign(out.properties, s.properties || {});
    out.required.push(...(s.required || []));
    (s.allOf || []).forEach(visit);
  };
  visit(schema);
  return out;
}
function rule(description, fn, severity = 'error') {
  return {
    description, severity, given: '$', formats: [oas3_1],
    then: { function: createRulesetFunction({ input: null, options: null }, fn) },
  };
}
const rules = {};

// ---- Idempotency (ARCH §4.1): every mutating operation declares its class, and the header matches it.
rules['qwq-idempotency-declared'] = rule(
  'Every POST/PUT/PATCH/DELETE declares x-qwq-idempotency (required | conditional | exempt + reason).',
  doc => {
    const out = [];
    for (const { method, op, at } of operations(doc)) {
      if (!MUTATING.has(method)) continue;
      const v = op['x-qwq-idempotency'];
      if (!['required', 'conditional', 'exempt'].includes(v)) {
        out.push({ message: 'x-qwq-idempotency must be required, conditional or exempt', path: at });
      } else if (v === 'exempt' && !(typeof op['x-qwq-idempotency-reason'] === 'string' && op['x-qwq-idempotency-reason'].length >= 10)) {
        out.push({ message: 'exempt operations need x-qwq-idempotency-reason', path: at });
      }
    }
    return out;
  });
rules['qwq-idempotency-header'] = rule(
  'The Idempotency-Key header matches x-qwq-idempotency: required -> required header, conditional -> optional header, exempt -> no header.',
  doc => {
    const out = [];
    for (const { method, op, item, at } of operations(doc)) {
      const p = findParam(item, op, 'header', 'Idempotency-Key');
      const v = MUTATING.has(method) ? op['x-qwq-idempotency'] : 'none';
      if ((v === 'required' && !(p && p.required === true)) ||
          (v === 'conditional' && !(p && p.required !== true)) ||
          ((v === 'exempt' || v === 'none') && p)) {
        out.push({ message: `Idempotency-Key header does not match x-qwq-idempotency=${v}`, path: at });
      }
    }
    return out;
  });

// ---- Errors (ARCH §4.1, RFC 9457): every operation has a default problem+json response and
// every 4xx/5xx response is application/problem+json only.
rules['qwq-problem-responses'] = rule(
  'Every operation has a default response; all error responses use application/problem+json with the Problem schema.',
  doc => {
    const out = [];
    for (const { op, at } of operations(doc)) {
      const responses = op.responses || {};
      if (!responses.default) out.push({ message: 'missing default (Problem) response', path: [...at, 'responses'] });
      for (const [code, r] of Object.entries(responses)) {
        if (!(code === 'default' || /^[45]/.test(code))) continue;
        const types = Object.keys((r && r.content) || {});
        const schema = types.length === 1 && r.content['application/problem+json'] && r.content['application/problem+json'].schema;
        const ok = schema && schema.properties && schema.properties.code && schema.properties.request_id && schema.properties.violations;
        if (!ok) out.push({ message: `response ${code} must be application/problem+json with the Problem schema`, path: [...at, 'responses', code] });
      }
    }
    return out;
  });
// ---- Security (ADR-0004 D4, D6, D8; ARCH §4.1.1)
const schemesOf = op => (op.security || []).map(req => Object.keys(req || {}).sort().join('+'));
rules['qwq-security-explicit'] = rule(
  'Every operation lists its security; only the allow-listed public endpoints may use security: [].',
  doc => {
    const out = [];
    for (const { path, method, op, at } of operations(doc)) {
      const key = `${method} ${path}`;
      if (!Array.isArray(op.security)) out.push({ message: 'operation must declare security explicitly', path: at });
      else if (op.security.length === 0 && !PUBLIC_OPS.has(key)) out.push({ message: `${key} is not an allow-listed public endpoint`, path: at });
      else if (op.security.length > 0 && PUBLIC_OPS.has(key)) out.push({ message: `${key} is listed as public but declares security`, path: at });
    }
    return out;
  });
rules['qwq-security-agent-delegation-only'] = rule(
  '/api/v1/agent/* accepts only the delegation token; the delegation token is accepted nowhere else.',
  doc => {
    const out = [];
    for (const { path, op, at } of operations(doc)) {
      const s = schemesOf(op);
      const isAgent = path.startsWith(AGENT_PREFIX);
      if (isAgent && !(s.length === 1 && s[0] === 'delegationToken')) out.push({ message: 'agent tools must use exactly [{delegationToken: []}]', path: [...at, 'security'] });
      if (!isAgent && s.some(x => x.split('+').includes('delegationToken'))) out.push({ message: 'delegationToken is only allowed on /api/v1/agent/*', path: [...at, 'security'] });
    }
    return out;
  });
rules['qwq-security-csrf'] = rule(
  'Non-GET operations pair sessionCookie with csrfToken in the same requirement; GET never asks for csrfToken.',
  doc => {
    const out = [];
    for (const { method, op, at } of operations(doc)) {
      for (const s of schemesOf(op)) {
        const parts = s.split('+');
        if (method === 'get' && parts.includes('csrfToken')) out.push({ message: 'GET must not require csrfToken', path: [...at, 'security'] });
        if (method !== 'get' && parts.includes('sessionCookie') && !parts.includes('csrfToken')) out.push({ message: 'sessionCookie on a non-GET operation must be combined with csrfToken', path: [...at, 'security'] });
        if (parts.includes('csrfToken') && !parts.includes('sessionCookie')) out.push({ message: 'csrfToken only makes sense together with sessionCookie', path: [...at, 'security'] });
      }
    }
    return out;
  });
rules['qwq-security-human-only'] = rule(
  'Approval decisions, delegation management, enrollment links and AI-provider management accept only a human browser session (ADR-0004 D6, ADR-0017).',
  doc => {
    const out = [];
    for (const { path, method, op, at } of operations(doc)) {
      const humanOnly = /^\/api\/v1\/approvals\/\{[^}]+\}\/decision$/.test(path) || path.startsWith('/api/v1/delegations') ||
        /^\/api\/v1\/users\/\{[^}]+\}\/enrollment-token$/.test(path) ||
        (path.startsWith('/api/v1/ai/providers') && method !== 'get');
      if (!humanOnly) continue;
      const s = schemesOf(op);
      const want = method === 'get' ? 'sessionCookie' : 'csrfToken+sessionCookie';
      if (!(s.length === 1 && s[0] === want)) out.push({ message: `must accept exactly ${want}`, path: [...at, 'security'] });
    }
    return out;
  });
// ---- Action catalog (ADR-0004 D1, D5): host mutations are registered with manifest-shaped metadata.
const ACTION_KEYS = ['id', 'summary', 'effect', 'risk', 'mode', 'idempotent', 'plannable', 'undo', 'ui_route', 'permission', 'timeout_ms'];
const ACTION_REQUIRED = ['id', 'summary', 'effect', 'risk', 'mode', 'idempotent', 'plannable', 'permission', 'timeout_ms'];
rules['qwq-action-registered'] = rule(
  'Every mutating operation outside /api/v1/agent/ has exactly one of x-qwq-action, x-qwq-action-from: manifest, or x-qwq-action-exempt (reason).',
  doc => {
    const out = [];
    for (const { path, method, op, at } of operations(doc)) {
      const n = ['x-qwq-action', 'x-qwq-action-from', 'x-qwq-action-exempt'].filter(k => op[k] !== undefined).length;
      if (!MUTATING.has(method) || path.startsWith(AGENT_PREFIX)) {
        if (n > 0) out.push({ message: 'only mutating REST operations carry action registration extensions', path: at });
        continue;
      }
      if (n !== 1) out.push({ message: 'needs exactly one of x-qwq-action, x-qwq-action-from, x-qwq-action-exempt', path: at });
      else if (op['x-qwq-action-from'] !== undefined && op['x-qwq-action-from'] !== 'manifest') out.push({ message: 'x-qwq-action-from must be "manifest"', path: at });
      else if (op['x-qwq-action-exempt'] !== undefined && !(typeof op['x-qwq-action-exempt'] === 'string' && op['x-qwq-action-exempt'].length >= 10)) out.push({ message: 'x-qwq-action-exempt must state the reason', path: at });
    }
    return out;
  });
rules['qwq-action-shape'] = rule(
  'x-qwq-action has the manifest operation fields and constraints (manifest.schema.json operations).',
  doc => {
    const out = [];
    const ids = new Map();
    const all = [...operations(doc)].filter(o => o.op['x-qwq-action']);
    for (const { op, at } of all) {
      const a = op['x-qwq-action'];
      const bad = m => out.push({ message: `x-qwq-action: ${m}`, path: [...at, 'x-qwq-action'] });
      if (typeof a !== 'object') { bad('must be an object'); continue; }
      for (const k of Object.keys(a)) if (!ACTION_KEYS.includes(k)) bad(`unknown field ${k}`);
      for (const k of ACTION_REQUIRED) if (a[k] === undefined) bad(`missing ${k}`);
      if (!/^host\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/.test(a.id || '')) bad('id must be host.<resource>.<verb>');
      if (ids.has(a.id)) bad(`duplicate id ${a.id}`); else ids.set(a.id, true);
      if (typeof a.summary !== 'string' || a.summary.length < 1 || a.summary.length > 120) bad('summary must be 1-120 characters');
      if (!['read', 'write', 'destructive'].includes(a.effect)) bad('effect must be read|write|destructive');
      if (!['low', 'medium', 'high'].includes(a.risk)) bad('risk must be low|medium|high');
      if (!['invoke', 'job'].includes(a.mode)) bad('mode must be invoke|job');
      if (typeof a.idempotent !== 'boolean' || typeof a.plannable !== 'boolean') bad('idempotent and plannable must be booleans');
      if (a.effect === 'destructive' && a.risk !== 'high') bad('destructive actions must have risk high');
      if (a.effect === 'read' && a.idempotent !== true) bad('read actions must be idempotent');
      if (a.ui_route !== undefined && !/^\/[a-z0-9._/:-]*$/.test(a.ui_route)) bad('ui_route must match the manifest ui_path pattern');
      if (!/^[a-z][a-z0-9_.-]*:[a-z][a-z0-9_]*$/.test(a.permission || '')) bad('permission must be <resource>:<verb>');
      if (!(Number.isInteger(a.timeout_ms) && a.timeout_ms >= 1 && a.timeout_ms <= 300000)) bad('timeout_ms must be 1..300000');
    }
    for (const { op, at } of all) {
      const u = op['x-qwq-action'].undo;
      if (u !== undefined && !ids.has(u)) out.push({ message: `x-qwq-action: undo ${u} is not a host action`, path: [...at, 'x-qwq-action'] });
    }
    return out;
  });
// ---- Operation responses (ADR-0004 D1; ARCH §4.1): 200 = finished outcome, 202 = Operation + Location.
const looksLikeOperation = s => { const p = propsOf(s).properties; return !!(p.operation_id && p.status); };
rules['qwq-operation-responses'] = rule(
  'Every 202 has a Location header and an Operation body; action routes return 202, and invoke-mode actions also 200 with an outcome.',
  doc => {
    const out = [];
    for (const { op, at } of operations(doc)) {
      const r = op.responses || {};
      if (r['202']) {
        const headers = Object.keys(r['202'].headers || {}).map(h => h.toLowerCase());
        if (!headers.includes('location')) out.push({ message: '202 needs a Location header', path: [...at, 'responses', '202'] });
        if (!looksLikeOperation(jsonSchemaOf(r['202'].content))) out.push({ message: '202 body must be an Operation', path: [...at, 'responses', '202'] });
      }
      const action = op['x-qwq-action'];
      const fromManifest = op['x-qwq-action-from'] === 'manifest';
      if (!action && !fromManifest) continue;
      if (!r['202']) out.push({ message: 'action routes must document 202 (job or approval)', path: [...at, 'responses'] });
      const needs200 = fromManifest || action.mode === 'invoke';
      if (needs200 && !(r['200'] && looksLikeOperation(jsonSchemaOf(r['200'].content)))) out.push({ message: 'invoke-mode actions need 200 with an OperationOutcome', path: [...at, 'responses'] });
      if (!needs200 && r['200']) out.push({ message: 'job-mode actions never finish synchronously; remove 200', path: [...at, 'responses', '200'] });
    }
    return out;
  });

// ---- Optimistic concurrency (ADR-0004 D2)
rules['qwq-expected-revision'] = rule(
  'PATCH bodies require expected_revision; DELETE of a resource requires the expected_revision query parameter.',
  doc => {
    const out = [];
    for (const { method, op, item, at } of operations(doc)) {
      if (method === 'patch') {
        const s = propsOf(jsonSchemaOf(op.requestBody && op.requestBody.content));
        if (!(s.properties.expected_revision && s.required.includes('expected_revision'))) out.push({ message: 'PATCH body must require expected_revision', path: [...at, 'requestBody'] });
      }
      if (method === 'delete' && op['x-qwq-idempotency'] === 'required') {
        const p = findParam(item, op, 'query', 'expected_revision');
        if (!(p && p.required === true)) out.push({ message: 'DELETE must require the expected_revision query parameter', path: at });
        if (op.requestBody) out.push({ message: 'DELETE must not have a request body', path: [...at, 'requestBody'] });
      }
    }
    return out;
  });

// ---- Request bodies are closed so that misspelled arguments fail instead of being ignored.
// The package upload is the only multipart operation: its form schema is closed too, but it has
// no application/json representation for the rule above to inspect.
const MULTIPART_UPLOADS = new Set(['/api/v1/plugin-packages']);
rules['qwq-request-closed'] = rule(
  'Every JSON request body schema sets additionalProperties: false; multipart uploads use one closed form schema.',
  doc => {
    const out = [];
    for (const { path, op, at } of operations(doc)) {
      const content = op.requestBody && op.requestBody.content;
      if (!op.requestBody) continue;
      const json = jsonSchemaOf(content);
      if (json) {
        if (!(json.type === 'object' && json.additionalProperties === false)) out.push({ message: 'request body schema must be an object with additionalProperties: false', path: [...at, 'requestBody'] });
        continue;
      }
      const form = content && content['multipart/form-data'] && content['multipart/form-data'].schema;
      if (!MULTIPART_UPLOADS.has(path) || !(form && form.type === 'object' && form.additionalProperties === false)) {
        out.push({ message: 'request body must be a closed JSON object, or a closed multipart form on the package upload route', path: [...at, 'requestBody'] });
      }
    }
    return out;
  });
// ---- Reads and deletes carry no body (the built-in no-request-body rule).
// ---- Naming: snake_case JSON (same as proto JSON names and the manifest); kebab-case paths except
// the agent tool segments, which equal the MCP tool names.
rules['qwq-snake-case-properties'] = rule(
  'Schema property names are snake_case.',
  doc => {
    const out = [];
    for (const [name, schema] of Object.entries((doc.components && doc.components.schemas) || {})) {
      const seen = new Set();
      const walk = (s, at) => {
        if (!s || typeof s !== 'object' || seen.has(s)) return;
        seen.add(s);
        for (const [k, v] of Object.entries(s.properties || {})) {
          if (!SNAKE.test(k)) out.push({ message: `property ${k} is not snake_case`, path: [...at, 'properties', k] });
          walk(v, [...at, 'properties', k]);
        }
        for (const key of ['items', 'additionalProperties']) if (typeof s[key] === 'object') walk(s[key], [...at, key]);
        for (const key of ['allOf', 'anyOf', 'oneOf']) (s[key] || []).forEach((x, i) => walk(x, [...at, key, i]));
      };
      walk(schema, ['components', 'schemas', name]);
    }
    return out;
  });
rules['qwq-path-segments'] = rule(
  'Paths live under /api/v1/ (except /healthz, /readyz); static segments are kebab-case, agent tools are the 7 snake_case tool names.',
  doc => {
    const out = [];
    for (const path of Object.keys(doc.paths || {})) {
      const at = ['paths', path];
      if (!ROOT_PATHS.has(path) && !path.startsWith('/api/v1/')) out.push({ message: 'path must start with /api/v1/', path: at });
      if (path.startsWith(AGENT_PREFIX)) {
        const tool = path.slice(AGENT_PREFIX.length);
        if (!AGENT_TOOLS.includes(tool)) out.push({ message: `unknown agent tool ${tool}; the tool set is fixed (ADR-0004 D8)`, path: at });
        continue;
      }
      for (const seg of path.split('/').slice(1)) {
        if (/^\{[a-z][a-z0-9_]*\}$/.test(seg)) continue;
        if (!KEBAB.test(seg)) out.push({ message: `segment ${seg} must be kebab-case (parameters snake_case)`, path: at });
      }
    }
    for (const tool of AGENT_TOOLS) if (!doc.paths[AGENT_PREFIX + tool]) out.push({ message: `agent tool ${tool} is missing`, path: ['paths'] });
    return out;
  });
rules['qwq-agent-mcp'] = rule(
  'Each agent tool is a POST with x-qwq-mcp {tool = path segment, all four MCP annotation hints}; read-only tools are idempotency-exempt.',
  doc => {
    const out = [];
    for (const { path, method, op, at } of operations(doc)) {
      if (!path.startsWith(AGENT_PREFIX)) continue;
      if (method !== 'post') { out.push({ message: 'agent tools are POST with JSON parameters', path: at }); continue; }
      const m = op['x-qwq-mcp'];
      const tool = path.slice(AGENT_PREFIX.length);
      if (!m || m.tool !== tool) { out.push({ message: `x-qwq-mcp.tool must be ${tool}`, path: at }); continue; }
      const a = m.annotations || {};
      for (const h of ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint']) if (typeof a[h] !== 'boolean') out.push({ message: `x-qwq-mcp.annotations.${h} must be a boolean`, path: [...at, 'x-qwq-mcp'] });
      if (a.readOnlyHint === true && a.destructiveHint === true) out.push({ message: 'a read-only tool cannot be destructive', path: [...at, 'x-qwq-mcp'] });
      if ((a.readOnlyHint === true) !== (op['x-qwq-idempotency'] === 'exempt')) out.push({ message: 'read-only tools are idempotency-exempt and only they', path: [...at, 'x-qwq-mcp'] });
      const s = jsonSchemaOf(op.requestBody && op.requestBody.content);
      if (!(op.requestBody && op.requestBody.required === true && s && s.type === 'object')) out.push({ message: 'tool parameters must be a required JSON object (function-calling schema)', path: at });
      if (s && (s.oneOf || s.anyOf || s.allOf)) out.push({ message: 'tool parameter schema must not use oneOf/anyOf/allOf at the top level', path: [...at, 'requestBody'] });
    }
    return out;
  });
// ---- Untrusted text (ADR-0004 D10, ARCH §5.5): pinned locations must keep the marker.
const UNTRUSTED = {
  Problem: ['detail', 'plugin_code'], FieldViolation: ['message'], OperationProgress: ['message'],
  Operation: ['result'], OperationOutcome: ['result'], PlannedChange: ['before', 'after'],
  Approval: ['plugin_preview'], Node: ['reported'], Plugin: ['name', 'summary', 'publisher_id'],
  ActionMeta: ['summary'], ActionSummary: ['summary'], Event: ['payload'],
  ActionDescription: ['args_schema', 'result_schema', 'examples', 'docs'], ReadResponse: ['values', 'items'],
};
rules['qwq-untrusted-markers'] = rule(
  'Fields carrying plugin, node or log text keep x-qwq-untrusted: true; the marker is never anything but true.',
  doc => {
    const out = [];
    const schemas = (doc.components && doc.components.schemas) || {};
    for (const [name, fields] of Object.entries(UNTRUSTED)) {
      for (const f of fields) {
        const p = schemas[name] && schemas[name].properties && schemas[name].properties[f];
        if (!p || p['x-qwq-untrusted'] !== true) out.push({ message: `${name}.${f} must be marked x-qwq-untrusted: true`, path: ['components', 'schemas', name] });
      }
    }
    const seen = new Set();
    const walk = (v, at) => {
      if (!v || typeof v !== 'object' || seen.has(v)) return;
      seen.add(v);
      if ('x-qwq-untrusted' in v && v['x-qwq-untrusted'] !== true) out.push({ message: 'x-qwq-untrusted must be true when present', path: at });
      for (const [k, c] of Object.entries(v)) walk(c, [...at, k]);
    };
    walk(schemas, ['components', 'schemas']);
    return out;
  });

// ---- Enums fixed by ADRs.
const sameSet = (a, b) => a.length === b.length && a.every(x => b.includes(x));
rules['qwq-fixed-enums'] = rule(
  'OperationStatus is exactly the ADR-0004 D7 states, ActorKind the D4 kinds, and ProblemCode contains the required codes.',
  doc => {
    const s = (doc.components && doc.components.schemas) || {};
    const out = [];
    const status = ['PENDING', 'AWAITING_APPROVAL', 'APPROVED', 'REJECTED', 'EXPIRED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELED'];
    if (!sameSet((s.OperationStatus && s.OperationStatus.enum) || [], status)) out.push({ message: 'OperationStatus must be exactly the ADR-0004 D7 states', path: ['components', 'schemas', 'OperationStatus'] });
    if (!sameSet((s.ActorKind && s.ActorKind.enum) || [], ['human', 'ai_agent', 'service', 'system'])) out.push({ message: 'ActorKind must be human|ai_agent|service|system', path: ['components', 'schemas', 'ActorKind'] });
    const required = ['VALIDATION_FAILED', 'UNAUTHENTICATED', 'PERMISSION_DENIED', 'NOT_FOUND', 'REVISION_CONFLICT', 'PRECONDITION_FAILED',
      'IDEMPOTENCY_KEY_REUSED', 'IDEMPOTENCY_IN_PROGRESS', 'RATE_LIMITED', 'PAYLOAD_TOO_LARGE', 'NODE_OFFLINE', 'APPROVAL_REQUIRED', 'INTERNAL'];
    const codes = (s.ProblemCode && s.ProblemCode.enum) || [];
    for (const c of required) if (!codes.includes(c)) out.push({ message: `ProblemCode is missing ${c}`, path: ['components', 'schemas', 'ProblemCode'] });
    for (const c of codes) if (!(s.ProblemCode.description || '').includes('`' + c + '`')) out.push({ message: `ProblemCode ${c} has no row in the status mapping table`, path: ['components', 'schemas', 'ProblemCode'] });
    return out;
  });
// ---- Reads (ARCH §4.1): lists paginate and support fields + since_revision; resources support fields.
rules['qwq-read-parameters'] = rule(
  'GET lists (responses with next_cursor) take cursor, limit, fields and since_revision; GET resources with a revision take fields.',
  doc => {
    const out = [];
    for (const { method, op, item, at } of operations(doc)) {
      if (method !== 'get') continue;
      const ok = op.responses && op.responses['200'];
      const body = propsOf(jsonSchemaOf(ok && ok.content)).properties;
      const need = body.next_cursor ? ['cursor', 'limit', 'fields', 'since_revision'] : body.revision ? ['fields'] : [];
      for (const n of need) if (!findParam(item, op, 'query', n)) out.push({ message: `missing query parameter ${n}`, path: at });
    }
    return out;
  });

// ---- Limits: root x-qwq-limits is complete, overrides only use known names, plugin payload
// routes declare the 4 MiB limit, and schema bounds agree with the declared numbers.
const LIMIT_KEYS = ['max_body_bytes', 'max_plugin_body_bytes', 'max_package_bytes', 'max_json_depth', 'list_limit_default', 'list_limit_max', 'fields_max',
  'violations_max', 'idempotency_ttl_seconds', 'idempotency_keys_per_principal', 'plan_ttl_seconds', 'approval_ttl_seconds',
  'sse_heartbeat_seconds', 'sse_topics_max', 'sse_buffer_events', 'agent_find_actions_default', 'agent_find_actions_max',
  'agent_read_items_default', 'agent_read_items_max', 'agent_read_response_bytes', 'agent_wait_timeout_default_seconds',
  'agent_wait_timeout_max_seconds', 'agent_concurrent_waits_per_delegation'];
rules['qwq-limits'] = rule(
  'x-qwq-limits is complete and consistent with the schemas that enforce it.',
  doc => {
    const out = [];
    const L = doc['x-qwq-limits'] || {};
    const S = (doc.components && doc.components.schemas) || {};
    const P = (doc.components && doc.components.parameters) || {};
    for (const k of LIMIT_KEYS) if (!(Number.isInteger(L[k]) && L[k] > 0)) out.push({ message: `x-qwq-limits.${k} must be a positive integer`, path: ['x-qwq-limits'] });
    for (const k of Object.keys(L)) if (!LIMIT_KEYS.includes(k)) out.push({ message: `unknown limit ${k}`, path: ['x-qwq-limits'] });
    if (!(L.sse_heartbeat_seconds < 30)) out.push({ message: 'SSE heartbeat must be below 30 s', path: ['x-qwq-limits'] });
    if (!(L.agent_wait_timeout_max_seconds <= 60)) out.push({ message: 'wait timeout must be at most 60 s', path: ['x-qwq-limits'] });
    for (const { op, at } of operations(doc)) {
      const o = op['x-qwq-limits'];
      if (o) for (const k of Object.keys(o)) if (!LIMIT_KEYS.includes(k)) out.push({ message: `unknown limit override ${k}`, path: [...at, 'x-qwq-limits'] });
      const body = propsOf(jsonSchemaOf(op.requestBody && op.requestBody.content)).properties;
      const carriesPluginPayload = body.payload || body.args;
      if (carriesPluginPayload && !(o && o.max_body_bytes === L.max_plugin_body_bytes)) out.push({ message: 'routes carrying plugin payloads set x-qwq-limits.max_body_bytes = max_plugin_body_bytes', path: at });
    }
    const eq = (actual, want, where, path) => { if (actual !== want) out.push({ message: `${where} is ${actual}, x-qwq-limits says ${want}`, path }); };
    const lim = P.Limit && P.Limit.schema;
    if (lim) { eq(lim.maximum, L.list_limit_max, 'limit maximum', ['components', 'parameters', 'Limit']); eq(lim.default, L.list_limit_default, 'limit default', ['components', 'parameters', 'Limit']); }
    const fa = S.FindActionsRequest && S.FindActionsRequest.properties.limit;
    if (fa) { eq(fa.maximum, L.agent_find_actions_max, 'find_actions limit maximum', ['components', 'schemas', 'FindActionsRequest']); eq(fa.default, L.agent_find_actions_default, 'find_actions limit default', ['components', 'schemas', 'FindActionsRequest']); }
    const rd = S.ReadRequest && S.ReadRequest.properties.limit;
    if (rd) { eq(rd.maximum, L.agent_read_items_max, 'read limit maximum', ['components', 'schemas', 'ReadRequest']); eq(rd.default, L.agent_read_items_default, 'read limit default', ['components', 'schemas', 'ReadRequest']); }
    const wt = S.WaitRequest && S.WaitRequest.properties.timeout_seconds;
    if (wt) { eq(wt.maximum, L.agent_wait_timeout_max_seconds, 'wait timeout maximum', ['components', 'schemas', 'WaitRequest']); eq(wt.default, L.agent_wait_timeout_default_seconds, 'wait timeout default', ['components', 'schemas', 'WaitRequest']); }
    const pv = S.Problem && S.Problem.properties.violations;
    if (pv) eq(pv.maxItems, L.violations_max, 'Problem.violations maxItems', ['components', 'schemas', 'Problem']);
    return out;
  });
// ---- Built-in rules switched off, each with its reason.
const OFF = {
  // The wire format is snake_case, the same as proto JSON names and manifest.schema.json;
  // replaced by qwq-snake-case-properties.
  'camel-case-properties': false,
  // Agent tool paths are the MCP tool names (find_actions, describe_action) so the HTTP route,
  // the tool definition and ADR-0004 D8 use one name; replaced by qwq-path-segments.
  'paths-kebab-case': false,
  // Examples live in the P0-T6 contract-test fixtures, which are validated against the schemas;
  // inline examples would be a second, unvalidated copy. Selected primitives carry `examples`.
  'oas3-missing-example': false,
  // Request and response DTOs share fields on purpose (display_name, reason, list wrappers);
  // the same field gets the same wording.
  'description-duplication': false,
  // `result`, `before`, `after` hold arbitrary JSON defined by each action's own schema; a type
  // list would only restate "any JSON value" and confuses the Go and TS generators.
  'oas-missing-type': false,
  // Tags are ordered along the request flow (setup -> sessions -> ... -> agent), not alphabetically.
  'openapi-tags-alphabetical': false,
  // Rate limits are signalled by 429 RATE_LIMITED + Retry-After (checked by owasp-rate-limit-retry-after).
  // The RateLimit-* response headers are still an IETF draft; adopt them in a later minor version.
  'owasp-rate-limit': false,
  // Free text (descriptions, messages, labels) cannot have a pattern or enum; every string still has
  // maxLength (owasp-string-limit stays on) and identifiers do have patterns.
  'owasp-string-restricted': false,
  // Every operation has a `default` Problem response that covers 500 (enforced by qwq-problem-responses);
  // listing 500 on each of 43 operations adds no information.
  'owasp-define-error-responses-500': false,
  // These three flag every operation with `security: []`. The project rule qwq-security-explicit is
  // stricter: it allows exactly the probe/setup/login/enrollment endpoints in PUBLIC_OPS and nothing else.
  'owasp-protection-global-safe': false,
  'owasp-protection-global-unsafe': false,
  'owasp-protection-global-unsafe-strict': false,
  // `args` and `payload` are open on purpose: they are validated against the target action's own
  // schema (plugin manifest or host route). Top-level request bodies are closed (qwq-request-closed).
  'owasp-no-additionalProperties': false,
  // No public contact address exists yet (GitHub organization not registered, IMPLEMENTATION-PLAN
  // Q12); add a security contact e-mail before the first public release and re-enable.
  'contact-properties': false,
};

export default {
  extends: [['vacuum:oas', 'all'], ['vacuum:owasp', 'all']],
  rules: { ...OFF, ...rules },
};
