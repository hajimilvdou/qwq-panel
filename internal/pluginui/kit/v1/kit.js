// SPDX-License-Identifier: AGPL-3.0-only
// kit/src/bridge.ts
var e = 1, t = class extends Error {
	code;
	status;
	violations;
	constructor(e, t, n, r) {
		super(t), this.name = "PluginHostError", this.code = e, this.status = n, this.violations = r;
	}
}, n = class extends t {
	constructor(e) {
		super(e.code || "INTERNAL", e.detail || e.code || "操作失败", e.status, e.violations), this.name = "PluginInvokeError";
	}
};
function r(e) {
	let t = e && typeof e == "object" ? e : null, r = String(t?.status || "SUCCEEDED").toUpperCase(), i = t?.operation_id || "";
	if (r === "AWAITING_APPROVAL" || t?.approval_id) return {
		kind: "awaiting_approval",
		operationId: i,
		approvalId: t?.approval_id || ""
	};
	if (r === "RUNNING" || r === "PENDING") return {
		kind: "running",
		operationId: i
	};
	let a = r === "FAILED" || r === "REJECTED" || r === "CANCELED" || r === "EXPIRED", o = typeof t?.error == "string" && t.error.trim().length > 0 || t?.error !== void 0 && t?.error !== null && typeof t.error == "object";
	if (a || o) {
		if (typeof t?.error == "string" && t.error.trim().length > 0) {
			let e = t.error.trim();
			throw new n({
				code: e,
				detail: e
			});
		}
		if (t?.error && typeof t.error == "object") {
			let e = t.error, i = e.code || (a ? r : "OPERATION_FAILED");
			throw new n({
				code: i,
				detail: e.detail || e.message || i,
				status: e.status,
				violations: e.violations
			});
		}
		throw new n({
			code: r,
			detail: `操作未完成 (${r})`
		});
	}
	return {
		kind: "done",
		operationId: i,
		result: t && "result" in t && t.result !== void 0 ? t.result : e
	};
}
var i = null;
function a(e) {
	if (typeof document > "u" || typeof CSSStyleSheet > "u" || !("adoptedStyleSheets" in document)) return !1;
	try {
		i || (i = new CSSStyleSheet(), document.adoptedStyleSheets = [...document.adoptedStyleSheets, i]);
		let t = [];
		for (let [n, r] of Object.entries(e)) typeof r == "string" && /^--[a-zA-Z0-9_-]+$/.test(n) && !/[{};\\]/.test(r) && t.push(`${n}: ${r};`);
		return i.replaceSync(t.length > 0 ? `:root { ${t.join(" ")} }` : ""), !0;
	} catch {
		return !1;
	}
}
function o(e, t) {
	let n = t ?? (typeof document < "u" ? document.documentElement : null);
	n && (n.dataset.theme = e.theme, n.dataset.motion = e.motion, n.dataset.density = e.density, e.tokens && Object.keys(e.tokens).length > 0 && a(e.tokens));
}
function s(e) {
	let t = new URLSearchParams(e.startsWith("#") ? e.slice(1) : e), n = t.get("theme") === "dark" ? "dark" : "light", r = t.get("motion"), i = r === "reduced" || r === "off" ? r : "full", a = t.get("density") === "compact" ? "compact" : "comfortable", o = t.get("path") || t.get("route") || "/";
	return {
		settings: {
			theme: n,
			motion: i,
			density: a,
			tokens: {},
			visible: !0
		},
		route: o
	};
}
function c(e = {}) {
	let n = e.win ?? window, i = e.parent ?? window.parent, a = s(e.hash ?? (typeof location < "u" ? location.hash : ""));
	return o(a.settings), new Promise((s, c) => {
		let l = null, u = 0, d = !1, f = a.settings, p = a.route, m = "", h = /* @__PURE__ */ new Map(), g = /* @__PURE__ */ new Set(), _ = /* @__PURE__ */ new Set(), v = /* @__PURE__ */ new Set(), y = setTimeout(() => {
			n.removeEventListener("message", S), c(new t("TIMEOUT", "Plugin bridge handshake timed out"));
		}, e.timeoutMs ?? 6e3), b = (e, n) => {
			if (d || !l) return Promise.reject(new t("UNAVAILABLE", "Plugin bridge is not connected"));
			if (n?.signal?.aborted) return Promise.reject(new t("ABORTED", "Request aborted"));
			let r = `kit_${++u}`;
			return new Promise((i, a) => {
				let o, s = () => {
					o !== void 0 && clearTimeout(o), n?.signal?.removeEventListener("abort", c);
				}, c = () => {
					h.delete(r) && (s(), a(new t("ABORTED", "Request aborted")));
				};
				n?.signal?.addEventListener("abort", c, { once: !0 }), n?.timeoutMs && n.timeoutMs > 0 && (o = setTimeout(() => {
					h.delete(r) && (s(), a(new t("TIMEOUT", "Request timed out")));
				}, n.timeoutMs)), h.set(r, {
					resolve: (e) => {
						s(), i(e);
					},
					reject: (e) => {
						s(), a(e);
					},
					timer: o
				});
				try {
					l.postMessage({
						...e,
						id: r
					});
				} catch (e) {
					h.delete(r) && (s(), a(new t("SERIALIZE_ERROR", e instanceof Error ? e.message : "Failed to post frame")));
				}
			});
		}, x = {
			get settings() {
				return f;
			},
			get route() {
				return p;
			},
			get publicOrigin() {
				return m;
			},
			invoke(e, t = {}, n) {
				let r = {
					t: "api.invoke",
					operation: e,
					payload: t
				};
				return n?.subject && (r.subject = n.subject), n?.expectedRevision && (r.expected_revision = n.expectedRevision), b(r, {
					signal: n?.signal,
					timeoutMs: n?.timeoutMs
				});
			},
			invokeOutcome(e, t = {}, n) {
				return x.invoke(e, t, n).then((e) => r(e));
			},
			confirm(e) {
				return b({
					t: "ui.confirm",
					title: e.title,
					body: e.body,
					confirm_label: e.confirmLabel,
					danger: !!e.danger
				}, { timeoutMs: 12e4 }).then((e) => !!e?.confirmed);
			},
			copyText(e, t = "已复制到剪贴板") {
				return b({
					t: "ui.copy",
					text: e,
					label: t
				}, { timeoutMs: 5e3 }).then(() => void 0);
			},
			buildPublicURL(e) {
				let t = e.startsWith("/") ? e : `/${e}`;
				return m ? `${m}${t}` : t;
			},
			subscribe(e, t) {
				let n = [...e], r = {
					subjects: n,
					fn: t
				};
				return v.add(r), !d && l && n.length > 0 && l.postMessage({
					t: "api.subscribe",
					subjects: n
				}), () => {
					if (v.delete(r), !d && l && n.length > 0) {
						let e = n.filter((e) => {
							for (let t of v) if (t.subjects.includes(e)) return !1;
							return !0;
						});
						e.length > 0 && l.postMessage({
							t: "events.unsubscribe",
							subjects: e
						});
					}
				};
			},
			resize(e) {
				!d && l && Number.isFinite(e) && l.postMessage({
					t: "ui.resize",
					height: Math.round(e)
				});
			},
			toast(e) {
				!d && l && e.trim() && l.postMessage({
					t: "ui.toast",
					text: e
				});
			},
			navigate(e) {
				!d && l && e.startsWith("/") && l.postMessage({
					t: "ui.navigate",
					path: e
				});
			},
			onSettings(e) {
				return g.add(e), () => g.delete(e);
			},
			onRoute(e) {
				return _.add(e), () => _.delete(e);
			},
			dispose() {
				d = !0, clearTimeout(y), n.removeEventListener("message", S), l &&= (l.onmessage = null, l.close(), null);
				for (let [, e] of h) e.timer !== void 0 && clearTimeout(e.timer), e.reject(new t("DISPOSED", "Plugin bridge disposed"));
				h.clear(), g.clear(), _.clear(), v.clear();
			}
		};
		function S(e) {
			if (d || l !== null || e.source !== i) return;
			let r = e.data;
			r && r.t === "plugin.port" && e.ports && e.ports[0] && (clearTimeout(y), n.removeEventListener("message", S), l = e.ports[0], l.onmessage = (e) => {
				let n = e.data;
				if (n && typeof n.t == "string") switch (n.t) {
					case "ui.settings":
						typeof n.public_origin == "string" && (m = n.public_origin.replace(/\/+$/, "")), f = {
							theme: n.theme === "dark" || n.scheme === "dark" ? "dark" : "light",
							motion: n.motion === "reduced" || n.motion === "off" ? n.motion : "full",
							density: n.density === "compact" ? "compact" : "comfortable",
							tokens: n.tokens && typeof n.tokens == "object" ? n.tokens : {},
							visible: n.visible !== !1,
							public_origin: m || void 0
						}, o(f);
						for (let e of g) e(f);
						break;
					case "ui.route":
						if (typeof n.path == "string") {
							p = n.path;
							for (let e of _) e(p);
						}
						break;
					case "api.result":
					case "ui.confirm.result":
					case "ui.copy.result": {
						let e = typeof n.id == "string" || typeof n.id == "number" ? String(n.id) : "", r = h.get(e);
						if (!r) return;
						if (h.delete(e), n.ok === !0) r.resolve(n.data);
						else {
							let e = n.problem ?? {};
							r.reject(new t(e.code || "INTERNAL", e.detail || e.code || "Operation failed", e.status, e.violations));
						}
						break;
					}
					case "api.event": {
						let e = n.event;
						if (e && typeof e == "object" && typeof e.subject == "string") for (let t of v) (t.subjects.length === 0 || t.subjects.some((t) => e.subject === t || e.subject.startsWith(t.endsWith("/") ? t : t + "/"))) && t.fn(e);
						break;
					}
				}
			}, l.start?.(), l.postMessage({ t: "ui.ready" }), s(x));
		}
		n.addEventListener("message", S), i.postMessage({
			t: "plugin.hello",
			kit_major: 1
		}, "*");
	});
}
var l = class {
	opts;
	#e = null;
	#t = null;
	#n = "/";
	constructor(e = {}) {
		if (this.opts = e, typeof document < "u" && typeof CSSStyleSheet < "u" && "adoptedStyleSheets" in document) try {
			this.#t = new CSSStyleSheet(), document.adoptedStyleSheets = [...document.adoptedStyleSheets, this.#t];
		} catch {
			this.#t = null;
		}
		let t = e.hash ?? (typeof location < "u" ? location.hash : "");
		this.#n = s(t).route;
	}
	get publicOrigin() {
		return this.#e?.publicOrigin ?? "";
	}
	get currentPath() {
		return this.#e?.route ?? this.#n;
	}
	async connect() {
		if (this.#e) return;
		let e = await c(this.opts);
		this.#e = e, this.#n = e.route, this.#r(e.settings), e.onSettings((e) => this.#r(e)), e.onRoute((e) => {
			this.#n = e;
		}), typeof window < "u" && window.addEventListener("pagehide", () => this.dispose(), { once: !0 });
	}
	invoke(e, r = {}, i = 15e3) {
		return this.#e ? this.#e.invokeOutcome(e, r, { timeoutMs: i }).catch((e) => {
			throw e instanceof t ? new n({
				code: e.code,
				detail: e.message,
				status: e.status,
				violations: e.violations
			}) : e;
		}) : Promise.reject(new n({
			code: "UNAVAILABLE",
			detail: "插件尚未完成宿主握手"
		}));
	}
	confirm(e) {
		return this.#e ? this.#e.confirm(e) : Promise.reject(new n({
			code: "UNAVAILABLE",
			detail: "插件尚未完成宿主握手"
		}));
	}
	copyText(e, t = "已复制到剪贴板") {
		return this.#e ? this.#e.copyText(e, t) : Promise.reject(new n({
			code: "UNAVAILABLE",
			detail: "插件尚未完成宿主握手"
		}));
	}
	buildPublicURL(e) {
		return this.#e ? this.#e.buildPublicURL(e) : e.startsWith("/") ? e : `/${e}`;
	}
	navigate(e) {
		this.#n = e, this.#e?.navigate(e);
	}
	toast(e) {
		this.#e?.toast(e);
	}
	onRouteChange(e) {
		return this.#e ? this.#e.onRoute(e) : () => {};
	}
	subscribe(e, t) {
		return this.#e ? this.#e.subscribe([e], t) : () => {};
	}
	observeAutoResize(e) {
		let t = new ResizeObserver(() => {
			let t = Math.ceil(e.getBoundingClientRect().height) + 16;
			this.#e?.resize(t);
		});
		return t.observe(e), () => t.disconnect();
	}
	dispose() {
		this.#e?.dispose(), this.#e = null;
	}
	#r(e) {
		if (!this.#t || !e.tokens) return;
		let t = [];
		for (let [n, r] of Object.entries(e.tokens)) /^--[a-zA-Z0-9_-]+$/.test(n) && !/[{};\\]/.test(r) && t.push(`${n}: ${r};`);
		t.length > 0 && this.#t.replaceSync(`:root { ${t.join(" ")} }`);
	}
};
// kit/src/followup_and_dom.ts
async function u(e, t, n, r) {
	let i = await e.invokeOutcome(t, n, r);
	if (i.kind === "done") return r.onImmediateDone && await r.onImmediateDone(i.result, i.operationId), i;
	if (i.kind === "awaiting_approval" ? e.toast("操作已提交，请在右侧审批浮窗点击批准后自动生效") : e.toast("后台任务执行中，完成后将自动刷新"), r.onBackgroundSettled) {
		let t = r.approvalWaitTimeoutMs ?? 6e5, n = !1, a = null, o = setTimeout(() => {
			n || (n = !0, a?.());
		}, t);
		a = e.subscribe([`plugins/${r.pluginId}/*`, "operations/*"], (e) => {
			if (n) return;
			let t = typeof e.operation_id == "string" ? e.operation_id : "", s = !!(i.operationId && t === i.operationId), c = e.subject.includes(`plugins/${r.pluginId}/`);
			(s || c) && (n = !0, clearTimeout(o), a?.(), Promise.resolve(r.onBackgroundSettled?.()).catch(() => {}));
		});
	}
	return i;
}
function d(e, t, ...n) {
	let r = document.createElement(e);
	if (t) {
		if (t.className && (r.className = t.className), t.id && (r.id = t.id), t.text !== void 0 && (r.textContent = t.text), t.attrs) for (let [e, n] of Object.entries(t.attrs)) {
			let t = e.toLowerCase();
			t === "style" || t.startsWith("on") || r.setAttribute(e, n);
		}
		if (t.dataset) for (let [e, n] of Object.entries(t.dataset)) r.dataset[e] = n;
		if (t.on) for (let [e, n] of Object.entries(t.on)) typeof n == "function" && r.addEventListener(e, n);
	}
	for (let e of n) e != null && e !== !1 && (typeof e == "string" || typeof e == "number" ? r.appendChild(document.createTextNode(String(e))) : r.appendChild(e));
	return r;
}
function f(e, t = document.body) {
	let n = () => {
		let n = Math.max(t.scrollHeight, document.documentElement.scrollHeight, 320);
		e.resize(n);
	}, r = typeof ResizeObserver < "u" ? new ResizeObserver(n) : null;
	r?.observe(t), n();
	let i = () => {
		r?.disconnect(), e.dispose();
	};
	return window.addEventListener("pagehide", i, { once: !0 }), i;
}
function p(e, t) {
	let n = /* @__PURE__ */ new Uint8Array(4);
	new DataView(n.buffer).setUint32(0, t.byteLength, !1), e.push(n, t);
}
function m(e, t) {
	p(e, new TextEncoder().encode(t));
}
function h(e) {
	let t = 0;
	for (let n of e) t += n.byteLength;
	let n = new Uint8Array(t), r = 0;
	for (let t of e) n.set(t, r), r += t.byteLength;
	return n;
}
function g(e, t = 70) {
	let n = "";
	for (let t = 0; t < e.byteLength; t++) n += String.fromCharCode(e[t] ?? 0);
	let r = btoa(n);
	if (t <= 0) return r;
	let i = [];
	for (let e = 0; e < r.length; e += t) i.push(r.slice(e, e + t));
	return i.join("\n");
}
function _(e) {
	return `-----${e} OPENSSH PRIVATE KEY-----`;
}
async function v(e = "qwq-admin") {
	let t = await crypto.subtle.generateKey({ name: "Ed25519" }, !0, ["sign", "verify"]), n = new Uint8Array(await crypto.subtle.exportKey("raw", t.publicKey)), r = new Uint8Array(await crypto.subtle.exportKey("pkcs8", t.privateKey));
	if (n.byteLength !== 32 || r.byteLength < 32) throw Error("Unexpected Ed25519 WebCrypto key length");
	let i = r.slice(r.byteLength - 32), a = [];
	m(a, "ssh-ed25519"), p(a, n);
	let o = h(a), s = e.trim() || "qwq-key", c = `ssh-ed25519 ${g(o, 0)} ${s}`, l = crypto.getRandomValues(/* @__PURE__ */ new Uint8Array(4)), u = [l, l];
	m(u, "ssh-ed25519"), p(u, n);
	let d = /* @__PURE__ */ new Uint8Array(64);
	d.set(i, 0), d.set(n, 32), p(u, d), m(u, s);
	let f = h(u), v = (8 - f.byteLength % 8) % 8, y = new Uint8Array(v);
	for (let e = 0; e < v; e++) y[e] = e + 1 & 255;
	let b = h([f, y]), x = [new TextEncoder().encode("openssh-key-v1\0")];
	m(x, "none"), m(x, "none"), p(x, /* @__PURE__ */ new Uint8Array()), x.push(new Uint8Array([
		0,
		0,
		0,
		1
	])), p(x, o), p(x, b);
	let S = h(x);
	return i.fill(0), d.fill(0), r.fill(0), {
		publicKeyAuthorized: c,
		privateKeyOpenSSHPEM: `${_("BEGIN")}\n${g(S, 70)}\n${_("END")}\n`
	};
}
export { e as KIT_MAJOR, t as PluginHostError, n as PluginInvokeError, l as QwqPluginBridge, o as applyHostSettings, c as createPluginBridge, v as generateOpenSSHEd25519KeyPair, d as h, u as invokeWithApprovalFollowup, f as mountAutoResize, s as parseInitialFragment, r as unwrapInvokeOutcome };
