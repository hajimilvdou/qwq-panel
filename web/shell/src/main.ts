// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 入口：样式 → 偏好 → 路由 → 接线 → 挂载 → 启动会话
 * ========================================================================== */
import './styles/fonts.css';
import './styles/tokens.css';
import './styles/base.css';

import { mount } from 'svelte';
import App from './App.svelte';
import { routes } from './app/routes';
import { wire } from './app/wiring';
import { prefs } from '$lib/prefs.svelte';
import { installLinkInterceptor, router } from '$lib/router.svelte';
import { session } from '$lib/session.svelte';

prefs.init();
router.init(routes);
installLinkInterceptor();
wire();

mount(App, { target: document.getElementById('app')! });

void session.bootstrap();
