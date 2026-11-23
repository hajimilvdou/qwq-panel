// SPDX-License-Identifier: AGPL-3.0-only
/* 进度感知文件上传（XHR + 403 CSRF_FAILED 自动刷新单次重试，独立拆包避免进入首屏） */
import { ApiError, NetworkError, getAuthHooks, parseRetryAfter, type ApiResponse } from './client';
import type { Problem } from './types';

export async function upload<T>(
  path: string,
  form: FormData,
  onProgress?: (loaded: number, total: number) => void,
  signal?: AbortSignal,
): Promise<ApiResponse<T>> {
  const sendOnce = (): Promise<ApiResponse<T>> =>
    new Promise((resolve, reject) => {
      if (signal?.aborted) {
        reject(new DOMException('aborted', 'AbortError'));
        return;
      }
      const { csrfToken, onUnauthenticated } = getAuthHooks();
      const xhr = new XMLHttpRequest();
      const onAbort = () => xhr.abort();
      const cleanup = () => signal?.removeEventListener('abort', onAbort);

      xhr.open('POST', path);
      xhr.setRequestHeader('Accept', 'application/json');
      if (csrfToken) xhr.setRequestHeader('X-CSRF-Token', csrfToken);
      xhr.withCredentials = true;
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) onProgress?.(e.loaded, e.total);
      };
      xhr.onerror = () => {
        cleanup();
        reject(new NetworkError(new Error('upload failed')));
      };
      xhr.onabort = () => {
        cleanup();
        reject(new DOMException('aborted', 'AbortError'));
      };
      xhr.onload = () => {
        cleanup();
        let parsed: unknown = null;
        try {
          parsed = xhr.responseText ? JSON.parse(xhr.responseText) : null;
        } catch {
          parsed = null;
        }
        const headers = new Headers();
        const ct = xhr.getResponseHeader('content-type');
        if (ct) headers.set('content-type', ct);
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve({ status: xhr.status, data: parsed as T, headers });
          return;
        }
        if (xhr.status === 401) onUnauthenticated?.();
        reject(
          new ApiError(xhr.status, parsed as Problem | null, xhr.statusText, parseRetryAfter(xhr.getResponseHeader('retry-after'))),
        );
      };
      signal?.addEventListener('abort', onAbort, { once: true });
      xhr.send(form);
    });

  try {
    return await sendOnce();
  } catch (err) {
    const { refreshCsrf } = getAuthHooks();
    if (err instanceof ApiError && err.status === 403 && err.code === 'CSRF_FAILED' && refreshCsrf && !signal?.aborted) {
      await refreshCsrf();
      return await sendOnce();
    }
    throw err;
  }
}
