/**
 * 2FA 驗證器 — Cloudflare Worker (v2.0.0)
 *
 * 安全設計：
 * - 僅接受同源請求（可用 ALLOWED_ORIGIN 環境變數開放指定來源，預設不允許跨域）
 * - 嚴格驗證 key 格式（64 位十六進位），防止 KV 金鑰濫用
 * - 請求與資料大小上限，防止儲存空間濫用
 * - 可選的 Rate Limiting binding（API_RATE_LIMITER），未配置時自動跳過
 * - 所有 API 回應 no-store，靜態資源附加安全標頭
 */

const KEY_RE = /^[a-f0-9]{64}$/;
const MAX_DATA_LENGTH = 2 * 1024 * 1024;        // encryptedData base64 上限 2MB
const MAX_BODY_LENGTH = MAX_DATA_LENGTH + 8192; // JSON body 上限（含其他欄位）
const SALT_RE = /^[A-Za-z0-9+/=]{8,64}$/;

const CSP = "default-src 'self'; script-src 'self' 'sha256-gERs5DaPoPALkgMmhL7Euk0rL2kXQCOlmad6Zl1WSLM='; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; media-src 'self' blob:; object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'";

const SECURITY_HEADERS = {
  'Content-Security-Policy': CSP,
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(self), microphone=(), geolocation=(), payment=()',
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/health') {
      return jsonResponse({ status: 'ok', timestamp: Date.now() }, 200, request, env);
    }

    if (url.pathname.startsWith('/api/')) {
      return handleAPI(request, env);
    }

    // 靜態資源（wrangler.toml 中設定 run_worker_first + ASSETS binding）
    if (!env.ASSETS) {
      return new Response('Not Found', { status: 404 });
    }
    const response = await env.ASSETS.fetch(request);
    const headers = new Headers(response.headers);
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
    // HTML 一律重新驗證（配合 Service Worker network-first，確保更新即時生效）
    const path = url.pathname;
    if (path === '/' || path.endsWith('.html')) {
      headers.set('Cache-Control', 'no-cache');
    }
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  },
};

/** 來源檢查：僅允許同源，或 env.ALLOWED_ORIGIN（逗號分隔清單） */
function originAllowed(request, url, env) {
  const origin = request.headers.get('Origin');
  if (!origin) return true;
  if (origin === url.origin) return true;
  if (env.ALLOWED_ORIGIN) {
    const list = String(env.ALLOWED_ORIGIN).split(',').map(s => s.trim()).filter(Boolean);
    return list.includes(origin);
  }
  return false;
}

function corsHeadersFor(request, url, env) {
  const origin = request.headers.get('Origin');
  if (!origin || !originAllowed(request, url, env)) return {};
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

async function handleAPI(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // 跨域檢查：Origin 不符直接拒絕
  if (!originAllowed(request, url, env)) {
    return jsonResponse({ error: 'Forbidden' }, 403, request, env);
  }
  const cors = corsHeadersFor(request, url, env);

  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: cors });
  }

  try {
    // 可選 Rate Limiting（wrangler.toml 設定 API_RATE_LIMITER binding 後啟用）
    if (env.API_RATE_LIMITER) {
      const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
      const { success } = await env.API_RATE_LIMITER.limit({ key: `api:${ip}` });
      if (!success) {
        return jsonResponse({ error: 'Too many requests' }, 429, request, env, { 'Retry-After': '60' });
      }
    }

    if (path === '/api/data' && method === 'GET') {
      const key = url.searchParams.get('key');
      if (!key || !KEY_RE.test(key)) {
        return jsonResponse({ error: 'Invalid key' }, 400, request, env);
      }
      const data = await env.DATA_KV.get(key);
      if (data === null) {
        return jsonResponse({ exists: false, data: null }, 200, request, env);
      }
      return jsonResponse({ exists: true, data }, 200, request, env);
    }

    if (path === '/api/data' && method === 'PUT') {
      const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
      if (contentLength > MAX_BODY_LENGTH) {
        return jsonResponse({ error: 'Payload too large' }, 413, request, env);
      }
      const raw = await request.text();
      if (raw.length > MAX_BODY_LENGTH) {
        return jsonResponse({ error: 'Payload too large' }, 413, request, env);
      }
      let body;
      try {
        body = JSON.parse(raw);
      } catch (e) {
        return jsonResponse({ error: 'Invalid JSON' }, 400, request, env);
      }
      const { key, data, salt, version } = body || {};

      if (!key || typeof key !== 'string' || !KEY_RE.test(key)) {
        return jsonResponse({ error: 'Invalid key' }, 400, request, env);
      }
      if (!data || typeof data !== 'string') {
        return jsonResponse({ error: 'Missing data' }, 400, request, env);
      }
      if (data.length > MAX_DATA_LENGTH) {
        return jsonResponse({ error: 'Payload too large' }, 413, request, env);
      }
      if (!salt || typeof salt !== 'string' || !SALT_RE.test(salt)) {
        return jsonResponse({ error: 'Invalid salt' }, 400, request, env);
      }
      const ver = version === undefined ? 1 : version;
      if (typeof ver !== 'number' || !Number.isInteger(ver) || ver < 1 || ver > 9) {
        return jsonResponse({ error: 'Invalid version' }, 400, request, env);
      }

      const stored = JSON.stringify({
        encryptedData: data,
        salt,
        version: ver,
        updatedAt: Date.now(),
      });
      await env.DATA_KV.put(key, stored);
      return jsonResponse({ success: true }, 200, request, env);
    }

    if (path === '/api/data' && method === 'DELETE') {
      const key = url.searchParams.get('key');
      if (!key || !KEY_RE.test(key)) {
        return jsonResponse({ error: 'Invalid key' }, 400, request, env);
      }
      await env.DATA_KV.delete(key);
      return jsonResponse({ success: true }, 200, request, env);
    }

    return jsonResponse({ error: 'Not found' }, 404, request, env);
  } catch (error) {
    console.error('API error:', error && error.message ? error.message : error);
    return jsonResponse({ error: 'Internal error' }, 500, request, env);
  }
}

function jsonResponse(data, status, request, env, extraHeaders = {}) {
  const url = new URL(request.url);
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...corsHeadersFor(request, url, env),
      ...extraHeaders,
    },
  });
}
