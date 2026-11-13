import { FEEDS } from "./catalog.js";
import { isAllowedFeedUrl } from "./guard.js";
import { parseFeed } from "./parse.js";

export const TTL_MS = 15 * 60 * 1000;
export const MAX_BYTES = 8 * 1024 * 1024;
export const MAX_ITEMS = 50;
export const CONCURRENCY = 6;
export const FETCH_TIMEOUT_MS = 12000;
const MAX_REDIRECTS = 3;
const UA = "timsonner-feeds/1.0 (+https://timsonner.com/news/)";

export const ALLOWED_ORIGINS = [
  "https://timsonner.com",
  "https://www.timsonner.com",
  "https://timsonner.github.io",
  "http://localhost:4000"
];

const ALLOWED = new Set(ALLOWED_ORIGINS);
const CACHE_URL = "https://timsonner-feeds.timsonner.workers.dev/__cache/items";

export function createHandler(deps = {}) {
  const feeds = deps.feeds || FEEDS;
  const fetchImpl = deps.fetchImpl || globalThis.fetch;
  const now = deps.now || (() => Date.now());
  let inflight = null;

  function store() {
    if (deps.cache) return deps.cache;
    return caches.default;
  }

  function fresh(data) {
    const ms = Date.parse(data && data.fetched_at || "");
    if (!Number.isFinite(ms)) return false;
    return now() - ms < TTL_MS;
  }

  async function ensureItems() {
    const cached = await readCache(store());
    if (cached && fresh(cached)) return cached;
    if (!inflight) {
      inflight = fill(cached).finally(() => {
        inflight = null;
      });
    }
    return inflight;
  }

  async function fill(previous) {
    const prevFeeds = previous && previous.feeds ? previous.feeds : {};
    const results = await mapPool(feeds, CONCURRENCY, (feed) => pullFeed(feed, prevFeeds[feed.key]));
    const next = {
      fetched_at: new Date(now()).toISOString(),
      feeds: {}
    };
    for (const row of results) next.feeds[row.key] = row.state;
    try {
      await writeCache(store(), next);
    } catch {
      // A cache write failure still returns the items we just fetched.
    }
    return next;
  }

  async function pullFeed(feed, previous) {
    try {
      const xml = await fetchText(feed.url, 0);
      const parsed = parseFeed(xml);
      if (!parsed.length) throw new Error("empty");
      return {
        key: feed.key,
        state: {
          status: "ok",
          fetched_at: new Date(now()).toISOString(),
          items: newest(parsed).slice(0, MAX_ITEMS)
        }
      };
    } catch {
      if (previous && Array.isArray(previous.items) && previous.items.length) {
        return {
          key: feed.key,
          state: {
            status: "stale",
            fetched_at: previous.fetched_at || null,
            items: previous.items
          }
        };
      }
      return { key: feed.key, state: { status: "unavailable", fetched_at: null, items: [] } };
    }
  }

  async function fetchText(url, hops) {
    if (!isAllowedFeedUrl(url)) throw new Error("blocked");
    const response = await fetchImpl(url, {
      method: "GET",
      redirect: "manual",
      headers: {
        "User-Agent": UA,
        "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.8"
      },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS)
    });
    const status = response.status;
    if (status >= 300 && status < 400) {
      if (hops >= MAX_REDIRECTS) throw new Error("redirect");
      const location = response.headers.get("Location");
      if (!location) throw new Error("redirect");
      return fetchText(new URL(location, url).href, hops + 1);
    }
    if (!response.ok) throw new Error("status");
    return readLimited(response);
  }

  return async function handle(request) {
    const origin = request.headers.get("Origin");
    if (origin && !ALLOWED.has(origin)) {
      return json({ error: "origin not allowed" }, 403, origin);
    }
    const method = request.method.toUpperCase();
    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: baseHeaders(origin) });
    }
    if (method !== "GET" && method !== "HEAD") {
      const headers = baseHeaders(origin);
      headers.set("Allow", "GET, HEAD, OPTIONS");
      return new Response(JSON.stringify({ error: "method not allowed" }), {
        status: 405,
        headers
      });
    }
    const path = normalizePath(request.url);
    if (path === "/sources") {
      const data = await readCache(store());
      return json(sourcesPayload(feeds, data), 200, origin);
    }
    if (path === "/items") {
      const data = await ensureItems();
      return json(itemsPayload(feeds, data), 200, origin);
    }
    return json({ error: "not found" }, 404, origin);
  };
}

export function sourcesPayload(feeds, data) {
  const states = data && data.feeds ? data.feeds : {};
  return feeds.map((feed) => ({
    key: feed.key,
    name: feed.name,
    category: feed.category,
    status: states[feed.key] ? states[feed.key].status : "unknown"
  }));
}

export function itemsPayload(feeds, data) {
  const states = data && data.feeds ? data.feeds : {};
  const items = [];
  const sources = feeds.map((feed) => {
    const state = states[feed.key];
    const list = state && Array.isArray(state.items) ? state.items : [];
    for (const item of list) {
      if (!item || typeof item.title !== "string" || !item.title) continue;
      items.push({
        source: feed.key,
        title: item.title,
        link: item.link || null,
        published: item.published || null
      });
    }
    return { key: feed.key, status: state ? state.status : "unavailable" };
  });
  items.sort(byDateDesc);
  return {
    fetched_at: data && data.fetched_at ? data.fetched_at : null,
    sources,
    items
  };
}

function byDateDesc(a, b) {
  const am = a.published ? Date.parse(a.published) : NaN;
  const bm = b.published ? Date.parse(b.published) : NaN;
  if (!Number.isFinite(am) && !Number.isFinite(bm)) return 0;
  if (!Number.isFinite(am)) return 1;
  if (!Number.isFinite(bm)) return -1;
  return bm - am;
}

function newest(items) {
  return items.slice().sort(byDateDesc);
}

function normalizePath(requestUrl) {
  const path = new URL(requestUrl).pathname.replace(/\/+$/, "");
  return path || "/";
}

function baseHeaders(origin) {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "public, max-age=300, s-maxage=900",
    "X-Content-Type-Options": "nosniff",
    "Vary": "Origin"
  });
  if (origin && ALLOWED.has(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Content-Type");
    headers.set("Access-Control-Max-Age", "86400");
  }
  return headers;
}

function json(body, status, origin) {
  return new Response(JSON.stringify(body), { status, headers: baseHeaders(origin) });
}

async function readCache(cache) {
  if (!cache) return null;
  const response = await cache.match(new Request(CACHE_URL));
  if (!response) return null;
  try {
    return await response.json();
  } catch {
    return null;
  }
}

async function writeCache(cache, data) {
  if (!cache) return;
  await cache.put(new Request(CACHE_URL), new Response(JSON.stringify(data), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "public, max-age=900"
    }
  }));
}

async function readLimited(response) {
  if (!response.body || typeof response.body.getReader !== "function") {
    const text = await response.text();
    if (text.length > MAX_BYTES) throw new Error("too_large");
    return text;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let received = 0;
  while (true) {
    const step = await reader.read();
    if (step.done) break;
    received += step.value.byteLength;
    if (received > MAX_BYTES) {
      try { await reader.cancel(); } catch { /* ignore */ }
      throw new Error("too_large");
    }
    chunks.push(step.value);
  }
  const buf = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    buf.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(buf);
}

async function mapPool(list, limit, fn) {
  const ret = new Array(list.length);
  let cursor = 0;
  const workers = Math.min(limit, list.length);
  await Promise.all(Array.from({ length: workers }, async () => {
    while (cursor < list.length) {
      const index = cursor;
      cursor += 1;
      ret[index] = await fn(list[index], index);
    }
  }));
  return ret;
}

