import { FEEDS } from "./catalog.js";
import { feedAllowed, isAllowedFeedUrl } from "./guard.js";
import { createItemScanner, parseFeed } from "./parse.js";

export const TTL_MS = 15 * 60 * 1000;
export const MAX_BYTES = 8 * 1024 * 1024;
export const MAX_SCAN = 512 * 1024;
export const MAX_ITEMS = 50;
// One cold feed per request. Parsing more than that exceeds the Workers Free
// CPU budget (about 10 ms). The News page requests one source at a time.
export const COLD_FETCHES = 1;
export const FETCH_TIMEOUT_MS = 12000;
const MAX_REDIRECTS = 3;
const UA = "timsonner-feeds/1.0 (+https://timsonner.com/news/)";
const DEFAULT_PER = 5;

export const ALLOWED_ORIGINS = [
  "https://timsonner.com",
  "https://www.timsonner.com",
  "https://timsonner.github.io",
  "http://localhost:4000"
];

const ALLOWED = new Set(ALLOWED_ORIGINS);
const CACHE_PREFIX = "https://timsonner-feeds.timsonner.workers.dev/__cache/source/";

export function createHandler(deps = {}) {
  const feeds = deps.feeds || FEEDS;
  const fetchImpl = deps.fetchImpl || globalThis.fetch;
  const now = deps.now || (() => Date.now());
  const inflight = new Map();

  function store() {
    if (deps.cache) return deps.cache;
    return caches.default;
  }

  function fresh(data) {
    const ms = Date.parse(data && data.fetched_at || "");
    if (!Number.isFinite(ms)) return false;
    return now() - ms < TTL_MS;
  }

  function usable(data, per) {
    if (!data || !fresh(data)) return false;
    if (data.status === "unavailable") return true;
    return data.status === "ok" && data.limit >= per && Array.isArray(data.items);
  }

  async function loadSource(feed, per) {
    const running = inflight.get(feed.key);
    if (running) return running;
    const job = pullFeed(feed, per).finally(() => {
      inflight.delete(feed.key);
    });
    inflight.set(feed.key, job);
    return job;
  }

  async function pullFeed(feed, per) {
    const previous = await readSource(store(), feed.key);
    if (usable(previous, per)) return previous;
    try {
      const response = await fetchResponse(feed.url, 0);
      const parsed = await readItems(response, per);
      if (!parsed.length) throw new Error("empty");
      const state = {
        key: feed.key,
        status: "ok",
        fetched_at: new Date(now()).toISOString(),
        limit: per,
        items: newest(parsed).slice(0, per)
      };
      await writeSource(store(), state);
      return state;
    } catch {
      if (previous && Array.isArray(previous.items) && previous.items.length) {
        return {
          key: feed.key,
          status: "stale",
          fetched_at: previous.fetched_at || null,
          limit: previous.limit || previous.items.length,
          items: previous.items.slice(0, per)
        };
      }
      const missing = {
        key: feed.key,
        status: "unavailable",
        fetched_at: new Date(now()).toISOString(),
        limit: per,
        items: []
      };
      await writeSource(store(), missing);
      return missing;
    }
  }

  async function fetchResponse(url, hops) {
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
      return fetchResponse(new URL(location, url).href, hops + 1);
    }
    if (!response.ok) throw new Error("status");
    return response;
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
      return json(sourcesPayload(feeds), 200, origin);
    }
    if (path === "/items") {
      const selected = selectFeeds(request.url, feeds);
      const per = selectPer(request.url);
      const states = [];
      let cold = 0;
      for (const feed of selected) {
        const cached = await readSource(store(), feed.key);
        if (usable(cached, per)) {
          states.push({
            ...cached,
            items: Array.isArray(cached.items) ? cached.items.slice(0, per) : []
          });
          continue;
        }
        if (cold >= COLD_FETCHES) {
          states.push({
            key: feed.key,
            status: "pending",
            fetched_at: null,
            limit: 0,
            items: []
          });
          continue;
        }
        cold += 1;
        states.push(await loadSource(feed, per));
      }
      return json(itemsPayload(states), 200, origin);
    }
    return json({ error: "not found" }, 404, origin);
  };
}

export function sourcesPayload(feeds) {
  return feeds.map((feed) => ({
    key: feed.key,
    name: feed.name,
    category: feed.category,
    status: "unknown"
  }));
}

export function selectFeeds(requestUrl, feeds) {
  const params = new URL(requestUrl).searchParams;
  const raw = params.get("sources");
  if (!raw) return [];
  const wanted = new Set();
  for (const part of raw.split(",")) {
    const key = part.trim().toLowerCase();
    if (!key || /crowdstrike/i.test(key)) continue;
    wanted.add(key);
  }
  return feeds.filter((feed) => wanted.has(feed.key) && feedAllowed(feed.key, feed.url));
}

export function selectPer(requestUrl) {
  const raw = new URL(requestUrl).searchParams.get("per");
  const per = parseInt(raw || "", 10);
  if (!Number.isFinite(per) || per < 1) return DEFAULT_PER;
  if (per > MAX_ITEMS) return MAX_ITEMS;
  return per;
}

export function itemsPayload(states) {
  const items = [];
  let fetchedAt = null;
  const sources = states.map((state) => {
    const list = state && Array.isArray(state.items) ? state.items : [];
    for (const item of list) {
      if (!item || typeof item.title !== "string" || !item.title) continue;
      items.push({
        source: state.key,
        title: item.title,
        link: item.link || null,
        published: item.published || null
      });
    }
    if (state && state.fetched_at && (!fetchedAt || state.fetched_at > fetchedAt)) {
      fetchedAt = state.fetched_at;
    }
    return { key: state.key, status: state && state.status ? state.status : "unavailable" };
  });
  items.sort(byDateDesc);
  return { fetched_at: fetchedAt, sources, items };
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

function cacheRequest(key) {
  return new Request(CACHE_PREFIX + key);
}

async function readSource(cache, key) {
  if (!cache) return null;
  const response = await cache.match(cacheRequest(key));
  if (!response) return null;
  try {
    return await response.json();
  } catch {
    return null;
  }
}

async function writeSource(cache, state) {
  if (!cache || !state || !state.key) return;
  await cache.put(cacheRequest(state.key), new Response(JSON.stringify(state), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "public, max-age=86400"
    }
  }));
}

async function readItems(response, limit) {
  if (!response.body || typeof response.body.getReader !== "function") {
    const text = await response.text();
    if (text.length > MAX_BYTES) throw new Error("too_large");
    return parseFeed(text, limit);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: false });
  const scanner = createItemScanner(limit);
  let received = 0;
  try {
    while (!scanner.done) {
      const step = await reader.read();
      if (step.done) {
        scanner.push(decoder.decode());
        break;
      }
      received += step.value.byteLength;
      if (received > MAX_BYTES) throw new Error("too_large");
      let piece = step.value;
      if (received > MAX_SCAN) {
        const keep = step.value.byteLength - (received - MAX_SCAN);
        piece = keep > 0 ? step.value.subarray(0, keep) : new Uint8Array();
      }
      if (piece.byteLength) scanner.push(decoder.decode(piece, { stream: true }));
      if (received >= MAX_SCAN) {
        if (!scanner.done) scanner.abort();
        break;
      }
    }
  } finally {
    try { await reader.cancel(); } catch { /* ignore */ }
  }
  return scanner.finish();
}
