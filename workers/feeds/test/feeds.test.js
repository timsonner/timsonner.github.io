import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { FEEDS, normalizeCatalog } from "../src/catalog.js";
import { feedAllowed, isBlockedHost, safeItemLink } from "../src/guard.js";
import {
  ALLOWED_ORIGINS,
  COLD_FETCHES,
  MAX_BYTES,
  MAX_SCAN,
  TTL_MS,
  createHandler
} from "../src/handler.js";
import { createItemScanner, parseFeed } from "../src/parse.js";

const TERMINAL_KEYS = [
  "netsec", "sysadmin", "cybersecurity", "security-se", "cis", "securitymagazine",
  "darkreading", "schneier", "trailofbits", "malwaretech", "projectzero", "krebs",
  "bleeping", "wired", "ars", "theregister", "cisa", "thehackernews", "sans",
  "unit42", "troyhunt", "securityweek", "helpnetsec", "msrc", "daemon",
  "techanarchy", "nixcraft", "doublepulsar", "blackhills", "dfirreport",
  "redcanary", "mandiant", "trustedsec"
];

const WHEN = "Fri, 13 Nov 2026 16:00:00 GMT";

function rssItem({ title, link, date = WHEN, extra = "" }) {
  return `<?xml version="1.0"?><rss version="2.0"><channel><title>Feed</title><item><title>${title}</title><link>${link}</link><pubDate>${date}</pubDate>${extra}</item></channel></rss>`;
}

function memoryCache() {
  const jar = new Map();
  return {
    async match(request) {
      const hit = jar.get(request.url);
      return hit ? hit.clone() : undefined;
    },
    async put(request, response) {
      jar.set(request.url, response.clone());
    }
  };
}

function handlerFor(feeds, fetchImpl, now, env) {
  return createHandler({
    feeds,
    fetchImpl,
    cache: memoryCache(),
    now,
    env
  });
}

const PROXY_FEEDS = [
  {
    key: "bleeping",
    name: "Bleeping Computer",
    url: "https://www.bleepingcomputer.com/feed/",
    category: "Security"
  },
  {
    key: "nixcraft",
    name: "nixCraft",
    url: "http://feeds.cyberciti.biz/Nixcraft-LinuxFreebsdSolarisTipsTricks",
    category: "Linux/Tech"
  },
  {
    key: "netsec",
    name: "/r/netsec",
    url: "https://www.reddit.com/r/netsec/.rss",
    category: "Community"
  },
  {
    key: "krebs",
    name: "Krebs on Security",
    url: "https://krebsonsecurity.com/feed/",
    category: "Security"
  }
];

const PROXY_ENV = {
  FEED_PROXY_URL: "https://proxy.example",
  FEED_PROXY_KEY: "test-proxy-key"
};

function captureFetch(responses = {}) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    const entry = {
      url: String(url),
      proxyKey: init?.headers?.["X-Feed-Proxy-Key"] ?? null
    };
    calls.push(entry);
    const key = PROXY_FEEDS.find((feed) => entry.url.endsWith("/" + feed.key))?.key
      || (entry.url.includes("krebsonsecurity") ? "krebs" : null)
      || (entry.url.includes("cdn.example") ? "redirect" : null);
    const spec = responses[key] || responses.default;
    if (typeof spec === "function") return spec(url, init, entry);
    if (spec) return spec;
    return new Response(rssItem({ title: "Story", link: "https://example.com/story" }), { status: 200 });
  };
  return { calls, fetchImpl };
}

test("catalog is the terminal list plus workflow feeds, with CrowdStrike gone", () => {
  const keys = new Set(FEEDS.map((feed) => feed.key));
  for (const key of TERMINAL_KEYS) assert.ok(keys.has(key), key);
  for (const key of ["phoronix", "hn-best", "lobsters", "lwn", "archlinux"]) {
    assert.ok(keys.has(key), key);
  }
  assert.equal(keys.size, FEEDS.length);
  assert.equal(new Set(FEEDS.map((feed) => feed.url)).size, FEEDS.length);
  assert.equal(FEEDS.length, 51);
  assert.equal(FEEDS.find((feed) => feed.key === "projectzero").url, "https://projectzero.google/feed.xml");
  assert.equal(FEEDS.find((feed) => feed.key === "phoronix").category, "Linux/Tech");
  assert.equal(FEEDS.find((feed) => feed.key === "cisa").category, "Advisories");
  assert.equal(FEEDS.find((feed) => feed.key === "krebs").category, "Security");
  assert.equal(FEEDS.find((feed) => feed.key === "netsec").category, "Community");
  assert.equal(FEEDS.some((feed) => /crowdstrike/i.test(feed.key + feed.url + feed.name)), false);
  for (const feed of FEEDS) assert.equal(feedAllowed(feed.key, feed.url), true);

  const blockedHost = ["crowd", "strike.com"].join("");
  const loopback = [127, 0, 0, 1].join(".");
  const dropped = normalizeCatalog({
    feeds: [
      { key: "crowdstrike", name: "Nope", url: "https://www." + blockedHost + "/blog/feed", category: "Security" },
      { key: "krebs", name: "Krebs on Security", url: "https://krebsonsecurity.com/feed/", category: "Security" },
      { key: "krebs-dup", name: "Dup", url: "https://krebsonsecurity.com/feed/", category: "Security" },
      { key: "local", name: "Local", url: "http://" + loopback + "/feed", category: "Security" }
    ]
  });
  assert.deepEqual(dropped.map((feed) => feed.key), ["krebs"]);
});

test("private hosts, credentials, and CrowdStrike links are blocked", () => {
  const host = ["crowd", "strike.com"].join("");
  const blocked = [
    "http://" + [127, 0, 0, 1].join(".") + "/feed",
    "http://localhost/feed",
    "http://" + [10, 1, 2, 3].join(".") + "/feed",
    "http://" + [192, 168, 0, 5].join(".") + "/feed",
    "http://" + [172, 16, 0, 4].join(".") + "/feed",
    "http://" + [169, 254, 169, 254].join(".") + "/latest",
    "http://[::1]/feed",
    "http://[fd00::1]/feed",
    "https://www." + host + "/blog/feed/",
    "https://news." + host + "/rss",
    "https://user:pass@example.com/feed",
    "javascript:alert(1)",
    "file:///etc/passwd",
    "http://metadata.google.internal/computeMetadata/v1/"
  ];
  for (const url of blocked) assert.equal(safeItemLink(url), null, url);
  assert.equal(isBlockedHost(["crowd", "strike.com"].join("")), true);
  assert.equal(feedAllowed("crowdstrike", "https://example.com/feed"), false);
  assert.equal(safeItemLink("https://krebsonsecurity.com/feed/"), "https://krebsonsecurity.com/feed/");
  assert.equal(safeItemLink("http://feeds.cyberciti.biz/Nixcraft-LinuxFreebsdSolarisTipsTricks") != null, true);
});

test("parser keeps title, link, and date, and drops descriptions and bad links", () => {
  const rss = rssItem({
    title: "<![CDATA[<script>alert(1)</script> A &amp; B]]>",
    link: "https://example.com/story?a=1&amp;b=2",
    extra: "<description>SECRET_BODY</description><comments>https://news.ycombinator.com/item?id=1</comments>"
  });
  const items = parseFeed(rss);
  assert.equal(items.length, 1);
  assert.deepEqual(Object.keys(items[0]).sort(), ["link", "published", "title"]);
  assert.equal(items[0].title.includes("<"), false);
  assert.equal(items[0].title.includes("SECRET_BODY"), false);
  assert.equal(items[0].title.includes("A & B"), true);
  assert.equal(items[0].link, "https://example.com/story?a=1&b=2");
  assert.equal(items[0].published, "2026-11-13T16:00:00.000Z");

  const atom = `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><entry>
    <title>Atom title</title>
    <link rel="replies" href="https://example.com/comments" />
    <link rel="alternate" type="text/html" href="https://example.com/post" />
    <published>2026-11-13T16:04:00Z</published>
    <content>SECRET_BODY</content>
  </entry></feed>`;
  const atomItems = parseFeed(atom);
  assert.equal(atomItems[0].link, "https://example.com/post");
  assert.equal(JSON.stringify(atomItems).includes("SECRET_BODY"), false);

  const bad = parseFeed(rssItem({ title: "Nope", link: "javascript:alert(1)" }));
  assert.equal(bad[0].link, null);
  assert.equal(parseFeed("<html>bot wall</html>").length, 0);

  const many = Array.from({ length: 6 }, (_, i) => (
    `<item><title>Story ${i}</title><link>https://example.com/${i}</link><pubDate>${WHEN}</pubDate></item>`
  )).join("");
  assert.equal(parseFeed(`<rss><channel>${many}</channel></rss>`, 2).length, 2);
  const scanner = createItemScanner(1);
  scanner.push(`<rss><channel><item><title>Kept</title><link>https://example.com/kept</link><pubDate>${WHEN}</pubDate></item>`);
  scanner.push("<item><title>Dropped</title><description>" + "x".repeat(200000) + "</description></item></channel></rss>");
  assert.equal(scanner.done, true);
  assert.equal(scanner.finish().length, 1);
  assert.equal(scanner.finish()[0].title, "Kept");
});

test("routes, origins, cache, stale items, and the allowlist", async () => {
  const feeds = [
    { key: "krebs", name: "Krebs on Security", url: "https://krebsonsecurity.com/feed/", category: "Security" },
    { key: "unit42", name: "Unit 42", url: "https://unit42.paloaltonetworks.com/feed/", category: "Security" }
  ];
  let nowMs = Date.parse("2026-11-13T18:00:00Z");
  let failKrebs = false;
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    const linkLocal = [169, 254].join(".");
    if (String(url).includes(linkLocal)) throw new Error("should not fetch a private redirect");
    if (String(url).includes("redirect-me")) {
      return new Response(null, { status: 302, headers: { Location: "https://cdn.example/feed.xml" } });
    }
    if (String(url).includes("cdn.example")) {
      return new Response(rssItem({ title: "Unit story", link: "https://example.com/unit-story" }), { status: 200 });
    }
    if (String(url).includes("krebsonsecurity")) {
      if (failKrebs) return new Response("nope", { status: 503 });
      return new Response(rssItem({
        title: "Krebs story",
        link: "https://krebsonsecurity.com/story",
        extra: "<description>SECRET_BODY</description>"
      }), { status: 200 });
    }
    if (String(url).includes("redirect-private")) {
      return new Response(null, {
        status: 302,
        headers: { Location: "http://" + [169, 254, 169, 254].join(".") + "/latest" }
      });
    }
    return new Response("missing", { status: 404 });
  };

  const handle = handlerFor([
    feeds[0],
    { ...feeds[1], url: "https://unit42.example/redirect-me" }
  ], fetchImpl, () => nowMs);

  const denied = await handle(new Request("https://timsonner-feeds.timsonner.workers.dev/items", {
    headers: { Origin: "https://evil.example" }
  }));
  assert.equal(denied.status, 403);
  assert.equal(denied.headers.get("Access-Control-Allow-Origin"), null);

  const sources = await handle(new Request("https://timsonner-feeds.timsonner.workers.dev/sources"));
  assert.equal(sources.status, 200);
  assert.equal(calls.length, 0);
  const sourceBody = await sources.json();
  assert.equal(sourceBody[0].status, "unknown");
  assert.equal(sourceBody[0].name, "Krebs on Security");

  const ignoredTarget = "http://" + [169, 254, 169, 254].join(".") + "/latest";
  const first = await handle(new Request("https://timsonner-feeds.timsonner.workers.dev/items?sources=krebs,unit42&url=" + encodeURIComponent(ignoredTarget), {
    headers: { Origin: "http://localhost:4000" }
  }));
  assert.equal(first.status, 200);
  assert.equal(first.headers.get("Access-Control-Allow-Origin"), "http://localhost:4000");
  assert.equal(first.headers.get("Cache-Control"), "public, max-age=300, s-maxage=900");
  const firstBody = await first.json();
  assert.equal(firstBody.items.some((item) => item.title === "Krebs story"), true);
  assert.equal(firstBody.items.some((item) => item.title === "Unit story"), false);
  assert.equal(firstBody.sources.find((source) => source.key === "unit42").status, "pending");
  assert.equal(JSON.stringify(firstBody).includes("SECRET_BODY"), false);
  assert.equal(calls.some((url) => String(url).includes("unit42")), false);
  assert.equal(calls.some((url) => String(url).includes([169, 254].join("."))), false);

  const unit = await handle(new Request("https://timsonner-feeds.timsonner.workers.dev/items?sources=unit42", {
    headers: { Origin: "https://timsonner.com" }
  }));
  assert.equal(unit.headers.get("Access-Control-Allow-Origin"), "https://timsonner.com");
  const unitBody = await unit.json();
  assert.equal(unitBody.items.some((item) => item.title === "Unit story"), true);

  const callsAfterFill = calls.length;
  const second = await handle(new Request("https://timsonner-feeds.timsonner.workers.dev/items?sources=krebs", {
    headers: { Origin: "https://timsonner.com" }
  }));
  assert.equal(calls.length, callsAfterFill);
  const secondBody = await second.json();
  assert.equal(secondBody.items.some((item) => item.title === "Krebs story"), true);

  nowMs += TTL_MS + 1000;
  failKrebs = true;
  const third = await handle(new Request("https://timsonner-feeds.timsonner.workers.dev/items?sources=krebs"));
  const thirdBody = await third.json();
  const krebs = thirdBody.sources.find((source) => source.key === "krebs");
  assert.equal(krebs.status, "stale");
  assert.equal(thirdBody.items.some((item) => item.title === "Krebs story"), true);

  const missing = await handle(new Request("https://timsonner-feeds.timsonner.workers.dev/other"));
  assert.equal(missing.status, 404);
  const posted = await handle(new Request("https://timsonner-feeds.timsonner.workers.dev/items", { method: "POST" }));
  assert.equal(posted.status, 405);
  assert.match(posted.headers.get("Allow"), /GET/);

  const privateFeed = createHandler({
    feeds: [{ key: "bad", name: "Bad", url: "https://example.com/redirect-private", category: "Security" }],
    fetchImpl,
    cache: memoryCache(),
    now: () => nowMs + 10 * TTL_MS
  });
  const blocked = await privateFeed(new Request("https://timsonner-feeds.timsonner.workers.dev/items?sources=bad"));
  const blockedBody = await blocked.json();
  assert.equal(blockedBody.sources[0].status, "unavailable");
  assert.equal(blockedBody.items.length, 0);
  assert.equal(calls.some((url) => String(url).includes([169, 254].join("."))), false);
});

test("concurrency stays capped and oversized bodies are dropped", async () => {
  let active = 0;
  let maxActive = 0;
  const feeds = Array.from({ length: 12 }, (_, i) => ({
    key: "f" + i,
    name: "Feed " + i,
    url: "https://example.com/feeds/" + i,
    category: "Security"
  }));
  const fetchImpl = async (url) => {
    active += 1;
    maxActive = Math.max(maxActive, active);
    await new Promise((resolve) => setTimeout(resolve, 20));
    active -= 1;
    const id = String(url).split("/").pop();
    return new Response(rssItem({ title: "Item " + id, link: "https://example.com/p/" + id }), { status: 200 });
  };
  const handle = handlerFor(feeds, fetchImpl, () => Date.parse("2026-11-13T18:00:00Z"));
  const names = feeds.map((feed) => feed.key).join(",");
  const response = await handle(new Request("https://timsonner-feeds.timsonner.workers.dev/items?sources=" + names));
  const body = await response.json();
  assert.equal(body.items.length, COLD_FETCHES);
  assert.equal(body.sources.filter((source) => source.status === "pending").length, feeds.length - COLD_FETCHES);
  assert.ok(maxActive <= COLD_FETCHES);

  const huge = createHandler({
    feeds: [{ key: "big", name: "Big", url: "https://example.com/big.xml", category: "Security" }],
    cache: memoryCache(),
    now: () => Date.now(),
    fetchImpl: async () => ({
      status: 200,
      ok: true,
      headers: { get() { return null; } },
      body: {
        getReader() {
          let sent = false;
          return {
            async read() {
              if (sent) return { done: true, value: undefined };
              sent = true;
              return { done: false, value: new Uint8Array(MAX_BYTES + 1) };
            },
            async cancel() {}
          };
        }
      }
    })
  });
  const oversized = await huge(new Request("https://timsonner-feeds.timsonner.workers.dev/items?sources=big"));
  const oversizedBody = await oversized.json();
  assert.equal(oversizedBody.sources[0].status, "unavailable");
  assert.equal(oversizedBody.items.length, 0);
});

test("a request fetches only the named sources and stops after per items", async () => {
  const feeds = [
    { key: "krebs", name: "Krebs on Security", url: "https://krebsonsecurity.com/feed/", category: "Security" },
    { key: "unit42", name: "Unit 42", url: "https://unit42.example/feed.xml", category: "Security" },
    { key: "wired", name: "Wired", url: "https://www.wired.com/feed/rss", category: "Security" }
  ];
  const calls = [];
  let reads = 0;
  const fetchImpl = async (url) => {
    calls.push(String(url));
    if (String(url).includes("krebsonsecurity")) {
      const chunks = [
        new TextEncoder().encode(rssItem({ title: "First", link: "https://krebsonsecurity.com/1" }).replace("</channel>", "")),
        new TextEncoder().encode("<item><title>Second</title><link>https://krebsonsecurity.com/2</link><pubDate>" + WHEN + "</pubDate><description>" + "y".repeat(300000) + "</description></item></channel></rss>")
      ];
      let index = 0;
      return {
        status: 200,
        ok: true,
        headers: { get() { return null; } },
        body: {
          getReader() {
            return {
              async read() {
                reads += 1;
                if (index >= chunks.length) return { done: true, value: undefined };
                const value = chunks[index];
                index += 1;
                return { done: false, value };
              },
              async cancel() {}
            };
          }
        }
      };
    }
    return new Response(rssItem({ title: "Other", link: "https://example.com/other" }), { status: 200 });
  };
  const handle = handlerFor(feeds, fetchImpl, () => Date.parse("2026-11-13T18:00:00Z"));
  const blockedName = ["crowd", "strike"].join("");
  const response = await handle(new Request(
    "https://timsonner-feeds.timsonner.workers.dev/items?sources=krebs," + blockedName + "&per=1"
  ));
  const body = await response.json();
  assert.equal(body.items.length, 1);
  assert.equal(body.items[0].title, "First");
  assert.equal(body.items[0].source, "krebs");
  assert.deepEqual(calls, ["https://krebsonsecurity.com/feed/"]);
  assert.equal(reads, 1);

  const again = await handle(new Request("https://timsonner-feeds.timsonner.workers.dev/items?sources=krebs&per=1"));
  const againBody = await again.json();
  assert.equal(againBody.items.length, 1);
  assert.equal(calls.length, 1);

  const chunkSize = 64 * 1024;
  let sent = 0;
  let wideReads = 0;
  const wide = createHandler({
    feeds: [{ key: "wide", name: "Wide", url: "https://example.com/wide.xml", category: "Security" }],
    cache: memoryCache(),
    now: () => Date.parse("2026-11-13T18:00:00Z"),
    fetchImpl: async () => ({
      status: 200,
      ok: true,
      headers: { get() { return null; } },
      body: {
        getReader() {
          return {
            async read() {
              wideReads += 1;
              if (sent >= MAX_SCAN * 4) return { done: true, value: undefined };
              const bytes = new Uint8Array(chunkSize);
              if (sent === 0) {
                const head = new TextEncoder().encode(
                  "<rss><channel><item><title>Partial</title><link>https://example.com/p</link><pubDate>" + WHEN + "</pubDate><description>"
                );
                bytes.set(head);
              }
              sent += chunkSize;
              return { done: false, value: bytes };
            },
            async cancel() {}
          };
        }
      }
    })
  });
  const wideResponse = await wide(new Request("https://timsonner-feeds.timsonner.workers.dev/items?sources=wide&per=5"));
  const wideBody = await wideResponse.json();
  assert.equal(wideBody.items[0].title, "Partial");
  assert.ok(wideReads * chunkSize <= MAX_SCAN + chunkSize);

  const bare = await handle(new Request("https://timsonner-feeds.timsonner.workers.dev/items"));
  const bareBody = await bare.json();
  assert.equal(bareBody.items.length, 0);
  assert.equal(bareBody.sources.length, 0);
  assert.equal(calls.length, 1);
});

test("optional fetch proxy targets three keys when both secrets are set", async () => {
  const { calls, fetchImpl } = captureFetch();
  const handle = handlerFor(
    PROXY_FEEDS,
    fetchImpl,
    () => Date.parse("2026-11-13T18:00:00Z"),
    PROXY_ENV
  );
  for (const key of ["bleeping", "nixcraft", "netsec"]) {
    calls.length = 0;
    const response = await handle(new Request(
      "https://timsonner-feeds.timsonner.workers.dev/items?sources=" + key
    ));
    assert.equal(response.status, 200);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://proxy.example/" + key);
    assert.equal(calls[0].proxyKey, PROXY_ENV.FEED_PROXY_KEY);
  }

  calls.length = 0;
  await handle(new Request(
    "https://timsonner-feeds.timsonner.workers.dev/items?sources=krebs"
  ));
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://krebsonsecurity.com/feed/");
  assert.equal(calls[0].proxyKey, null);
});

test("proxy path is skipped when either secret is missing", async () => {
  const { calls, fetchImpl } = captureFetch();
  const handle = handlerFor(
    PROXY_FEEDS,
    fetchImpl,
    () => Date.parse("2026-11-13T18:00:00Z"),
    { FEED_PROXY_URL: "https://proxy.example" }
  );
  for (const feed of PROXY_FEEDS.filter((row) => row.key !== "krebs")) {
    calls.length = 0;
    await handle(new Request(
      "https://timsonner-feeds.timsonner.workers.dev/items?sources=" + feed.key
    ));
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, feed.url);
    assert.equal(calls[0].proxyKey, null);
  }
});

test("proxy redirects do not send the proxy key to another host", async () => {
  const { calls, fetchImpl } = captureFetch({
    bleeping: new Response(null, {
      status: 302,
      headers: { Location: "https://cdn.example/feed.xml" }
    }),
    redirect: new Response(rssItem({
      title: "After redirect",
      link: "https://example.com/after"
    }), { status: 200 })
  });
  const handle = handlerFor(
    [PROXY_FEEDS[0]],
    fetchImpl,
    () => Date.parse("2026-11-13T18:00:00Z"),
    PROXY_ENV
  );
  const response = await handle(new Request(
    "https://timsonner-feeds.timsonner.workers.dev/items?sources=bleeping"
  ));
  assert.equal(response.status, 200);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, "https://proxy.example/bleeping");
  assert.equal(calls[0].proxyKey, PROXY_ENV.FEED_PROXY_KEY);
  assert.equal(calls[1].url, "https://cdn.example/feed.xml");
  assert.equal(calls[1].proxyKey, null);
  const body = await response.json();
  assert.equal(body.items.some((item) => item.title === "After redirect"), true);
});

test("wrangler config names the feeds Worker and allows localhost only here", () => {
  const toml = fs.readFileSync(new URL("../wrangler.toml", import.meta.url), "utf8");
  assert.match(toml, /name = "timsonner-feeds"/);
  assert.deepEqual(ALLOWED_ORIGINS, [
    "https://timsonner.com",
    "https://www.timsonner.com",
    "https://timsonner.github.io",
    "http://localhost:4000"
  ]);
});
