# timsonner-feeds

Cached allowlist of public RSS and Atom feeds for the News page at `/news/`.

The Worker fetches only the URLs in `assets/data/news-feeds.json`. It is not an open proxy. Callers cannot pass a target URL. CrowdStrike hosts are rejected by key and by hostname, along with loopback, private, and link-local hosts.

GitHub Pages does not publish this directory. `_config.yml` excludes `workers`.

## Routes

- `GET /sources` returns a list of `{ key, name, category, status }`. Status from this route is `unknown`. It does not fetch feeds.
- `GET /items?sources=krebs&per=5` returns `{ fetched_at, sources, items }` for the named allowlist keys only. `per` is 1 to 50 and defaults to 5. Each item is `{ source, title, link, published }`. Titles are plain text. Links are http or https. Descriptions are not included. A request with no `sources` returns an empty list. A `url` query cannot add a target.
- One request fetches at most one source that is not already in cache. Further named sources come back as `pending` so a long list cannot exceed the Workers Free CPU budget (about 10 ms). The News page requests one source at a time.
- Any other path returns 404. Any other method returns 405.

Allowed browser origins are `https://timsonner.com`, `https://www.timsonner.com`, `https://timsonner.github.io`, and `http://localhost:4000` (this Worker only, so local Jekyll preview can load items).

## Cache

Each source is cached on its own for 15 minutes. A later request for that source does not fetch it again until the cache is older than that. Parsing stops after `per` items, keeps only the start of each item, and does not scan more than 512 KB of a feed. If an upstream fails and a previous good copy is still stored, that copy is returned and the source is marked stale. A fetch uses a 12 second timeout and an 8 MiB size cap.

A cron warmer is not included. Cron triggers still have the free-plan CPU limit, and the Cache API is local to one location, so a schedule would not keep every location warm.

## Checks

From the repository root:

```bash
node --test workers/feeds/test/feeds.test.js
node --check assets/js/news.js
```

Local Worker (does not deploy):

```bash
cd workers/feeds
npx wrangler dev
```

Then open `http://localhost:8787/sources`. The News page on `http://localhost:4000/news/` calls the deployed hostname, not this local port.

## Deploy

Deploy only when you mean to publish this Worker. From `workers/feeds`:

```bash
npx wrangler login
npx wrangler deploy
```

The public hostname is `https://timsonner-feeds.timsonner.workers.dev`. Do not put tokens or account ids in this folder.

## Optional fetch proxy

Some catalog sources block Cloudflare egress. When both Worker secrets are set, the Worker fetches `bleeping`, `nixcraft`, and `netsec` through an optional fetch proxy configured by Worker secrets instead of their catalog URLs. All other sources are unchanged. If either secret is unset, every source uses its catalog URL as today.

Set the secrets from `workers/feeds` (do not commit values):

```bash
npx wrangler secret put FEED_PROXY_URL
npx wrangler secret put FEED_PROXY_KEY
```

`FEED_PROXY_URL` must be an `https` origin with no trailing slash. The Worker requests `{FEED_PROXY_URL}/{key}` for the three keys above and sends `X-Feed-Proxy-Key: {FEED_PROXY_KEY}`. Redirects off the proxy host do not include that header.
