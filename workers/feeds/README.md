# timsonner-feeds

Cached allowlist of public RSS and Atom feeds for the News page at `/news/`.

The Worker fetches only the URLs in `assets/data/news-feeds.json`. It is not an open proxy. Callers cannot pass a target URL. CrowdStrike hosts are rejected by key and by hostname, along with loopback, private, and link-local hosts.

GitHub Pages does not publish this directory. `_config.yml` excludes `workers`.

## Routes

- `GET /sources` returns a list of `{ key, name, category, status }`.
- `GET /items` returns `{ fetched_at, sources, items }`. Each item is `{ source, title, link, published }`. Titles are plain text. Links are http or https. Descriptions are not included.
- Any other path returns 404. Any other method returns 405.

Allowed browser origins are `https://timsonner.com`, `https://www.timsonner.com`, `https://timsonner.github.io`, and `http://localhost:4000` (this Worker only, so local Jekyll preview can load items).

## Cache

The item list is cached for 15 minutes (`Cache-Control: public, max-age=300, s-maxage=900`). A browser refresh inside that window does not fetch every upstream. If an upstream fails, the last good items for that source stay in the cache and the source is marked stale. Feeds are fetched with a small concurrency cap, a 12 second timeout, and an 8 MiB size cap.

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
