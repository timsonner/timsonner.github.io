# timsonner.com

A Jekyll-powered cybersecurity blog hosted on GitHub Pages. Beyond write-ups and tutorials, the homepage includes interactive client-side tools: a command terminal, an email header/body parser, and a proxy browser for inspecting framed content and clickjacking behavior.

**Live site:** [https://timsonner.com](https://timsonner.com) · [https://timsonner.github.io](https://timsonner.github.io)

## Features

### Interactive Terminal
Browser-based terminal on the homepage (`_includes/terminal.html` + `assets/js/terminal.js`). Useful recon-style helpers, all run client-side:

| Command | Description |
|---|---|
| `help` | List available commands |
| `whois <domain>` | RDAP/WHOIS lookup |
| `dig <domain>` | DNS records |
| `osint <target>` | Quick OSINT link pack |
| `subdomains <domain>` | Subdomain discovery helpers |
| `headers <url>` | Fetch and review response headers (incl. framing/CSP checks) |
| `cve <id>` | CVE lookup |
| `mac <address>` | MAC vendor lookup |
| `subnet <cidr>` | Subnet calculator |
| `news` | Security news headlines |
| `date` / `clear` | Utilities |

Arrow keys walk command history. Window controls minimize, restore, and clear output.

### News
Headlines from the same public RSS feeds, on one page (`/news/`). Filters cover source, how many items per source (default 5, max 50), and a time window (24 hours, 48 hours, 7 days, all, or a from/to date range). The default view is Security and Advisories, five items each, from the last 48 hours.

A query such as `?sources=unit42,krebs&per=5&range=48h` restores that view, and the browser remembers the last view locally. The page loads each selected source on its own, again when you press Refresh, and every 15 minutes while the tab is visible. Item text is escaped. Only http and https links can be clicked. Copy link copies the URL.

The feed list is `assets/data/news-feeds.json`. Headlines come from the `timsonner-feeds` Worker in `workers/feeds/`. That Worker fetches only the sources named on the request and caches each one for 15 minutes. Deploy steps are in `workers/feeds/README.md`. Until that Worker is deployed, the page says the feeds API is not reachable yet.

### Email Parser
Client-side `.eml` / raw email analyzer (`_includes/email-parser.html`):

- Upload a file or paste raw message content
- Parse headers, body parts, and attachments in-browser
- No server upload — processing stays local

### Proxy Browser (X-Frame Demo)
Mini browser for investigating pages in-frame (`_includes/proxy-browser.html` + `assets/js/proxy-browser.js`):

- **Proxy Fetch** — load HTML through the Cloudflare Worker `timsonner-cors.timsonner.workers.dev`, inject `<base>` + nav interceptor (phishing / framed inspection without a full browser session)
- **Auto (race)** — races the configured backend list (Worker today); cancel in-flight loads; try-next on failure
- **Raw HTML** — inspect fetched source when render is broken
- **Direct iframe** — set `iframe src` directly to demo `X-Frame-Options` / `CSP frame-ancestors` blocking
- Back / forward / reload chrome and selectable proxy backends

### Blog & Site UX
- Technical walkthroughs (TryHackMe, AD lab notes, malware/dev posts)
- Rouge syntax highlighting with one-click code copy (`assets/js/copy-code.js`)
- Visitor greeting with IP/location hint (`assets/js/visitor.js`)
- SEO via `jekyll-seo-tag`, sitemap, and feed plugins
- Custom Minima-based theme with modular SCSS

## Project Structure

```
├── _config.yml              # Site config, plugins, permalinks
├── _layouts/                # default.html, post.html
├── _includes/
│   ├── terminal.html        # Interactive terminal shell
│   ├── email-parser.html    # Email header/body parser
│   ├── proxy-browser.html   # Proxy / X-Frame demo browser
│   ├── head.html            # Meta, OG, assets
│   ├── header.html / footer.html / social.html
│   └── favicon-og.html
├── _posts/                  # Blog posts (YYYY-MM-DD-title.md)
├── _sass/                   # SCSS partials (terminal, code-blocks, variables)
├── assets/
│   ├── main.scss            # Styles entrypoint
│   ├── js/                  # terminal.js, news.js, proxy-browser.js, copy-code.js, visitor.js, …
│   ├── data/news-feeds.json # Public feed allowlist for /news/
│   └── images/              # Per-post image folders
├── workers/feeds/           # timsonner-feeds Worker (not published by Jekyll)
├── index.html               # Homepage (tools + latest posts)
├── news.html                # News headlines
├── python.html
├── Gemfile                  # Ruby / GitHub Pages deps
└── .github/copilot-instructions.md
```

## Local Development

```bash
# System deps (Debian/Ubuntu) — run as root if needed
apt update
apt install -y ruby-full build-essential zlib1g-dev

# User gem path
echo 'export GEM_HOME="$HOME/gems"' >> ~/.bashrc
echo 'export PATH="$HOME/gems/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

gem install bundler
bundle install
bundle exec jekyll serve
```

Open [http://localhost:4000](http://localhost:4000).

### Deploy
Push to `main`. GitHub Pages builds from the branch automatically.

## Writing Posts

Filename: `_posts/YYYY-MM-DD-title.md` (date must match front matter).

```markdown
---
layout: post
title: "Your Post Title"
date: 2026-07-21 12:00:00 -0000
categories: [security, tutorial]
excerpt: "Short summary for listings and SEO."
---

Your content in Markdown…
```

**Code blocks** — fenced with a language tag; copy buttons are injected automatically:

````markdown
```python
print("Hello, world!")
```
````

**Images** — store under `assets/images/<post-slug>/` and reference with `site.baseurl`:

```markdown
![Descriptive alt text]({{ site.baseurl }}/assets/images/my-post/diagram.png)
```

## Customization

| Area | Where |
|---|---|
| Title, author, plugins, nav pages | `_config.yml` |
| Global styles | `assets/main.scss` + `_sass/` |
| Terminal commands | `processCommand` in `assets/js/terminal.js` |
| Terminal look | `_sass/terminal.scss` |
| News page | `news.html`, `assets/js/news.js`, `_sass/news.scss`, `assets/data/news-feeds.json` |
| Feeds Worker | `workers/feeds/` (deploy notes in that README) |
| Email parser / proxy browser | `_includes/email-parser.html`, `_includes/proxy-browser.html` + `assets/js/proxy-browser.js` |
| New pages | Root `.md` / `.html` + add to `header_pages` in `_config.yml` |

## Stack

- **Engine:** Jekyll via the `github-pages` gem
- **Theme base:** Minima (heavily customized)
- **Highlighting:** Rouge
- **Plugins:** `jekyll-feed`, `jekyll-sitemap`, `jekyll-seo-tag`
- **Front-end:** Vanilla JS + SCSS (no Bootstrap/Tailwind)

## License / Contact

Personal site and lab notes by [Tim Sonner](https://timsonner.com).  
Email: [tim@timsonner.com](mailto:tim@timsonner.com)
