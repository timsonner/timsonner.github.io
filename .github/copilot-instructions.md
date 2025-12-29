
# Copilot Instructions for AI Agents

## Project Overview
This is a Jekyll-powered cybersecurity blog hosted on GitHub Pages. It features a custom interactive terminal, advanced code block UX, and detailed technical walkthroughs. The site is based on the Minima theme but is heavily customized with JavaScript and SCSS for interactivity and branding.

## Architecture & Key Components
- **Engine:** Jekyll (Ruby, via `github-pages` gem)
- **Theme:** Minima (customized)
- **Templating:** Liquid templates in `_layouts/` and `_includes/`
- **Styling:** SCSS in `assets/main.scss` and modular partials in `_sass/`
- **Scripts:** Vanilla JavaScript in `assets/js/` for all interactivity

### Major Features
- **Interactive Terminal:**
  - Structure: `_includes/terminal.html`
  - Logic: `assets/js/terminal.js` (see `processCommand` for command handling)
  - Styles: `_sass/terminal.scss`
- **Code Blocks:**
  - Markdown fences, highlighted by Rouge (see `_config.yml`)
  - Copy buttons auto-injected by `assets/js/copy-code.js`
  - Styles in `_sass/code-blocks.scss`
- **Visitor Info:**
  - Logic: `assets/js/visitor.js` (fetches and displays IP/location)
- **Email Header Analyzer:**
  - Structure and logic: `_includes/email-parser.html` (all processing is client-side)

## Developer Workflows
- **Setup:** `bundle install`
- **Local Dev:** `bundle exec jekyll serve` (visit `http://localhost:4000`)
- **Deploy:** Push to `main` branch; GitHub Pages auto-builds

## Project-Specific Conventions
- **Posts:**
  - Filename: `YYYY-MM-DD-title.md` (date must match front matter)
  - Front matter must include: `layout: post`, `title`, `date`, `categories`
  - Example:
    ```yaml
    layout: post
    title: "Example Post"
    date: 2025-01-01 12:00:00 -0000
    categories: [security, tutorial]
    ```
- **Images:**
  - Store in `assets/images/<post-slug>/`
  - Reference as `{{ site.baseurl }}/assets/images/<post-slug>/image.png`
- **Internal Links:**
  - Always use `{{ site.baseurl }}` for compatibility with subpath deployments
- **SCSS:**
  - Use `_sass/` partials for modularity; import into `assets/main.scss`
  - Do not place all styles in `main.scss`
- **Terminal:**
  - Add/modify commands in `processCommand` in `assets/js/terminal.js`
  - Use `_sass/terminal.scss` for terminal-specific styles
- **Code Block Copy:**
  - `copy-code.js` auto-injects copy buttons into all code blocks

## Integration Points & Plugins
- **Jekyll Plugins:** `jekyll-feed`, `jekyll-sitemap`, `jekyll-seo-tag` (see `_config.yml`)
- **No external CSS frameworks** (Bootstrap/Tailwind not used)
- **SEO & Social:** Meta tags and OpenGraph in `_includes/head.html` and `favicon-og.html`

## Examples & Patterns
- **Terminal Command Example:** See `processCommand` in `assets/js/terminal.js` for how commands are registered and handled
- **Image Reference Example:**
  ```markdown
  ![TryHackMe Blue team hero illustration showing a confident cybersecurity analyst at a glowing terminal surrounded by digital network graphics in a dark blue command center environment]
  (\{{ site.baseurl \}}/assets/images/thm-blue/thm-blue-hero.png)
  ```
- **Code Block Example:**
  ```markdown
  ```python
  print("Hello, world!")
  ```
  ```

## Tips for AI Agents
- Always check `_config.yml` for global settings (permalinks, plugins, author info)
- When adding posts, ensure filename and front matter dates match
- For terminal changes, update both JS and SCSS as needed
- Use modular SCSS; avoid style duplication
- Reference images and internal links with `{{ site.baseurl }}`
- Review `README.md` for additional workflow and structure details
