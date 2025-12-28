# Copilot Instructions for AI Agents

## Project Overview
This is a Jekyll-powered static blog hosted on GitHub Pages, featuring a custom terminal emulator and cybersecurity-focused content. The site uses the Minima theme as a base but includes significant custom JavaScript and SCSS for interactive features.

## Architecture & Core Components
- **Engine:** Jekyll (Ruby) via `github-pages` gem.
- **Theme:** Minima (customized).
- **Templating:** Liquid templates in `_layouts/` and `_includes/`.
- **Styling:** SCSS in `assets/main.scss` importing from `_sass/`.
- **Scripts:** Vanilla JavaScript in `assets/js/` for interactive features.

## Key Directories & Files
- `_posts/`: Content files. Naming: `YYYY-MM-DD-title.md`.
- `_includes/`: Reusable components.
  - `terminal.html`: Structure for the interactive terminal.
  - `head.html`, `header.html`, `footer.html`: Standard site partials.
- `assets/js/`:
  - `terminal.js`: Logic for the terminal emulator (command processing, history).
  - `copy-code.js`: Functionality for code block copy buttons.
  - `visitor.js`: Visitor tracking logic.
- `_sass/`:
  - `terminal.scss`: Styles for the terminal emulator.
  - `code-blocks.scss`: Custom syntax highlighting styles.
  - `variables.scss`: Site-wide variables (colors, fonts).
- `_config.yml`: Site configuration, including permalink structure `/:categories/:year/:month/:day/:title/`.

## Developer Workflows
- **Setup:** `bundle install`
- **Run Local Server:** `bundle exec jekyll serve` (Access at `http://localhost:4000`)
- **Deployment:** Push to `main` branch triggers GitHub Pages build.

## Project-Specific Conventions
- **Front Matter:**
  - Posts must include `layout: post`, `title`, `date`, `categories`.
  - Example:
    ```yaml
    layout: post
    title: "My Post"
    date: 2025-01-01 12:00:00 -0000
    categories: [security, tutorial]
    ```
- **Terminal Feature:**
  - The terminal is a key feature. Modifications to terminal behavior go in `assets/js/terminal.js`.
  - Styles are in `_sass/terminal.scss`.
  - The terminal HTML structure is defined in `_includes/terminal.html`.
- **Images:**
  - Store in `assets/images/<post-slug>/` for organization.
  - Reference: `{{ site.baseurl }}/assets/images/<post-slug>/image.png`.
- **Code Blocks:**
  - Use standard markdown fences.
  - `copy-code.js` automatically adds copy buttons to these blocks.
  - Syntax highlighting is handled by Rouge (configured in `_config.yml`).

## Integration Points
- **Plugins:** `jekyll-feed`, `jekyll-sitemap`, `jekyll-seo-tag` are enabled in `_config.yml`.
- **External Assets:** No heavy external frameworks (Bootstrap/Tailwind) detected; styles are custom SCSS.

## Tips for AI Agents
- When adding posts, ensure the filename date matches the front matter date.
- If modifying the terminal, check `processCommand` in `terminal.js` for command handling logic.
- Respect the `_sass` modular structure; don't dump everything in `main.scss`.
- Use `{{ site.baseurl }}` for all internal links to ensure compatibility with GitHub Pages subpath deployment if applicable.
- Always check `_config.yml` for site-wide settings before making global changes.
