# Copilot Instructions for AI Agents

## Project Overview
This is a Jekyll-powered static blog hosted on GitHub Pages. The site uses Markdown for content, with layouts and includes for templating, and supports syntax highlighting and image embedding. The project is organized for clarity and ease of content management.

## Key Structure & Conventions
- **Posts:** Markdown files in `_posts/` named `YYYY-MM-DD-title.md`.
- **Layouts:** HTML templates in `_layouts/` (e.g., `default.html`, `post.html`).
- **Includes:** Reusable HTML snippets in `_includes/` (e.g., `header.html`, `footer.html`).
- **Assets:** Images in `assets/images/`, styles in `assets/main.scss` and `assets/syntax-highlighting.css`.
- **Config:** Site-wide settings in `_config.yml` (title, author, social, etc.).
- **Pages:** Add new pages by creating `.md` files in the root with front matter.

## Developer Workflows
- **Local Development:**
  1. Install Ruby and Bundler
  2. Run `bundle install`
  3. Start server: `bundle exec jekyll serve` (site at http://localhost:4000)
- **Deployment:**
  - Push to `main` branch; GitHub Pages auto-deploys.

## Project-Specific Patterns
- **Front Matter:** All posts/pages require YAML front matter (layout, title, date, etc.).
- **Images:** Place in `assets/images/` and reference with `{{ site.baseurl }}/assets/images/...`.
- **Code Blocks:** Use triple backticks with language for syntax highlighting.
- **Styling:** Edit `assets/main.scss` for site-wide styles; `assets/syntax-highlighting.css` for code.
- **SEO:** Meta tags and sitemap are auto-generated via Jekyll plugins.

## Examples
- **Post Example:** See `_posts/2023-07-11-golang-malware-rc4.md` for structure.
- **Layout Example:** See `_layouts/post.html` for blog post HTML structure.
- **Image Example:** See `assets/images/thm-blue/` for image organization.

## Tips for AI Agents
- Follow the naming and directory conventions strictly.
- Always include required front matter in new posts/pages.
- Reference images and assets using the correct base URL pattern.
- For new features, prefer Jekyll/Liquid patterns over custom scripts.
- Review `_config.yml` for site-wide settings before making global changes.

---
For more, see the project [README.md](../README.md) and Jekyll documentation.
