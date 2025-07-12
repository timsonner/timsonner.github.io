# GitHub Pages Blog

A Jekyll-powered blog hosted on GitHub Pages with syntax highlighting and image support.

## 🚀 Features

- **Beautiful Design**: Clean, modern, responsive layout
- **Syntax Highlighting**: Code blocks with Rouge syntax highlighter
- **Image Support**: Easy image embedding with optimization tips
- **SEO Optimized**: Built-in SEO tags and sitemap generation
- **Fast Loading**: Optimized CSS and minimal JavaScript
- **Mobile Friendly**: Responsive design that works on all devices

## 📁 Project Structure

```
├── _config.yml          # Jekyll configuration
├── _layouts/            # Page layouts
│   ├── default.html     # Base layout
│   └── post.html        # Blog post layout
├── _includes/           # Reusable components
│   ├── head.html        # HTML head section
│   ├── header.html      # Site header
│   ├── footer.html      # Site footer
│   └── social.html      # Social media links
├── _posts/              # Blog posts (markdown files)
├── assets/              # Static assets
│   ├── images/          # Blog images
│   ├── main.scss        # Main stylesheet
│   └── syntax-highlighting.css  # Code highlighting styles
├── index.html           # Homepage
├── about.md             # About page
└── Gemfile              # Ruby dependencies
```

## 🛠️ Setup

1. **Clone or download** this repository to your local machine
2. **Push to GitHub**: Create a repository named `yourusername.github.io`
3. **Enable GitHub Pages**: Go to repository Settings > Pages > Source: Deploy from a branch (main)

## ✍️ Writing Blog Posts

Create new blog posts in the `_posts` directory with the following naming convention:
`YYYY-MM-DD-title.md`

### Example Post Structure

```markdown
---
layout: post
title: "Your Post Title"
date: 2025-07-12 10:00:00 -0000
categories: category1 category2
excerpt: "A brief description of your post."
---

# Your Content Here

Write your blog post content in Markdown...
```

### Adding Code Blocks

Use triple backticks with language specification:

```markdown
```javascript
function hello() {
    console.log("Hello, World!");
}
```
```

### Adding Images

1. Place images in `assets/images/`
2. Reference them in your posts:

```markdown
![Alt text]({{ site.baseurl }}/assets/images/your-image.png)
```

## 🎨 Customization

### Update Site Information

Edit `_config.yml` to update:
- Site title and description
- Author information
- Social media links
- URL settings

### Styling

- Modify `assets/main.scss` for general styling
- Update `assets/syntax-highlighting.css` for code highlighting themes

### Navigation

Add new pages by creating `.md` files in the root directory with proper front matter.

## 🔧 Local Development

If you want to test your blog locally:

1. Install Ruby and Bundler
2. Run `bundle install`
3. Run `bundle exec jekyll serve`
4. Visit `http://localhost:4000`

## 📱 Responsive Design

The blog is fully responsive and includes:
- Mobile-friendly navigation
- Optimized images
- Touch-friendly interface
- Fast loading on all devices

## 🚀 Deployment

Your blog will automatically deploy to `https://yourusername.github.io` when you push changes to the main branch.

## 📊 SEO Features

- Automatic sitemap generation
- SEO-optimized meta tags
- Social media sharing cards
- Fast loading times

## 🎯 Best Practices

- Use descriptive filenames for images
- Optimize images before uploading
- Write engaging post excerpts
- Use proper heading hierarchy
- Include alt text for images
- Test on multiple devices

## 📝 Content Ideas

- Tutorial posts with code examples
- Project showcases
- Tech industry insights
- Development tips and tricks
- Tool reviews and comparisons

---

Happy blogging! 🎉
