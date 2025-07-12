---
layout: post
title: "Welcome to My Blog - Getting Started with Jekyll and GitHub Pages"
date: 2025-07-12 10:00:00 -0000
categories: jekyll tutorial
excerpt: "Learn how to create a beautiful blog with Jekyll, complete with syntax highlighting and image support."
featured_image: "https://upload.wikimedia.org/wikipedia/commons/thumb/6/6e/Red_Panda_%2824986761703%29.jpg/320px-Red_Panda_%2824986761703%29.jpg"
---

# Welcome to My Blog!

This is my first blog post, and I'm excited to share how I set up this blog using Jekyll and GitHub Pages. In this post, I'll walk you through the key features and show you some examples of what you can do.

## Code Highlighting

One of the best features of this blog is syntax highlighting for code blocks. Here are some examples:

### JavaScript Example

```javascript
function greetUser(name) {
    if (!name) {
        throw new Error('Name is required');
    }
    
    const greeting = `Hello, ${name}! Welcome to my blog.`;
    console.log(greeting);
    
    return {
        message: greeting,
        timestamp: new Date().toISOString()
    };
}

// Usage
try {
    const result = greetUser('Developer');
    document.getElementById('greeting').textContent = result.message;
} catch (error) {
    console.error('Error:', error.message);
}
```

### Python Example

```python
import datetime
from typing import List, Dict

class BlogPost:
    def __init__(self, title: str, content: str, author: str):
        self.title = title
        self.content = content
        self.author = author
        self.created_at = datetime.datetime.now()
        self.tags: List[str] = []
    
    def add_tag(self, tag: str) -> None:
        """Add a tag to the blog post."""
        if tag not in self.tags:
            self.tags.append(tag.lower())
    
    def to_dict(self) -> Dict:
        """Convert blog post to dictionary."""
        return {
            'title': self.title,
            'content': self.content,
            'author': self.author,
            'created_at': self.created_at.isoformat(),
            'tags': self.tags
        }

# Create a new blog post
post = BlogPost(
    title="My First Post", 
    content="This is the content of my blog post.",
    author="Tim Sonner"
)
post.add_tag("tutorial")
post.add_tag("jekyll")

print(f"Created post: {post.title}")
```

### CSS Example

```css
/* Modern button styling */
.btn {
    display: inline-block;
    padding: 12px 24px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    text-decoration: none;
    border-radius: 8px;
    border: none;
    cursor: pointer;
    font-weight: 600;
    transition: all 0.3s ease;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0,0,0,0.2);
}

.btn:active {
    transform: translateY(0);
}
```

## Working with Images

You can easily add images to your blog posts. Just place them in an `assets/images` folder and reference them like this:

```markdown
![Blog Setup]({{ site.baseurl }}/assets/images/blog-setup.png)
```

## Markdown Features

This blog supports all standard Markdown features:

- **Bold text** and *italic text*
- [Links](https://github.com/timsonner)
- Lists (like this one!)

### Blockquotes

> "The best way to learn programming is by writing programs." - Anonymous

### Tables

| Language   | Use Case           | Difficulty |
|------------|-------------------|------------|
| JavaScript | Web Development   | Beginner   |
| Python     | Data Science      | Beginner   |
| Rust       | Systems Programming| Advanced   |

## Next Steps

In upcoming posts, I'll be covering:

1. **Advanced Jekyll Features** - Custom plugins and configurations
2. **Deployment Strategies** - CI/CD with GitHub Actions
3. **Performance Optimization** - Making your site lightning fast
4. **SEO Best Practices** - Getting found on search engines

## Conclusion

I'm excited to start this blogging journey and share my knowledge with the community. Stay tuned for more posts, and feel free to reach out if you have any questions or suggestions!

Happy coding! 🚀
