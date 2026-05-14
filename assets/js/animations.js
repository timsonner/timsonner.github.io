document.addEventListener('DOMContentLoaded', function() {

  // ── Typewriter effect on hero description ─────────────────────────────────
  const desc = document.querySelector('.site-description');
  if (desc) {
    const text = desc.textContent;
    desc.textContent = '';

    let i = 0;
    const timer = setInterval(function() {
      if (i < text.length) {
        desc.textContent += text[i];
        i++;
      } else {
        clearInterval(timer);
      }
    }, 18);
  }

  // ── Scroll-in fade for sections and post cards ────────────────────────────
  const observer = new IntersectionObserver(function(entries) {
    entries.forEach(function(entry) {
      if (entry.isIntersecting) {
        entry.target.classList.add('is-visible');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.08, rootMargin: '0px 0px -40px 0px' });

  // Section labels and tool sections
  document.querySelectorAll('.section-label, .tool-section').forEach(function(el) {
    el.classList.add('fade-up');
    observer.observe(el);
  });

  // Post cards — staggered delay
  document.querySelectorAll('.post-item').forEach(function(el, i) {
    el.classList.add('fade-up');
    el.style.transitionDelay = (i * 0.07) + 's';
    observer.observe(el);
  });

});
