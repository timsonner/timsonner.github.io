document.addEventListener('DOMContentLoaded', (event) => {
  // Target only the wrapper div to avoid double buttons (Jekyll uses div.highlight > pre.highlight)
  const codeBlocks = document.querySelectorAll('div.highlight');

  codeBlocks.forEach((block) => {
    // Check if button already exists
    if (block.querySelector('.copy-code-button')) return;

    const button = document.createElement('button');
    button.className = 'copy-code-button';
    button.type = 'button';
    button.innerText = 'Copy';

    button.addEventListener('click', () => {
      let code = block.querySelector('code');
      let text = code ? code.innerText : block.innerText;

      // Fallback function for browsers that don't support clipboard API or are in non-secure contexts
      const copyToClipboardFallback = (text) => {
        const textArea = document.createElement("textarea");
        textArea.value = text;
        textArea.style.position = "fixed"; // Avoid scrolling to bottom
        textArea.style.opacity = "0";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();

        try {
          const successful = document.execCommand('copy');
          if (successful) {
            button.innerText = 'Copied!';
            setTimeout(() => button.innerText = 'Copy', 2000);
          } else {
            button.innerText = 'Error';
          }
        } catch (err) {
          console.error('Fallback copy failed', err);
          button.innerText = 'Error';
        }
        document.body.removeChild(textArea);
      };

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
          button.innerText = 'Copied!';
          setTimeout(() => {
            button.innerText = 'Copy';
          }, 2000);
        }).catch(err => {
          console.warn('Clipboard API failed, trying fallback', err);
          copyToClipboardFallback(text);
        });
      } else {
        copyToClipboardFallback(text);
      }
    });

    block.appendChild(button);
  });
});
