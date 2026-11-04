// Fetch visitor IP and location information
async function fetchVisitorInfo() {
  const greetingElement = document.getElementById('visitor-greeting');
  
  try {
    const response = await fetch('https://ipapi.co/json/');
    const data = await response.json();
    
    if (data.ip && data.city && data.region) {
      const location = `${data.city}, ${data.region}`;
      const userAgent = navigator.userAgent;

      const esc = (value) => String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');

      greetingElement.innerHTML = `
        <span class="visitor-row visitor-row-meta">
          <span class="info-item"><span class="visitor-label">Visitor:</span> ${esc(data.ip)}</span>
          <span class="info-separator">|</span>
          <span class="info-item"><span class="visitor-label">Location:</span> ${esc(location)}</span>
          <span class="info-separator">|</span>
          <span class="info-item"><span class="visitor-label">Data:</span> <a href="https://ipapi.co" target="_blank">ipapi.co</a></span>
        </span>
        <span class="visitor-row visitor-row-ua">
          <span class="info-item visitor-ua" title="${esc(userAgent)}"><span class="visitor-label">UA:</span> ${esc(userAgent)}</span>
        </span>
      `;

    } else {
      greetingElement.innerHTML = 'Welcome, visitor!';
    }
  } catch (error) {
    console.log('Could not fetch visitor info:', error);
    greetingElement.innerHTML = 'Welcome to my blog!';
  }
}

// Load visitor info when page loads
document.addEventListener('DOMContentLoaded', fetchVisitorInfo);
