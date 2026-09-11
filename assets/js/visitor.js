// Fetch visitor IP and location information
async function fetchVisitorInfo() {
  const greetingElement = document.getElementById('visitor-greeting');
  
  try {
    const response = await fetch('https://ipapi.co/json/');
    const data = await response.json();
    
    if (data.ip && data.city && data.region) {
      const location = `${data.city}, ${data.region}`;
      const userAgent = navigator.userAgent;

      greetingElement.innerHTML = `
        <span class="info-item"><span class="visitor-label">Visitor:</span> ${data.ip}</span>
        <span class="info-separator">|</span>
        <span class="info-item"><span class="visitor-label">Location:</span> ${location}</span>
        <span class="info-separator">|</span>
        <span class="info-item"><span class="visitor-label">Data:</span> <a href="https://ipapi.co" target="_blank">ipapi.co</a></span>
        <span class="info-item"><span class="visitor-label">UA:</span> ${userAgent}</span>
      `;

    } else {
      greetingElement.innerHTML = 'Welcome, visitor!';
    }
  } catch (error) {
    console.log('Could not fetch visitor info:', error);
    greetingElement.innerHTML = 'Welcome to my blog!';
  }
}

const timeFormatters = {};

function getTimeFormatter(timeZone, format) {
  const key = `${timeZone}:${format}`;
  if (!timeFormatters[key]) {
    const options = format === '24'
      ? { timeZone, hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' }
      : { timeZone, hour: 'numeric', minute: '2-digit', second: '2-digit', hour12: true };
    timeFormatters[key] = new Intl.DateTimeFormat('en-US', options);
  }
  return timeFormatters[key];
}

function updateTimezoneClocks() {
  const now = new Date();
  document.querySelectorAll('.timezone-time[data-tz][data-format]').forEach((el) => {
    const timeZone = el.dataset.tz;
    const format = el.dataset.format;
    el.textContent = getTimeFormatter(timeZone, format).format(now);
  });
}

function startTimezoneClocks() {
  if (!document.getElementById('timezone-clocks')) {
    return;
  }

  updateTimezoneClocks();
  setInterval(updateTimezoneClocks, 1000);
}

// Load visitor info and US timezone clocks when the page loads
document.addEventListener('DOMContentLoaded', () => {
  fetchVisitorInfo();
  startTimezoneClocks();
});
