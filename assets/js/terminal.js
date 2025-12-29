// Terminal Emulator Logic
document.addEventListener('DOMContentLoaded', function() {
  const terminalInput = document.getElementById('terminal-input');
  const terminalOutput = document.getElementById('terminal-output');
  const terminalWindow = document.getElementById('terminal-window');

  let commandHistory = [];
  let historyIndex = -1;

  // Focus input when clicking terminal, unless selecting text
  terminalWindow.addEventListener('click', function(e) {
    const selection = window.getSelection();
    if (selection.toString().length === 0) {
      terminalInput.focus();
    }
  });

  // Copy Terminal Button Logic
  const copyBtn = document.getElementById('copy-terminal-btn');
  if (copyBtn) {
    copyBtn.addEventListener('click', function() {
      const textToCopy = terminalOutput.innerText;
      if (window.copyToClipboard) {
        window.copyToClipboard(textToCopy, copyBtn);
      } else {
        console.error('copyToClipboard function not found');
      }
    });
  }

  // Terminal Window Controls
  const btnYellow = document.getElementById('terminal-btn-yellow');
  const btnGreen = document.getElementById('terminal-btn-green');
  const btnRed = document.getElementById('terminal-btn-red');
  
  if (btnYellow && terminalWindow) {
    btnYellow.addEventListener('click', function() {
      terminalWindow.style.display = 'none';
      // Remove bottom border radius from header when minimized
      const header = document.querySelector('.terminal-header');
      if (header) {
        header.style.borderBottomLeftRadius = '8px';
        header.style.borderBottomRightRadius = '8px';
        header.style.borderBottom = '1px solid #39ff14';
      }
    });
  }

  if (btnGreen && terminalWindow) {
    btnGreen.addEventListener('click', function() {
      terminalWindow.style.display = 'block';
      // Restore header styles
      const header = document.querySelector('.terminal-header');
      if (header) {
        header.style.borderBottomLeftRadius = '0';
        header.style.borderBottomRightRadius = '0';
        header.style.borderBottom = 'none';
      }
      terminalInput.focus();
    });
  }

  if (btnRed && terminalOutput) {
    btnRed.addEventListener('click', function() {
      terminalOutput.innerHTML = '';
      terminalInput.focus();
    });
  }

  terminalInput.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') {
      const input = terminalInput.value;
      
      if (input.trim() !== '') {
        commandHistory.push(input);
        historyIndex = commandHistory.length;
      }
      
      processCommand(input);
      terminalInput.value = '';
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (historyIndex > 0) {
        historyIndex--;
        terminalInput.value = commandHistory[historyIndex];
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex < commandHistory.length - 1) {
        historyIndex++;
        terminalInput.value = commandHistory[historyIndex];
      } else {
        historyIndex = commandHistory.length;
        terminalInput.value = '';
      }
    }
  });

  function processCommand(input) {
    const parts = input.trim().split(/\s+/);
    const command = parts[0].toLowerCase();
    const args = parts.slice(1);

    // Add command to output
    addToOutput(`guest@timsonner.com:~$ ${input}`);

    if (input.trim() === '') return;

    switch(command) {
      case 'help':
        addToOutput('Available commands: help, clear, date, whois, dig, osint, subdomains, headers, mac, cve, news');
        break;
      case 'news':
        handleNews(args);
        break;
      case 'date':
        addToOutput(new Date().toString());
        break;
      case 'clear':
        terminalOutput.innerHTML = '';
        break;
      case 'whois':
        handleWhois(args);
        break;
      case 'dig':
        handleDig(args);
        break;
      case 'osint':
        handleOsint(args);
        break;
      case 'subdomains':
        handleSubdomains(args);
        break;
      case 'headers':
        handleHeaders(args);
        break;
      case 'cve':
        handleCVE(args);
        break;
      case 'mac':
        handleMac(args);
        break;
      default:
        addToOutput(`Command not found: ${command}`, 'command-error');
    }
    
    // Scroll to bottom
    terminalWindow.scrollTop = terminalWindow.scrollHeight;
  }

  function addToOutput(text, className = '', isHtml = false) {
    const div = document.createElement('div');
    div.className = `terminal-line ${className}`;
    if (isHtml) {
      div.innerHTML = text;
    } else {
      div.textContent = text;
    }
    terminalOutput.appendChild(div);
  }

  async function handleWhois(args) {
    if (args.length === 0) {
      addToOutput('Usage: whois <domain>');
      return;
    }
    
    const domain = args[0];
    addToOutput(`Querying RDAP for ${domain}...`);
    
    try {
      const response = await fetch(`https://rdap.org/domain/${domain}`);
      
      if (!response.ok) {
        if (response.status === 404) {
          addToOutput(`Domain '${domain}' not found or TLD not supported.`, 'command-error');
        } else {
          addToOutput(`Error querying domain: ${response.status}`, 'command-error');
        }
        return;
      }
      
      const data = await response.json();
      
      // Format Output
      addToOutput('----------------------------------------');
      addToOutput(`Domain Name: ${data.ldhName || data.handle}`);
      if (data.handle) addToOutput(`Registry Domain ID: ${data.handle}`);
      
      if (data.status) {
        addToOutput(`Status: ${data.status.join(', ')}`);
      }
      
      if (data.secureDNS) {
         addToOutput(`DNSSEC: ${data.secureDNS.delegationSigned ? 'signedDelegation' : 'unsigned'}`);
      }
      
      if (data.events) {
        data.events.forEach(event => {
          let date = new Date(event.eventDate).toISOString().split('T')[0];
          addToOutput(`${event.eventAction}: ${date}`);
        });
      }
      
      if (data.nameservers) {
        const ns = data.nameservers.map(n => n.ldhName).join(', ');
        addToOutput(`Name Servers: ${ns}`);
      }
      
      // Process Entities (Registrar, Registrant, Admin, etc.)
      if (data.entities) {
        addToOutput(''); // Spacer
        processEntities(data.entities);
      }
      
      // Notices
      if (data.notices) {
        addToOutput('');
        data.notices.forEach(notice => {
           if (notice.title) addToOutput(`Notice: ${notice.title}`);
           if (notice.description) notice.description.forEach(d => addToOutput(`  ${d}`));
        });
      }
      
      addToOutput('----------------------------------------');
      addToOutput('Data provided by rdap.org');
      
    } catch (error) {
      addToOutput(`Network error: ${error.message}`, 'command-error');
    }
    
    // Scroll to bottom after async operation
    terminalWindow.scrollTop = terminalWindow.scrollHeight;
  }

  async function handleDig(args) {
    if (args.length === 0) {
      addToOutput('Usage: dig <domain> [type] (default: A)');
      addToOutput('       Types: A, AAAA, CNAME, MX, TXT, NS, SOA');
      addToOutput('       dig <domain> DMARC');
      addToOutput('       dig <selector>._domainkey.<domain> DKIM');
      return;
    }

    let domain = args[0];
    let type = args[1] ? args[1].toUpperCase() : 'A';

    // Special handling for DMARC
    if (type === 'DMARC') {
        if (!domain.startsWith('_dmarc.')) {
            domain = '_dmarc.' + domain;
        }
        type = 'TXT';
        addToOutput(`; (Pseudo-type DMARC maps to ${domain} IN TXT)`);
    }

    // Special handling for DKIM
    if (type === 'DKIM') {
        addToOutput('; For DKIM, you need the selector.');
        addToOutput(`; Usage: dig <selector>._domainkey.${domain} TXT`);
        addToOutput('; Example: dig google._domainkey.example.com TXT');
        return;
    }
    
    addToOutput(`; <<>> DiG 9.10.6 <<>> ${domain} ${type}`);
    addToOutput(';; global options: +cmd');
    addToOutput(';; Got answer:');
    addToOutput(`;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ${Math.floor(Math.random() * 65535)}`);
    addToOutput(';; flags: qr rd ra; QUERY: 1, ANSWER: ?, AUTHORITY: 0, ADDITIONAL: 1');
    addToOutput('');
    addToOutput(';; QUESTION SECTION:');
    addToOutput(`;${domain}.\t\tIN\t${type}`);
    addToOutput('');

    try {
      const startTime = performance.now();
      const response = await fetch(`https://dns.google/resolve?name=${domain}&type=${type}`);
      const endTime = performance.now();
      const queryTime = Math.round(endTime - startTime);

      if (!response.ok) {
        addToOutput(`;; connection timed out; no servers could be reached`, 'command-error');
        return;
      }

      const data = await response.json();

      if (data.Status !== 0) {
         addToOutput(`;; ->>HEADER<<- status: ${data.Status === 3 ? 'NXDOMAIN' : 'SERVFAIL'}`);
      }

      if (data.Answer) {
        addToOutput(';; ANSWER SECTION:');
        data.Answer.forEach(record => {
          // Map type number to name if possible, or use raw type
          let typeName = 'A';
          if (record.type === 1) typeName = 'A';
          if (record.type === 28) typeName = 'AAAA';
          if (record.type === 5) typeName = 'CNAME';
          if (record.type === 15) typeName = 'MX';
          if (record.type === 16) typeName = 'TXT';
          if (record.type === 2) typeName = 'NS';
          if (record.type === 6) typeName = 'SOA';
          
          // If user requested a specific type, use that label, otherwise guess
          if (type !== 'A' && type !== 'AAAA') typeName = type;

          addToOutput(`${record.name}\t${record.TTL}\tIN\t${typeName}\t${record.data}`);
        });
        addToOutput('');
      }

      addToOutput(`;; Query time: ${queryTime} msec`);
      addToOutput(`;; SERVER: 8.8.8.8#53(8.8.8.8)`);
      addToOutput(`;; WHEN: ${new Date().toString()}`);
      addToOutput(`;; MSG SIZE  rcvd: ${JSON.stringify(data).length}`);
      addToOutput(`;; Data provided by Google Public DNS (dns.google)`);

    } catch (error) {
      addToOutput(`;; connection failed: ${error.message}`, 'command-error');
    }
    
    terminalWindow.scrollTop = terminalWindow.scrollHeight;
  }

  async function handleOsint(args) {
    if (args.length === 0) {
      addToOutput('Usage: osint <ip_address|domain>');
      return;
    }

    let ip = args[0];
    
    // Check if input is a domain (not an IP)
    const isIpv4 = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ip);
    const isIpv6 = ip.includes(':');
    
    if (!isIpv4 && !isIpv6) {
        addToOutput(`Resolving domain ${ip}...`);
        try {
            // Try IPv4 first
            let dnsResp = await fetch(`https://dns.google/resolve?name=${ip}&type=A`);
            let dnsData = await dnsResp.json();
            let resolved = false;

            if (dnsData.Answer) {
                const aRecord = dnsData.Answer.find(r => r.type === 1);
                if (aRecord) {
                    ip = aRecord.data;
                    addToOutput(`Resolved to IPv4: ${ip}`);
                    resolved = true;
                }
            }

            // If no IPv4, try IPv6
            if (!resolved) {
                dnsResp = await fetch(`https://dns.google/resolve?name=${ip}&type=AAAA`);
                dnsData = await dnsResp.json();
                if (dnsData.Answer) {
                    const aaaaRecord = dnsData.Answer.find(r => r.type === 28);
                    if (aaaaRecord) {
                        ip = aaaaRecord.data;
                        addToOutput(`Resolved to IPv6: ${ip}`);
                        resolved = true;
                    }
                }
            }

            if (!resolved) {
                throw new Error('Could not resolve domain (No A or AAAA records found)');
            }

        } catch (e) {
            addToOutput(`DNS Error: ${e.message}`, 'command-error');
            return;
        }
    }

    addToOutput(`Gathering intelligence for ${ip}...`);
    addToOutput('----------------------------------------');

    // 1. Geo/Network Info (ipwho.is)
    try {
      const geoResponse = await fetch(`https://ipwho.is/${ip}`);
      const geoData = await geoResponse.json();

      if (geoData.success) {
        addToOutput(`[Network Info]`);
        addToOutput(`  IP Type: ${geoData.type}`);
        addToOutput(`  Location: ${geoData.city}, ${geoData.region}, ${geoData.country} ${geoData.flag ? geoData.flag.emoji : ''}`);
        addToOutput(`  Continent: ${geoData.continent} (${geoData.continent_code})`);
        addToOutput(`  Coordinates: ${geoData.latitude}, ${geoData.longitude}`);
        if (geoData.postal) addToOutput(`  Postal Code: ${geoData.postal}`);
        if (geoData.calling_code) addToOutput(`  Calling Code: +${geoData.calling_code}`);
        
        addToOutput(`  ISP: ${geoData.connection.isp}`);
        addToOutput(`  ASN: AS${geoData.connection.asn} (${geoData.connection.org})`);
        if (geoData.connection.domain) addToOutput(`  Domain: ${geoData.connection.domain}`);
        
        if (geoData.timezone) {
            addToOutput(`  Timezone: ${geoData.timezone.id} (${geoData.timezone.utc})`);
            addToOutput(`  Local Time: ${geoData.timezone.current_time}`);
        }
      } else {
        addToOutput(`[Network Info] Failed: ${geoData.message}`, 'command-error');
      }
    } catch (e) {
      addToOutput(`[Network Info] Error: ${e.message}`, 'command-error');
    }

    // 2. Tor Node Check (Onionoo)
    try {
        const torResponse = await fetch(`https://onionoo.torproject.org/details?search=${ip}`);
        const torData = await torResponse.json();
        
        if (torData.relays.length > 0 || torData.bridges.length > 0) {
            addToOutput(`[Tor Check]`);
            addToOutput(`  ⚠️  CONFIRMED TOR NODE`, 'command-error');
            if (torData.relays.length > 0) {
                const relay = torData.relays[0];
                addToOutput(`  Nickname: ${relay.nickname}`);
                addToOutput(`  Platform: ${relay.platform}`);
                addToOutput(`  Contact: ${relay.contact || 'None'}`);
            }
        }
    } catch (e) {
        // Silent fail for Tor check if network error, or log it
        // addToOutput(`[Tor Check] Error: ${e.message}`, 'command-error');
    }

    // 3. Reputation/Spam Check (StopForumSpam)
    try {
      const spamResponse = await fetch(`https://api.stopforumspam.org/api?ip=${ip}&json`);
      const spamData = await spamResponse.json();

      addToOutput(`[Reputation Check]`);
      if (spamData.success) {
        if (spamData.ip.appears) {
           addToOutput(`  ⚠️  FLAGGED: This IP appears in the spam database!`, 'command-error');
           addToOutput(`  Frequency: ${spamData.ip.frequency}`);
           addToOutput(`  Last Seen: ${spamData.ip.lastseen}`);
           if (spamData.ip.confidence) addToOutput(`  Confidence: ${spamData.ip.confidence}%`);
           if (spamData.ip.delegated) addToOutput(`  Delegated: ${spamData.ip.delegated}`);
           if (spamData.ip.country) addToOutput(`  Country: ${spamData.ip.country}`);
           if (spamData.ip.asn) addToOutput(`  ASN: ${spamData.ip.asn}`);
        } else {
           addToOutput(`  ✅  CLEAN: No recent spam reports found.`);
           addToOutput(`  Frequency: ${spamData.ip.frequency}`);
           addToOutput(`  Appears: ${spamData.ip.appears}`);
        }
      } else {
        addToOutput(`  Could not verify reputation.`);
      }
    } catch (e) {
      addToOutput(`[Reputation Check] Error: ${e.message}`, 'command-error');
    }
    
    addToOutput('----------------------------------------');
    addToOutput('Data provided by ipwho.is, onionoo.torproject.org, and stopforumspam.org');
    addToOutput('----------------------------------------');
    addToOutput(`[External Links]`);
    
    const target = args[0];
    const targetIsIpv4 = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target);
    const targetIsIpv6 = target.includes(':');
    const targetIsIp = targetIsIpv4 || targetIsIpv6;

    const links = [];
    
    // Universal (IP & Domain)
    links.push({ name: 'Talos Intelligence', url: `https://talosintelligence.com/reputation_center/lookup?search=${target}` });
    links.push({ name: 'FortiGuard', url: `https://www.fortiguard.com/search?q=${target}&engine=1` });
    links.push({ name: 'Google Safe Browsing', url: `https://transparencyreport.google.com/safe-browsing/search?url=${target}` });
    links.push({ name: 'Sucuri SiteCheck', url: `https://sitecheck.sucuri.net/results/${target}` });
    links.push({ name: 'Spamhaus', url: `https://check.spamhaus.org/listed/?searchterm=${target}` });
    links.push({ name: 'DomainTools', url: `https://whois.domaintools.com/${target}` });
    links.push({ name: 'IBM X-Force', url: `https://exchange.xforce.ibmcloud.com/url/${target}` });
    links.push({ name: 'CRT.sh', url: `https://crt.sh/?q=${target}` });
    links.push({ name: 'VirusTotal', url: `https://www.virustotal.com/gui/search/${target}` });
    links.push({ name: 'AlienVault OTX', url: `https://otx.alienvault.com/indicator/${targetIsIp ? 'ip' : 'domain'}/${target}` });
    links.push({ name: 'IBM X-Force', url: `https://exchange.xforce.ibmcloud.com/ip/${target}` });

    if (targetIsIp) {
        // IP Only
        links.push({ name: 'IPInfo', url: `https://ipinfo.io/${target}` });
        links.push({ name: 'Shodan', url: `https://www.shodan.io/host/${target}` });
        links.push({ name: 'Censys', url: `https://search.censys.io/hosts/${target}` });
        links.push({ name: 'Criminal IP', url: `https://www.criminalip.io/asset/search?query=${target}` });
        links.push({ name: 'AbuseIPDB', url: `https://www.abuseipdb.com/check/${target}` });
        links.push({ name: 'GreyNoise', url: `https://viz.greynoise.io/ip/${target}` });
        links.push({ name: 'Spur', url: `https://spur.us/context/${target}` });
        links.push({ name: 'ip-api', url: `https://ip-api.com/#${target}` });
        links.push({ name: 'ProxyCheck', url: `https://proxycheck.io/v3/${target}` });
        links.push({ name: 'IPQualityScore', url: `https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/${target}` });
        links.push({ name: 'IP2Location', url: `https://www.ip2location.io/${target}` });
    } else {
        // Domain Only
        links.push({ name: 'URLhaus', url: `https://urlhaus.abuse.ch/browse/search/${target}/` });
        links.push({ name: 'Urlscan.io', url: `https://urlscan.io/search/#${target}` });
    }
    
    links.forEach(link => {
        const anchor = `<a href="${link.url}" target="_blank" rel="noopener noreferrer" style="color: inherit; text-decoration: underline;">${link.name}</a>`;
        addToOutput(anchor, '', true);
    });
    terminalWindow.scrollTop = terminalWindow.scrollHeight;
  }

  async function handleSubdomains(args) {
    if (args.length === 0) {
      addToOutput('Usage: subdomains <domain>');
      return;
    }
    
    const domain = args[0];
    addToOutput(`Searching for subdomains of ${domain} via crt.sh...`);
    
    try {
      // Encode the query to ensure special characters like % are handled correctly
      const query = `%.${domain}`;
      const response = await fetch(`https://crt.sh/?q=${encodeURIComponent(query)}&output=json`);
      
      if (!response.ok) {
        addToOutput(`Error fetching subdomains: ${response.status} ${response.statusText}`, 'command-error');
        return;
      }
      
      const data = await response.json();
      
      if (!data || data.length === 0) {
        addToOutput(`No subdomains found for ${domain}.`);
        return;
      }
      
      // Extract and deduplicate subdomains
      const subdomains = new Set();
      data.forEach(entry => {
        const nameValue = entry.name_value;
        const names = nameValue.split('\n');
        names.forEach(name => {
            if (!name.includes('*')) { // Filter out wildcards
                subdomains.add(name.toLowerCase());
            }
        });
      });
      
      const sortedSubdomains = Array.from(subdomains).sort();
      
      addToOutput(`Found ${sortedSubdomains.length} unique subdomains:`);
      addToOutput('----------------------------------------');
      
      if (sortedSubdomains.length > 1000) {
          addToOutput(`(Warning: Rendering ${sortedSubdomains.length} items. This may freeze your browser briefly.)`);
      }
      
      sortedSubdomains.forEach(sub => addToOutput(sub));
      
      addToOutput('----------------------------------------');
      addToOutput('Data provided by crt.sh (Certificate Transparency)');
      
    } catch (error) {
      addToOutput(`Network error: ${error.message}`, 'command-error');
      addToOutput(`(This might be caused by AdBlockers, Privacy Extensions, or crt.sh being down)`, 'command-error');
    }
    terminalWindow.scrollTop = terminalWindow.scrollHeight;
  }

  async function handleHeaders(args) {
    if (args.length === 0) {
      addToOutput('Usage: headers <url>');
      return;
    }
    
    let url = args[0];
    // Strip protocol if present for cleaner display, but API handles it either way
    url = url.replace(/^https?:\/\//, '');
    
    addToOutput(`Fetching HTTP headers for ${url}...`);
    
    try {
      const response = await fetch(`https://api.hackertarget.com/httpheaders/?q=${url}`);
      
      if (!response.ok) {
        addToOutput(`Error fetching headers: ${response.status}`, 'command-error');
        return;
      }
      
      const text = await response.text();
      
      if (text.trim() === '') {
        addToOutput('No headers returned. Host might be down or blocking the scanner.', 'command-error');
        return;
      }
      
      addToOutput('----------------------------------------');
      
      // Parse headers for analysis
      const headerMap = {};
      const lines = text.split('\n');
      
      lines.forEach(line => {
          if (line.trim() !== '') {
              addToOutput(line);
              
              const parts = line.split(':');
              if (parts.length > 1) {
                  const key = parts[0].trim().toLowerCase();
                  const value = parts.slice(1).join(':').trim();
                  headerMap[key] = value;
              }
          }
      });
      
      addToOutput('----------------------------------------');
      addToOutput('Security Analysis:');

      // 1. HSTS
      if (headerMap['strict-transport-security']) {
          addToOutput('✅ [HSTS] Enforced');
      } else {
          addToOutput('❌ [HSTS] Missing (Vulnerable to MITM/Downgrade)', 'command-error');
      }

      // 2. Clickjacking
      if (headerMap['x-frame-options'] || headerMap['content-security-policy']?.includes('frame-ancestors')) {
          addToOutput('✅ [Clickjacking] Protected');
      } else {
          addToOutput('❌ [Clickjacking] Missing X-Frame-Options or CSP frame-ancestors', 'command-error');
      }

      // 3. MIME Sniffing
      if (headerMap['x-content-type-options'] === 'nosniff') {
          addToOutput('✅ [MIME Sniffing] Protected (nosniff)');
      } else {
          addToOutput('❌ [MIME Sniffing] Missing X-Content-Type-Options: nosniff', 'command-error');
      }

      // 4. XSS Protection (CSP)
      if (headerMap['content-security-policy']) {
          addToOutput('✅ [XSS] Content-Security-Policy detected');
      } else {
          addToOutput('⚠️ [XSS] Missing Content-Security-Policy', 'command-error');
      }

      // 5. Referrer Policy
      if (headerMap['referrer-policy']) {
          const rp = headerMap['referrer-policy'];
          if (rp.includes('unsafe-url')) {
              addToOutput(`❌ [Referrer] Unsafe policy detected: ${rp}`, 'command-error');
          } else {
              addToOutput(`✅ [Referrer] Policy set: ${rp}`);
          }
      } else {
          addToOutput('⚠️ [Referrer] Missing Referrer-Policy', 'command-error');
      }

      // 6. Permissions Policy
      if (headerMap['permissions-policy'] || headerMap['feature-policy']) {
          addToOutput('✅ [Permissions] Policy detected');
      } else {
          addToOutput('⚠️ [Permissions] Missing Permissions-Policy', 'command-error');
      }

      // 7. Cookie Security
      if (headerMap['set-cookie']) {
          const cookies = headerMap['set-cookie'].toLowerCase();
          const secure = cookies.includes('secure');
          const httpOnly = cookies.includes('httponly');
          const sameSite = cookies.includes('samesite');
          
          if (secure && httpOnly && sameSite) {
              addToOutput('✅ [Cookies] Secure attributes found (Secure, HttpOnly, SameSite)');
          } else {
              let missing = [];
              if (!secure) missing.push('Secure');
              if (!httpOnly) missing.push('HttpOnly');
              if (!sameSite) missing.push('SameSite');
              addToOutput(`⚠️ [Cookies] Missing attributes: ${missing.join(', ')}`, 'command-error');
          }
      }

      // 8. Information Leakage
      let leaks = [];
      if (headerMap['server']) leaks.push(`Server: ${headerMap['server']}`);
      if (headerMap['x-powered-by']) leaks.push(`X-Powered-By: ${headerMap['x-powered-by']}`);
      if (headerMap['x-aspnet-version']) leaks.push(`ASP.NET: ${headerMap['x-aspnet-version']}`);

      if (leaks.length > 0) {
          addToOutput('⚠️ [Info Leak] Technology details exposed:', 'command-error');
          leaks.forEach(leak => addToOutput(`   - ${leak}`, 'command-error'));
      } else {
          addToOutput('✅ [Info Leak] No obvious version headers found');
      }

      addToOutput('----------------------------------------');
      addToOutput('Data provided by hackertarget.com');
      
    } catch (error) {
      addToOutput(`Network error: ${error.message}`, 'command-error');
    }
    terminalWindow.scrollTop = terminalWindow.scrollHeight;
  }

  async function handleCVE(args) {
    if (args.length === 0) {
      addToOutput('Usage: cve <search_term>');
      addToOutput('Example: cve wordpress 5.0');
      return;
    }

    const query = args.join(' ').toLowerCase();
    addToOutput(`Searching NIST NVD for CVEs: "${query}"...`);

    // Search NIST NVD
    try {
      // NVD allows up to 2000 results per page
      const response = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=2000`);

      if (!response.ok) {
        addToOutput(`Error fetching data: ${response.status} ${response.statusText}`, 'command-error');
        return;
      }

      const data = await response.json();

      if (data.totalResults === 0) {
        addToOutput('No results found.');
        return;
      }

      const displayedCount = data.vulnerabilities.length;
      addToOutput(`Found ${data.totalResults} results (showing ${displayedCount}):`);
      addToOutput('----------------------------------------');

      if (displayedCount > 100) {
          addToOutput(`(Warning: Rendering ${displayedCount} items. This may freeze your browser briefly.)`);
      }

      data.vulnerabilities.forEach(item => {
        const cve = item.cve;
        addToOutput(`[${cve.id}] Status: ${cve.vulnStatus}`);
        if (cve.descriptions && cve.descriptions.length > 0) {
            // Truncate description if too long
            let desc = cve.descriptions[0].value;
            if (desc.length > 200) desc = desc.substring(0, 200) + '...';
            addToOutput(`Description: ${desc}`);
        }
        
        // Check for exploit references
        if (cve.references) {
            const exploits = cve.references.filter(ref => ref.tags && ref.tags.includes('Exploit'));
            if (exploits.length > 0) {
                addToOutput('Exploit Refs:');
                exploits.forEach(ref => addToOutput(`  - ${ref.url}`));
            }
        }
        addToOutput(''); // Spacer
      });

      addToOutput('----------------------------------------');
      addToOutput('Data provided by NIST NVD');

    } catch (error) {
      addToOutput(`Search failed: ${error.message}`, 'command-error');
    }
    terminalWindow.scrollTop = terminalWindow.scrollHeight;
  }

  async function handleMac(args) {
    if (args.length === 0) {
      addToOutput('Usage: mac <mac_address>');
      addToOutput('Example: mac FC:A1:3E:2A:1C:33');
      return;
    }

    const mac = args[0];
    addToOutput(`Looking up vendor for MAC: ${mac}...`);

    try {
      // Use corsproxy.io to bypass CORS restrictions on the MAC lookup API
      const response = await fetch(`https://corsproxy.io/?https://api.maclookup.app/v2/macs/${mac}`);

      if (!response.ok) {
        addToOutput(`Error fetching data: ${response.status}`, 'command-error');
        return;
      }

      const data = await response.json();

      if (!data.found) {
        addToOutput('Vendor not found.', 'command-error');
        return;
      }

      addToOutput('----------------------------------------');
      addToOutput(`Vendor:  ${data.company}`);
      if (data.address) addToOutput(`Address: ${data.address}`);
      if (data.country) addToOutput(`Country: ${data.country}`);
      addToOutput(`Prefix:  ${data.macPrefix}`);
      addToOutput('----------------------------------------');
      addToOutput('Data provided by maclookup.app (via corsproxy.io)');

    } catch (error) {
      addToOutput(`Lookup failed: ${error.message}`, 'command-error');
      addToOutput('(Note: This feature relies on a public proxy which may be blocked by some networks)', 'command-error');
    }
    terminalWindow.scrollTop = terminalWindow.scrollHeight;
  }

  const rssFeeds = {
    "netsec": { url: "https://www.reddit.com/r/netsec/.rss", desc: "/r/netsec" },
    "sysadmin": { url: "https://www.reddit.com/r/sysadmin/.rss", desc: "/r/sysadmin" },
    "cybersecurity": { url: "https://www.reddit.com/r/cybersecurity/.rss", desc: "/r/cybersecurity" },
    "security-se": { url: "https://security.stackexchange.com/feeds/week", desc: "IT Security Stack Exchange" },
    "cis": { url: "https://www.cisecurity.org/feed/advisories", desc: "CIS Advisories" },
    "securitymagazine": { url: "https://www.securitymagazine.com/rss/15", desc: "Security Magazine" },
    "darkreading": { url: "https://www.darkreading.com/rss.xml", desc: "Dark Reading" },
    "schneier": { url: "https://feeds.feedburner.com/schneier/fulltext", desc: "Schneier on Security" },
    "trailofbits": { url: "https://blog.trailofbits.com/feed/", desc: "Trail of Bits" },
    "malwaretech": { url: "https://www.malwaretech.com/feed/", desc: "MalwareTech" },
    "projectzero": { url: "https://googleprojectzero.blogspot.com/feeds/posts/default", desc: "Project Zero" },
    "krebs": { url: "https://krebsonsecurity.com/feed/", desc: "Krebs on Security" },
    "bleeping": { url: "https://www.bleepingcomputer.com/feed/", desc: "Bleeping Computer" },
    "threatpost": { url: "https://threatpost.com/feed/", desc: "Threatpost" },
    "wired": { url: "https://www.wired.com/feed/category/security/latest/rss", desc: "Wired Security" },
    "ars": { url: "https://arstechnica.com/security/feed/", desc: "Ars Technica Security" },
    "theregister": { url: "https://www.theregister.com/security/headlines.atom", desc: "The Register Security" },
    "errata": { url: "http://blog.erratasec.com/feeds/posts/default", desc: "Errata Security" },
    "imperialviolet": { url: "https://www.imperialviolet.org/iv-rss.xml", desc: "ImperialViolet" },
    "cisa": { url: "https://www.cisa.gov/cybersecurity-advisories/all.xml", desc: "CISA Advisories" },
    "thehackernews": { url: "https://feeds.feedburner.com/TheHackersNews", desc: "The Hacker News" },
    "sans": { url: "https://isc.sans.edu/rssfeed.xml", desc: "SANS ISC" },
    "unit42": { url: "https://unit42.paloaltonetworks.com/feed/", desc: "Unit 42" },
    "troyhunt": { url: "https://www.troyhunt.com/rss/", desc: "Troy Hunt" },
    "securityweek": { url: "https://www.securityweek.com/feed/", desc: "SecurityWeek" },
    "helpnetsec": { url: "https://www.helpnetsecurity.com/feed/", desc: "Help Net Security" },
    "msrc": { url: "https://api.msrc.microsoft.com/update-guide/rss", desc: "Microsoft Security" },
    "daemon": { url: "http://www.daemonology.net/blog/index.rss", desc: "Daemonic Dispatches" },
    "irongeek": { url: "http://feeds.feedburner.com/IrongeeksSecuritySite", desc: "Irongeek's Security Site" },
    "techanarchy": { url: "https://techanarchy.net/feed/", desc: "Tech Anarchy" },
    "nixcraft": { url: "http://feeds.cyberciti.biz/Nixcraft-LinuxFreebsdSolarisTipsTricks", desc: "nixCraft" },
    "doublepulsar": { url: "https://doublepulsar.com/feed", desc: "doublepulsar" }
  };

  async function handleNews(args) {
    if (args.length === 0 || args[0] === 'list') {
      addToOutput('Available News Feeds:');
      addToOutput('---------------------');
      Object.keys(rssFeeds).sort().forEach(key => {
        addToOutput(`${key.padEnd(15)} - ${rssFeeds[key].desc}`);
      });
      addToOutput('---------------------');
      addToOutput('Usage: news <feed_name>');
      return;
    }

    const feedKey = args[0].toLowerCase();
    const feed = rssFeeds[feedKey];

    if (!feed) {
      addToOutput(`Feed '${feedKey}' not found. Type 'news list' for available feeds.`, 'command-error');
      return;
    }

    addToOutput(`Fetching ${feed.desc}...`);

    try {
      // Use a CORS proxy to fetch the raw RSS/Atom XML
      // Using corsproxy.io to bypass CORS (api.allorigins.win was blocked by Reddit)
      const proxyUrl = `https://corsproxy.io/?${feed.url}`;
      const response = await fetch(proxyUrl);
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const str = await response.text();
      const parser = new DOMParser();
      const xmlDoc = parser.parseFromString(str, "text/xml");
      
      // Check for parser errors
      const parserError = xmlDoc.querySelector('parsererror');
      if (parserError) {
        throw new Error('Failed to parse feed XML');
      }

      let items = [];
      let feedTitle = feed.desc;

      // Try RSS <item>
      const rssItems = xmlDoc.querySelectorAll("item");
      if (rssItems.length > 0) {
        const channelTitle = xmlDoc.querySelector("channel > title");
        if (channelTitle) feedTitle = channelTitle.textContent;
        
        rssItems.forEach(item => {
          items.push({
            title: item.querySelector("title")?.textContent || "No Title",
            link: item.querySelector("link")?.textContent || "#",
            pubDate: item.querySelector("pubDate")?.textContent || ""
          });
        });
      } else {
        // Try Atom <entry>
        const atomEntries = xmlDoc.querySelectorAll("entry");
        if (atomEntries.length > 0) {
          const feedTitleElem = xmlDoc.querySelector("feed > title");
          if (feedTitleElem) feedTitle = feedTitleElem.textContent;

          atomEntries.forEach(entry => {
            // Find the correct link (rel="alternate" or no rel)
            const links = entry.querySelectorAll("link");
            let href = "#";
            for (let i = 0; i < links.length; i++) {
                const rel = links[i].getAttribute("rel");
                if (!rel || rel === "alternate") {
                    href = links[i].getAttribute("href");
                    break;
                }
            }
            
            items.push({
              title: entry.querySelector("title")?.textContent || "No Title",
              link: href,
              pubDate: entry.querySelector("updated")?.textContent || entry.querySelector("published")?.textContent || ""
            });
          });
        }
      }

      if (items.length === 0) {
        addToOutput('No items found in feed.', 'command-error');
        return;
      }

      addToOutput(`Latest from ${feedTitle}:`);
      addToOutput('----------------------------------------');
      
      items.slice(0, 5).forEach(item => {
        // Format date
        let dateStr = item.pubDate;
        try {
            const date = new Date(item.pubDate);
            if (!isNaN(date.getTime())) {
                dateStr = date.toISOString().split('T')[0];
            }
        } catch (e) {
            // keep original string if parsing fails
        }

        // Create a clickable link
        const link = `<a href="${item.link}" target="_blank" style="color: inherit; text-decoration: underline;">${item.title}</a>`;
        addToOutput(`* ${link}`, '', true);
        addToOutput(`  ${dateStr}`);
        addToOutput('');
      });

    } catch (error) {
      addToOutput(`Error fetching news: ${error.message}`, 'command-error');
      addToOutput(`Try visiting: ${feed.url}`, 'command-error');
    }
  }

  function processEntities(entities, indent = '') {
    entities.forEach(entity => {
      const roles = entity.roles ? entity.roles.join(', ') : 'Entity';
      const handle = entity.handle || '';
      
      // Extract vCard Data
      let name = '', org = '', email = '', phone = '';
      if (entity.vcardArray && entity.vcardArray[1]) {
        const vcard = entity.vcardArray[1];
        vcard.forEach(item => {
          if (item[0] === 'fn') name = item[3];
          if (item[0] === 'org') org = item[3];
          if (item[0] === 'email') email = item[3];
          if (item[0] === 'tel') phone = item[3];
        });
      }
      
      // Only print if we have meaningful data
      if (name || org || email || roles) {
        addToOutput(`${indent}${roles.toUpperCase()}: ${name || org || handle}`);
        if (org && org !== name) addToOutput(`${indent}  Org: ${org}`);
        if (email) addToOutput(`${indent}  Email: ${email}`);
        if (phone) addToOutput(`${indent}  Phone: ${phone}`);
      }
      
      // Recursive for nested entities (like abuse contacts inside registrar)
      if (entity.entities) {
        processEntities(entity.entities, indent + '  ');
      }
    });
  }
});
