const fs = require('fs');

let content = fs.readFileSync('assets/js/terminal.js', 'utf8');

const searchMac = `
    try {
      // Use corsproxy.io to bypass CORS restrictions on the MAC lookup API
      const response = await fetch(\`https://corsproxy.io/?https://api.maclookup.app/v2/macs/\${mac}\`);

      if (!response.ok) {
        addToOutput(\`Error fetching data: \${response.status}\`, 'command-error');
        return;
      }

      const data = await response.json();

      if (!data.found) {
        addToOutput('Vendor not found.', 'command-error');
        return;
      }

      addToOutput('----------------------------------------');
      addToOutput(\`Vendor:  \${data.company}\`);
      if (data.address) addToOutput(\`Address: \${data.address}\`);
      if (data.country) addToOutput(\`Country: \${data.country}\`);
      addToOutput(\`Prefix:  \${data.macPrefix}\`);
      addToOutput('----------------------------------------');
      addToOutput('Data provided by maclookup.app (via corsproxy.io)');

    } catch (error) {
      addToOutput(\`Lookup failed: \${error.message}\`, 'command-error');
      addToOutput('(Note: This feature relies on a public proxy which may be blocked by some networks)', 'command-error');
    }
`;

const replaceMac = `
    try {
      const apiUrl = \`https://api.maclookup.app/v2/macs/\${mac}\`;
      const proxies = [
        (url) => \`https://api.allorigins.win/get?url=\${encodeURIComponent(url)}\`,
        (url) => \`https://corsproxy.io/?\${encodeURIComponent(url)}\`
      ];

      let data = null;
      let fetchError = null;

      for (const getProxyUrl of proxies) {
        try {
          const proxyUrl = getProxyUrl(apiUrl);
          const response = await fetch(proxyUrl);

          if (!response.ok) {
            throw new Error(\`HTTP status: \${response.status}\`);
          }

          const proxyData = await response.json();
          // allorigins returns { contents: "..." }, corsproxy returns direct json
          data = proxyData.contents ? JSON.parse(proxyData.contents) : proxyData;
          if (data && typeof data === 'object') {
             break;
          }
        } catch (e) {
          fetchError = e;
        }
      }

      if (!data) {
        addToOutput(\`Error fetching data: \${fetchError?.message || 'Unknown error'}\`, 'command-error');
        return;
      }

      if (!data.found) {
        addToOutput('Vendor not found.', 'command-error');
        return;
      }

      addToOutput('----------------------------------------');
      addToOutput(\`Vendor:  \${data.company}\`);
      if (data.address) addToOutput(\`Address: \${data.address}\`);
      if (data.country) addToOutput(\`Country: \${data.country}\`);
      addToOutput(\`Prefix:  \${data.macPrefix}\`);
      addToOutput('----------------------------------------');
      addToOutput('Data provided by maclookup.app (via proxies)');

    } catch (error) {
      addToOutput(\`Lookup failed: \${error.message}\`, 'command-error');
      addToOutput('(Note: This feature relies on a public proxy which may be blocked by some networks)', 'command-error');
    }
`;

content = content.replace(searchMac.trim(), replaceMac.trim());

const searchHelp = `addToOutput('Available commands: help, clear, date, whois, dig, osint, subdomains, headers, mac, cve, news');`;
const replaceHelp = `addToOutput('Available commands: help, clear, date, whois, dig, osint, subdomains, headers, mac, cve, news, subnet');`;
content = content.replace(searchHelp, replaceHelp);

const searchNews = `      case 'news':
        handleNews(args);
        break;`;
const replaceNews = `      case 'news':
        handleNews(args);
        break;
      case 'subnet':
        handleSubnet(args);
        break;`;
content = content.replace(searchNews, replaceNews);

const searchProcessEntities = `function processEntities(entities, indent = '') {`;
const replaceProcessEntities = `function handleSubnet(args) {
    if (args.length === 0) {
      addToOutput('Usage: subnet <ip_address>/<cidr>');
      addToOutput('Example: subnet 192.168.1.0/24');
      return;
    }

    const input = args[0];
    const parts = input.split('/');

    if (parts.length !== 2) {
      addToOutput('Invalid format. Please use <ip>/<cidr> (e.g., 10.0.0.1/24)', 'command-error');
      return;
    }

    const ip = parts[0];
    const cidr = parseInt(parts[1], 10);

    const ipRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

    if (!ipRegex.test(ip)) {
        addToOutput('Invalid IP address format.', 'command-error');
        return;
    }

    if (isNaN(cidr) || cidr < 0 || cidr > 32) {
        addToOutput('Invalid CIDR notation. Must be between 0 and 32.', 'command-error');
        return;
    }

    try {
        const ipParts = ip.split('.').map(Number);

        // Convert to signed 32-bit int
        const ipInt = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];

        // Mask for CIDR
        const maskInt = cidr === 0 ? 0 : ~((1 << (32 - cidr)) - 1);

        const networkInt = ipInt & maskInt;
        const broadcastInt = networkInt | ~maskInt;

        const intToIp = (int) => {
            return [
                (int >>> 24) & 255,
                (int >>> 16) & 255,
                (int >>> 8) & 255,
                int & 255
            ].join('.');
        };

        const network = intToIp(networkInt);
        const broadcast = intToIp(broadcastInt);
        const mask = intToIp(maskInt);

        let hostMin = "N/A";
        let hostMax = "N/A";
        let totalHosts = 0;

        if (cidr < 31) {
            hostMin = intToIp(networkInt + 1);
            hostMax = intToIp(broadcastInt - 1);
            totalHosts = Math.pow(2, 32 - cidr) - 2;
        } else if (cidr === 31) {
            hostMin = network;
            hostMax = broadcast;
            totalHosts = 2;
        } else if (cidr === 32) {
            hostMin = network;
            hostMax = network;
            totalHosts = 1;
        }

        addToOutput('----------------------------------------');
        addToOutput(\`IP Address:   \${ip}\`);
        addToOutput(\`Subnet Mask:  \${mask} (/\${cidr})\`);
        addToOutput(\`Network:      \${network}\`);
        addToOutput(\`Broadcast:    \${broadcast}\`);
        addToOutput(\`Host Min:     \${hostMin}\`);
        addToOutput(\`Host Max:     \${hostMax}\`);
        addToOutput(\`Total Hosts:  \${totalHosts.toLocaleString()}\`);
        addToOutput('----------------------------------------');
    } catch (e) {
        addToOutput(\`Error calculating subnet: \${e.message}\`, 'command-error');
    }
    terminalWindow.scrollTop = terminalWindow.scrollHeight;
  }

  function processEntities(entities, indent = '') {`;
content = content.replace(searchProcessEntities, replaceProcessEntities);

fs.writeFileSync('assets/js/terminal.js', content);
