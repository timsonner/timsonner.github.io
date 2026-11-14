/**
 * Client-side DNS report helper (DoH + ipapi.co ASN). No DOM access.
 * Exposes window.DnsLookup / globalThis.DnsLookup and works under Node for tests.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.DnsLookup = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const DNS_TYPES = {
    A: 1,
    NS: 2,
    CNAME: 5,
    SOA: 6,
    PTR: 12,
    MX: 15,
    TXT: 16,
    AAAA: 28,
    CAA: 257,
  };

  const WAVE1_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT', 'CAA'];
  const DKIM_SELECTORS = [
    'selector1', 'selector2', 'google', 'default', 'k1', 'k2', 's1', 's2',
    'mail', 'dkim', 'smtp', 'mandrill', 'mxvault', 'zoho', 'protonmail', 'zendesk1',
  ];

  const IPV4_RE =
    /^(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
  const IPV6_RE =
    /^[0-9a-fA-F:]+$/;

  const DEFAULT_FETCH = typeof fetch !== 'undefined' ? fetch.bind(globalThis) : null;

  function createDoHPool(maxInFlight) {
    let active = 0;
    const queue = [];

    function runNext() {
      while (active < maxInFlight && queue.length > 0) {
        const job = queue.shift();
        active += 1;
        job()
          .catch(() => {})
          .finally(() => {
            active -= 1;
            runNext();
          });
      }
    }

    return function schedule(fn) {
      return new Promise((resolve, reject) => {
        queue.push(() => fn().then(resolve, reject));
        runNext();
      });
    };
  }

  function normalizeHostname(host) {
    if (host == null) return '';
    return String(host).replace(/\.$/, '').toLowerCase();
  }

  function normalizeTarget(raw) {
    if (raw == null) return { ok: false, reason: 'usage' };
    let s = String(raw).trim();
    if (!s) return { ok: false, reason: 'usage' };

    try {
      if (/^https?:\/\//i.test(s)) {
        const u = new URL(s);
        s = u.hostname;
      }
    } catch (_e) {
      return { ok: false, reason: 'invalid' };
    }

    if (s.endsWith('.')) s = s.slice(0, -1);
    if (!s) return { ok: false, reason: 'invalid' };

    if (IPV4_RE.test(s)) return { ok: true, kind: 'ipv4', value: s };
    if (s.includes(':') && IPV6_RE.test(s)) return { ok: true, kind: 'ipv6', value: s.toLowerCase() };

    if (!/^[a-zA-Z0-9]([a-zA-Z0-9-._]{0,253}[a-zA-Z0-9])?$/.test(s)) {
      return { ok: false, reason: 'invalid' };
    }
  return { ok: true, kind: 'domain', value: s.toLowerCase() };
  }

  function buildIpv4Ptr(ip) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some((p) => p < 0 || p > 255)) return null;
    return `${parts[3]}.${parts[2]}.${parts[1]}.${parts[0]}.in-addr.arpa`;
  }

  function expandIpv6(ip) {
    const halves = ip.split('::');
    if (halves.length > 2) return null;
    let left = halves[0] ? halves[0].split(':').filter(Boolean) : [];
    let right = halves.length === 2 && halves[1] ? halves[1].split(':').filter(Boolean) : [];
    const missing = 8 - left.length - right.length;
    if (missing < 0) return null;
    const groups = [...left, ...Array(missing).fill('0'), ...right];
    if (groups.length !== 8) return null;
    const hextets = [];
    for (const g of groups) {
      const n = parseInt(g, 16);
      if (Number.isNaN(n) || n < 0 || n > 0xffff) return null;
      hextets.push(n);
    }
    return hextets;
  }

  function buildIpv6Ptr(ip) {
    const hextets = expandIpv6(ip);
    if (!hextets) return null;
    const nibbles = [];
    for (let i = hextets.length - 1; i >= 0; i -= 1) {
      const h = hextets[i];
      nibbles.push(((h >>> 0) & 0xf).toString(16));
      nibbles.push(((h >>> 4) & 0xf).toString(16));
      nibbles.push(((h >>> 8) & 0xf).toString(16));
      nibbles.push(((h >>> 12) & 0xf).toString(16));
    }
    return `${nibbles.join('.')}.ip6.arpa`;
  }

  function registrableDomainFromHost(host) {
    const h = host.replace(/\.$/, '').toLowerCase();
    const labels = h.split('.').filter(Boolean);
    if (labels.length < 2) return null;
    if (labels.length === 2) return h;
    return `${labels[labels.length - 2]}.${labels[labels.length - 1]}`;
  }

  function parseSpfRecord(txt) {
    const raw = txt.replace(/^"|"$/g, '').replace(/\\"/g, '"');
    if (!/^v=spf1\b/i.test(raw)) return null;

    const tokens = raw.split(/\s+/).filter(Boolean);
    const mechanisms = ['include', 'a', 'mx', 'ptr', 'exists', 'redirect'];
    let mechanismCount = 0;
    let allQualifier = null;
    let allWord = null;
    const notes = [];
    const visited = new Set();
    const chain = [raw];

    function countLine(line) {
      const parts = line.split(/\s+/).filter(Boolean);
      for (const part of parts) {
        if (part === 'v=spf1') continue;
        const m = part.match(/^(~|-|\+|\?)?([a-zA-Z]+)/);
        if (!m) continue;
        const qual = m[1] || '+';
        const mech = m[2].toLowerCase();
        if (mech === 'all') {
          allQualifier = qual;
          allWord = describeAll(qual);
          continue;
        }
        if (mechanisms.includes(mech)) {
          mechanismCount += 1;
          if (mech === 'ptr') {
            notes.push('ptr present (not followed in this walk)');
          }
        }
      }
    }

    countLine(raw);

    function describeAll(qual) {
      if (qual === '-') return 'fail (-all)';
      if (qual === '~') return 'softfail (~all)';
      if (qual === '?') return 'neutral (?all)';
      return 'pass (+all or all)';
    }

    const warnings = [];
    if (mechanismCount > 10) {
      warnings.push('SPF lists more than 10 DNS mechanisms (RFC 7208 limit)');
    }

    return {
      raw,
      mechanismCount,
      maxWalk: 10,
      allQualifier,
      allWord,
      notes,
      warnings,
      displayCount: `${mechanismCount} / 10`,
      visited,
      chain,
    };
  }

  async function walkSpfIncludes(rootTxt, resolveTxt, limit) {
    const result = parseSpfRecord(rootTxt);
    if (!result) return null;

    const queue = [];
    const rootParts = rootTxt.replace(/^"|"$/g, '').split(/\s+/).filter(Boolean);
    for (const part of rootParts) {
      const inc = part.match(/^include:([^\s]+)/i);
      const redir = part.match(/^redirect=([^\s]+)/i);
      if (inc) queue.push(inc[1].toLowerCase());
      if (redir) queue.push(redir[1].toLowerCase());
    }

    let walked = 0;
    while (queue.length > 0 && walked < limit) {
      const domain = queue.shift();
      if (result.visited.has(domain)) continue;
      result.visited.add(domain);
      walked += 1;
      let txts;
      try {
        txts = await resolveTxt(domain);
      } catch (_e) {
        result.chain.push(`; include ${domain}: lookup failed`);
        continue;
      }
      const spf = txts.find((t) => /^v=spf1\b/i.test(t.replace(/^"|"$/g, '')));
      if (!spf) {
        result.chain.push(`; include ${domain}: no SPF TXT`);
        continue;
      }
      result.chain.push(spf);
      const inner = parseSpfRecord(spf);
      if (inner) {
        result.mechanismCount += inner.mechanismCount;
        if (inner.allWord && !result.allWord) {
          result.allWord = inner.allWord;
          result.allQualifier = inner.allQualifier;
        }
        for (const n of inner.notes) {
          if (!result.notes.includes(n)) result.notes.push(n);
        }
      }
      const parts = spf.replace(/^"|"$/g, '').split(/\s+/).filter(Boolean);
      for (const part of parts) {
        const inc = part.match(/^include:([^\s]+)/i);
        const redir = part.match(/^redirect=([^\s]+)/i);
        if (inc) queue.push(inc[1].toLowerCase());
        if (redir) queue.push(redir[1].toLowerCase());
      }
    }

    if (result.mechanismCount > 10 && !result.warnings.length) {
      result.warnings.push('SPF lists more than 10 DNS mechanisms (RFC 7208 limit)');
    }
    result.displayCount = `${result.mechanismCount} / 10`;
    return result;
  }

  function parseDmarcFromTxts(txts) {
    const joined = txts
      .map((t) => t.replace(/^"|"$/g, '').replace(/\\;/g, ';'))
      .find((t) => /^v=DMARC1\b/i.test(t));
    if (!joined) return null;
    const tags = {};
    joined.split(';').forEach((piece) => {
      const [k, v] = piece.trim().split('=');
      if (!k || v === undefined) return;
      tags[k.trim().toLowerCase()] = v.trim();
    });
    return {
      p: tags.p || '',
      pct: tags.pct || '',
      sp: tags.sp || '',
      rua: tags.rua || '',
      ruf: tags.ruf || '',
      raw: joined,
    };
  }

  function truncateDkim(txt, maxLen) {
    const lim = maxLen || 120;
    const s = txt.replace(/^"|"$/g, '');
    if (s.length <= lim) return s;
    return `${s.slice(0, lim)}...`;
  }

  function typeLabel(num) {
    const map = {
      1: 'A',
      2: 'NS',
      5: 'CNAME',
      6: 'SOA',
      12: 'PTR',
      15: 'MX',
      16: 'TXT',
      28: 'AAAA',
      257: 'CAA',
    };
    return map[num] || String(num);
  }

  function createResolver(options) {
    const fetchFn = options.fetch || DEFAULT_FETCH;
    if (!fetchFn) {
      throw new Error('fetch is not available');
    }
    const dohTimeoutMs = options.dohTimeoutMs || 5000;
    const asnTimeoutMs = options.asnTimeoutMs || 6000;
    const scheduleDoh = createDoHPool(6);
    const dnsCache = new Map();
    const asnCache = new Map();
    let asnBudgetRemaining = 15;
    let asnStopped = false;
    let asnInFlight = 0;
    const asnWaiters = [];

    function resetAsnRunState() {
      asnBudgetRemaining = 15;
      asnStopped = false;
    }

    function fetchWithTimeout(url, init, ms) {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), ms);
      return fetchFn(url, { ...init, signal: ctrl.signal }).finally(() => clearTimeout(timer));
    }

    async function queryOneProvider(name, typeNum, provider) {
      if (provider === 'cloudflare') {
        const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${typeNum}`;
        const resp = await fetchWithTimeout(
          url,
          { headers: { Accept: 'application/dns-json' } },
          dohTimeoutMs,
        );
        if (!resp.ok) throw new Error(`cloudflare ${resp.status}`);
        const data = await resp.json();
        return normalizeAnswers(data);
      }
      const typeName = typeLabel(typeNum);
      const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${typeName}`;
      const resp = await fetchWithTimeout(url, {}, dohTimeoutMs);
      if (!resp.ok) throw new Error(`google ${resp.status}`);
      const data = await resp.json();
      return normalizeAnswers(data);
    }

    function normalizeAnswers(data) {
      if (!data) return [];
      const status = data.Status !== undefined ? data.Status : 0;
      if (status !== 0 && !data.Answer) return [];
      const answers = data.Answer || [];
      return answers.map((r) => ({
        name: (r.name || '').replace(/\.$/, ''),
        type: r.type,
        ttl: r.TTL,
        data: typeof r.data === 'string' ? r.data : String(r.data),
      }));
    }

    async function dohQueryUncached(name, typeKey) {
      const typeNum = DNS_TYPES[typeKey] ?? parseInt(typeKey, 10);
      const errors = [];
      try {
        return await queryOneProvider(name, typeNum, 'cloudflare');
      } catch (e1) {
        errors.push(e1);
      }
      try {
        return await queryOneProvider(name, typeNum, 'google');
      } catch (e2) {
        errors.push(e2);
        throw new Error(errors.map((x) => x.message || x).join('; '));
      }
    }

    async function dohQuery(name, typeKey) {
      const normName = normalizeHostname(name);
      const key = `${normName}|${typeKey}`;
      if (dnsCache.has(key)) return dnsCache.get(key);
      const pending = scheduleDoh(() => dohQueryUncached(normName, typeKey));
      dnsCache.set(key, pending);
      pending.catch(() => {
        dnsCache.delete(key);
      });
      return pending;
    }

    async function dohQueryCatch(name, typeKey) {
      try {
        const answers = await dohQuery(name, typeKey);
        return { answers, error: null };
      } catch (e) {
        return { answers: [], error: e.message || String(e) };
      }
    }

    async function resolveTxt(name) {
      const rows = await dohQuery(name, 'TXT');
      return rows.map((r) => r.data);
    }

    async function lookupAsn(ip) {
      if (asnCache.has(ip)) {
        const cached = asnCache.get(ip);
        if (cached && cached.asn) return cached;
      }
      if (asnStopped) {
        return { ip, asn: null, org: null, skipped: true };
      }
      if (asnBudgetRemaining <= 0) {
        return { ip, asn: null, org: null, skipped: true };
      }

      const runLookup = async () => {
        asnBudgetRemaining -= 1;
        try {
          const resp = await fetchWithTimeout(`https://ipapi.co/${ip}/json/`, {}, asnTimeoutMs);
          if (resp.status === 429) {
            asnStopped = true;
            return { ip, asn: null, org: null, error: 'rate limited' };
          }
          if (!resp.ok) {
            return { ip, asn: null, org: null, error: `http ${resp.status}` };
          }
          const body = await resp.json();
          if (body.error) {
            if (body.reason && /rate/i.test(body.reason)) asnStopped = true;
            return { ip, asn: null, org: null, error: body.reason || body.message || 'error' };
          }
          return { ip, asn: body.asn || null, org: body.org || null };
        } catch (e) {
          return { ip, asn: null, org: null, error: e.message || 'error' };
        }
      };

      while (asnInFlight >= 2) {
        await new Promise((r) => asnWaiters.push(r));
      }
      asnInFlight += 1;
      let result;
      try {
        result = await runLookup();
      } finally {
        asnInFlight -= 1;
        const w = asnWaiters.shift();
        if (w) w();
      }
      if (result.asn) {
        asnCache.set(ip, result);
      }
      return result;
    }

    function collectIpsForBudget(wave1) {
      const ips = [];
      const seen = new Set();

      function pushIp(ip) {
        const n = ip && String(ip).toLowerCase();
        if (!n || seen.has(n)) return;
        seen.add(n);
        ips.push(n);
      }

      (wave1.A || []).forEach((r) => pushIp(r.data));
      (wave1.AAAA || []).forEach((r) => pushIp(r.data));

      (wave1.MX || []).forEach((mx) => {
        const host = normalizeHostname(mx.data.includes(' ') ? mx.data.split(/\s+/).pop() : mx.data);
        const targets = wave1._mxIps && wave1._mxIps[host];
        if (targets) {
          targets.a.forEach((x) => pushIp(x));
          targets.aaaa.forEach((x) => pushIp(x));
        }
      });

      (wave1.NS || []).forEach((ns) => {
        const host = normalizeHostname(ns.data);
        const targets = wave1._nsIps && wave1._nsIps[host];
        if (targets) {
          targets.a.forEach((x) => pushIp(x));
          targets.aaaa.forEach((x) => pushIp(x));
        }
      });

      return ips.slice(0, 15);
    }

    function formatAsnOrg(asnRow) {
      if (!asnRow || !asnRow.asn) return '';
      return `AS${String(asnRow.asn).replace(/^AS/i, '')} ${asnRow.org || ''}`.trim();
    }

    function formatIpDetail(ip, asnByIp, ptrByIp) {
      const asnPart = formatAsnOrg(asnByIp[ip]);
      const ptr = ptrByIp[ip];
      const extra = [asnPart, ptr ? `PTR ${ptr}` : ''].filter(Boolean).join(' | ');
      return extra ? `  ${ip}  ${extra}` : `  ${ip}`;
    }

    async function buildIpEnrichment(wave1) {
      const budgetIps = collectIpsForBudget(wave1);
      const asnByIp = {};
      const ptrByIp = {};

      await Promise.all(
        budgetIps.map(async (ip) => {
          asnByIp[ip] = await lookupAsn(ip);
          const ptrName = IPV4_RE.test(ip) ? buildIpv4Ptr(ip) : buildIpv6Ptr(ip);
          if (!ptrName) return;
          const { answers, error } = await dohQueryCatch(ptrName, 'PTR');
          if (!error && answers.length) {
            ptrByIp[ip] = answers.map((p) => p.data.replace(/\.$/, '')).join(', ');
          }
        }),
      );

      return { asnByIp, ptrByIp, budgetIps };
    }

    function sectionEmpty(wave1, types, errors) {
      const rows = types.flatMap((t) => wave1[t] || []);
      if (rows.length) return null;
      const err = types.map((t) => errors[t]).filter(Boolean);
      if (err.length) return `Lookup failed: ${err[0]}`;
      return 'No records';
    }

    async function runDomainLookup(domain, extraArgs) {
      const lines = [];
      if (extraArgs && extraArgs.length > 0) {
        lines.push('dns pulls all records; extra arguments ignored');
      }
      lines.push(`; DNS report for ${domain}`);
      lines.push('');

      const wave1 = { _errors: {} };
      await Promise.all(
        WAVE1_TYPES.map(async (t) => {
          const { answers, error } = await dohQueryCatch(domain, t);
          wave1[t] = answers;
          if (error) wave1._errors[t] = error;
        }),
      );

      const dmarcResult = await dohQueryCatch(`_dmarc.${domain}`, 'TXT');
      wave1._dmarcTxt = dmarcResult.answers;
      if (dmarcResult.error) wave1._errors._dmarc = dmarcResult.error;

      const mxHosts = new Set();
      (wave1.MX || []).forEach((r) => {
        const host = normalizeHostname(r.data.includes(' ') ? r.data.split(/\s+/).pop() : r.data);
        if (host) mxHosts.add(host);
      });
      const nsHosts = new Set();
      (wave1.NS || []).forEach((r) => {
        const host = normalizeHostname(r.data);
        if (host) nsHosts.add(host);
      });

      wave1._mxIps = {};
      await Promise.all(
        [...mxHosts].map(async (h) => {
          const [aRes, aaaaRes] = await Promise.all([dohQueryCatch(h, 'A'), dohQueryCatch(h, 'AAAA')]);
          wave1._mxIps[h] = {
            a: aRes.answers.map((x) => x.data),
            aaaa: aaaaRes.answers.map((x) => x.data),
            error: aRes.error || aaaaRes.error,
          };
        }),
      );

      wave1._nsIps = {};
      await Promise.all(
        [...nsHosts].map(async (h) => {
          const [aRes, aaaaRes] = await Promise.all([dohQueryCatch(h, 'A'), dohQueryCatch(h, 'AAAA')]);
          wave1._nsIps[h] = {
            a: aRes.answers.map((x) => x.data),
            aaaa: aaaaRes.answers.map((x) => x.data),
            error: aRes.error || aaaaRes.error,
          };
        }),
      );

      const dkimFound = [];
      const dkimMiss = [];
      await Promise.all(
        DKIM_SELECTORS.map(async (sel) => {
          const name = `${sel}._domainkey.${domain}`;
          const [txtRes, cnameRes] = await Promise.all([dohQueryCatch(name, 'TXT'), dohQueryCatch(name, 'CNAME')]);
          if (txtRes.answers.length > 0) {
            dkimFound.push({
              selector: sel,
              type: 'TXT',
              value: truncateDkim(txtRes.answers.map((x) => x.data).join(' ')),
            });
          } else if (cnameRes.answers.length > 0) {
            dkimFound.push({
              selector: sel,
              type: 'CNAME',
              value: cnameRes.answers.map((x) => x.data).join(', '),
            });
          } else {
            dkimMiss.push(sel);
          }
        }),
      );

      const { asnByIp, ptrByIp } = await buildIpEnrichment(wave1);

      lines.push('[A / AAAA]');
      const addrRows = [...(wave1.A || []), ...(wave1.AAAA || [])];
      const cnameRows = wave1.CNAME || [];
      const emptyA = sectionEmpty(wave1, ['A', 'AAAA', 'CNAME'], wave1._errors);
      if (!addrRows.length && !cnameRows.length) {
        lines.push(emptyA);
      } else {
        addrRows.forEach((r) => {
          lines.push(`${r.name} ${r.ttl} IN ${typeLabel(r.type)} ${r.data}`);
          const ip = String(r.data).toLowerCase();
          if ((r.type === 1 || r.type === 28) && (asnByIp[ip] || ptrByIp[ip])) {
            lines.push(formatIpDetail(ip, asnByIp, ptrByIp));
          }
        });
        cnameRows.forEach((r) => {
          lines.push(`${r.name} ${r.ttl} IN CNAME ${r.data}`);
        });
      }
      lines.push('');

      lines.push('[MX]');
      if (!(wave1.MX || []).length) {
        lines.push(sectionEmpty(wave1, ['MX'], wave1._errors));
      } else {
        wave1.MX.forEach((r) => {
          lines.push(`${r.name} ${r.ttl} IN MX ${r.data}`);
          const host = normalizeHostname(r.data.includes(' ') ? r.data.split(/\s+/).pop() : r.data);
          const targets = wave1._mxIps[host] || { a: [], aaaa: [] };
          const ips = [...targets.a, ...targets.aaaa];
          if (!ips.length) {
            if (targets.error) lines.push(`  Lookup failed: ${targets.error}`);
            else lines.push(`  (no A/AAAA for ${host})`);
          } else {
            ips.forEach((ip) => lines.push(formatIpDetail(ip, asnByIp, ptrByIp)));
          }
        });
      }
      lines.push('');

      lines.push('[NS]');
      if (!(wave1.NS || []).length) {
        lines.push(sectionEmpty(wave1, ['NS'], wave1._errors));
      } else {
        for (const r of wave1.NS) {
          const host = normalizeHostname(r.data);
          const targets = wave1._nsIps[host] || { a: [], aaaa: [] };
          const ips = [...targets.a, ...targets.aaaa];
          lines.push(`${r.name} ${r.ttl} IN NS ${r.data}`);
          if (!ips.length) {
            if (targets.error) lines.push(`  Lookup failed: ${targets.error}`);
            else lines.push(`  (no A/AAAA for ${host})`);
          } else {
            ips.forEach((ip) => lines.push(formatIpDetail(ip, asnByIp, ptrByIp)));
          }
        }
      }
      lines.push('');

      lines.push('[SOA]');
      if (!(wave1.SOA || []).length) lines.push('No records');
      else {
        wave1.SOA.forEach((r) => lines.push(`${r.name} ${r.ttl} IN SOA ${r.data}`));
      }
      lines.push('');

      lines.push('[TXT]');
      if (!(wave1.TXT || []).length) lines.push('No records');
      else {
        wave1.TXT.forEach((r) => lines.push(`${r.name} ${r.ttl} IN TXT ${r.data}`));
      }
      lines.push('');

      lines.push('[CAA]');
      if (!(wave1.CAA || []).length) lines.push('No records');
      else {
        wave1.CAA.forEach((r) => lines.push(`${r.name} ${r.ttl} IN CAA ${r.data}`));
      }
      lines.push('');

      lines.push('[SPF]');
      const spfTxt = (wave1.TXT || []).map((r) => r.data).find((t) => /^"?v=spf1\b/i.test(t));
      if (!spfTxt) {
        lines.push('No records');
      } else {
        const spf = await walkSpfIncludes(spfTxt, resolveTxt, 10);
        if (spf) {
          lines.push(spf.raw);
          lines.push(`Mechanisms counted: ${spf.displayCount}`);
          if (spf.allWord) lines.push(`Default: ${spf.allWord}`);
          spf.notes.forEach((n) => lines.push(`Note: ${n}`));
          spf.warnings.forEach((w) => lines.push(`Warning: ${w}`));
          if (spf.chain.length > 1) {
            lines.push('Included/redirect chain:');
            spf.chain.slice(1).forEach((c) => lines.push(`  ${c}`));
          }
        } else {
          lines.push(spfTxt);
        }
      }
      lines.push('');

      lines.push('[DMARC]');
      const dmarcTxts = (wave1._dmarcTxt || []).map((r) => r.data);
      const dmarc = parseDmarcFromTxts(dmarcTxts);
      if (!dmarc) lines.push('No records');
      else {
        lines.push(dmarc.raw);
        lines.push(`p=${dmarc.p || '(unset)'} pct=${dmarc.pct || '(unset)'} sp=${dmarc.sp || '(unset)'}`);
        if (dmarc.rua) lines.push(`rua=${dmarc.rua}`);
        if (dmarc.ruf) lines.push(`ruf=${dmarc.ruf}`);
      }
      lines.push('');

      lines.push('[DKIM]');
      if (dkimFound.length === 0) {
        lines.push('No selectors matched common probes.');
        lines.push('This is not proof the domain has no DKIM.');
      } else {
        dkimFound.forEach((d) => lines.push(`${d.selector}: ${d.type} ${d.value}`));
      }
      if (dkimMiss.length) {
        lines.push(`Not found: ${dkimMiss.join(', ')}`);
      }
      lines.push('');

      lines.push('Sources: Cloudflare/Google DoH, ipapi.co');
      lines.push(`Subdomains: run \`subdomains ${domain}\``);

      return { kind: 'domain', lines, dnsCacheKeys: [...dnsCache.keys()] };
    }

    async function ipForwardMatches(ptrHost, originalIp) {
      const a = await dohQuery(ptrHost.replace(/\.$/, ''), 'A');
      const aaaa = await dohQuery(ptrHost.replace(/\.$/, ''), 'AAAA');
      const targets = [...a.map((x) => x.data), ...aaaa.map((x) => x.data)];
      const norm = originalIp.toLowerCase();
      const match = targets.some((t) => t.toLowerCase() === norm);
      return { match, targets };
    }

    async function runIpLookup(ip, kind, extraArgs) {
      const lines = [];
      if (extraArgs && extraArgs.length > 0) {
        lines.push('dns pulls all records; extra arguments ignored');
      }
      lines.push(`; Reverse DNS report for ${ip}`);
      lines.push('');

      const ptrName = kind === 'ipv4' ? buildIpv4Ptr(ip) : buildIpv6Ptr(ip);
      if (!ptrName) {
        lines.push('Invalid IP for PTR construction.');
        return { kind: 'ip', lines };
      }

      const ptrResult = await dohQueryCatch(ptrName, 'PTR');
      lines.push('[PTR]');
      if (ptrResult.error) {
        lines.push(`Lookup failed: ${ptrResult.error}`);
      } else if (!ptrResult.answers.length) {
        lines.push('No records');
      } else {
        ptrResult.answers.forEach((r) => lines.push(`${r.name} ${r.ttl} IN PTR ${r.data}`));
      }
      lines.push('');

      const asn = await lookupAsn(ip);
      lines.push('[ASN]');
      if (asn.asn) {
        lines.push(`AS${String(asn.asn).replace(/^AS/i, '')} ${asn.org || ''}`.trim());
      } else if (asn.error) {
        lines.push(`Lookup unavailable (${asn.error})`);
      } else {
        lines.push('No records');
      }
      lines.push('');

      const ptrs = ptrResult.answers;

      lines.push('[Forward confirm]');
      if (!ptrs.length) {
        lines.push('No PTR names to confirm.');
      } else {
        for (const r of ptrs) {
          const host = r.data.replace(/\.$/, '');
          const { match, targets } = await ipForwardMatches(host, ip);
          const listed = targets.length ? targets.join(', ') : '(no A/AAAA)';
          lines.push(`${host} -> ${listed} ${match ? '(matches)' : '(does not match)'}`);
          const reg = registrableDomainFromHost(host);
          if (reg && host.split('.').length > 2) {
            lines.push(`Tip: run dns ${reg} for mail/DNS context on ${reg}`);
          }
        }
      }
      lines.push('');

      lines.push('Sources: Cloudflare/Google DoH, ipapi.co');

      return { kind: 'ip', lines };
    }

    async function runLookup(target, extraArgs) {
      const norm = normalizeTarget(target);
      if (!norm.ok) {
        return {
          ok: false,
          reason: norm.reason,
          lines: usageLines(),
        };
      }
      resetAsnRunState();
      if (norm.kind === 'domain') {
        const report = await runDomainLookup(norm.value, extraArgs);
        return { ok: true, ...report };
      }
      const report = await runIpLookup(norm.value, norm.kind, extraArgs);
      return { ok: true, ...report };
    }

    return {
      dohQuery,
      dohQueryCatch,
      resolveTxt,
      lookupAsn,
      runLookup,
      walkSpfIncludes,
      normalizeTarget,
      parseSpfRecord,
      parseDmarcFromTxts,
      buildIpv4Ptr,
      buildIpv6Ptr,
      registrableDomainFromHost,
      DKIM_SELECTORS,
      _dnsCache: dnsCache,
      _getAsnState: () => ({ asnBudgetRemaining, asnStopped }),
    };
  }

  function usageLines() {
    return [
      'Usage: dns <domain|ip>',
      '       dns queries public DoH resolvers and prints a full record report.',
      'Example: dns example.com',
      'Example: dns 192.0.2.10',
    ];
  }

  let sessionResolver = null;
  const resolverByFetch = new WeakMap();

  function getSessionResolver(options) {
    const opts = options || {};
    const fetchFn = opts.fetch || DEFAULT_FETCH;
    if (!fetchFn) {
      throw new Error('fetch is not available');
    }
    if (opts.fetch) {
      if (!resolverByFetch.has(fetchFn)) {
        resolverByFetch.set(fetchFn, createResolver(opts));
      }
      return resolverByFetch.get(fetchFn);
    }
    if (!sessionResolver) {
      sessionResolver = createResolver({ fetch: DEFAULT_FETCH });
    }
    return sessionResolver;
  }

  return {
    usageLines,
    normalizeTarget,
    normalizeHostname,
    parseSpfRecord,
    parseDmarcFromTxts,
    buildIpv4Ptr,
    buildIpv6Ptr,
    registrableDomainFromHost,
    DKIM_SELECTORS,
    createResolver,
    getSessionResolver,
    resetSessionForTests() {
      sessionResolver = null;
    },
    async lookup(target, extraArgs, options) {
      return getSessionResolver(options).runLookup(target, extraArgs);
    },
  };
});