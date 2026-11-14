'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const DnsLookup = require('../assets/js/dns-lookup.js');

const jsonAnswer = (name, type, data) => ({
  Status: 0,
  Answer: [{ name: `${name}.`, type, TTL: 300, data }],
});

function emptyDns() {
  return { Status: 0, Answer: [] };
}

function makeFetch(handlers) {
  const calls = [];
  const fetchFn = async (url, init) => {
    calls.push({ url, init });
    for (const h of handlers) {
      const res = await h(url, init, calls);
      if (res !== undefined) return res;
    }
    throw new Error(`unhandled fetch: ${url}`);
  };
  return { fetchFn, calls };
}

function cloudflareHandler(map) {
  return async (url) => {
    if (!url.includes('cloudflare-dns.com')) return undefined;
    const u = new URL(url);
    const name = u.searchParams.get('name');
    const type = u.searchParams.get('type');
    const key = `${name}|${type}`;
    if (map.failCloudflare) {
      return { ok: false, status: 503, json: async () => ({}) };
    }
    const body = map[key] ?? map.default ?? emptyDns();
    return { ok: true, json: async () => body };
  };
}

function googleHandler(map) {
  return async (url) => {
    if (!url.includes('dns.google')) return undefined;
    const u = new URL(url);
    const name = u.searchParams.get('name');
    const type = u.searchParams.get('type');
    const key = `${name}|${type}`;
    const body = map[key] ?? map.googleDefault ?? emptyDns();
    return { ok: true, json: async () => body };
  };
}

function ipapiHandler(map) {
  let asnCalls = 0;
  return {
    handler: async (url) => {
      if (!url.includes('ipapi.co')) return undefined;
      asnCalls += 1;
      if (map.stopAfter && asnCalls >= map.stopAfter) {
        return { ok: false, status: 429, json: async () => ({ error: true, reason: 'rate limit' }) };
      }
      const m = url.match(/ipapi\.co\/([^/]+)\/json/);
      const ip = m && m[1];
      const row = (map.ips && map.ips[ip]) || { asn: 'AS64496', org: 'Example Org', ip };
      return { ok: true, json: async () => row };
    },
    getCount: () => asnCalls,
  };
}

describe('dns-lookup', () => {
  it('usage on empty or invalid input without fetch', async () => {
    const { fetchFn, calls } = makeFetch([]);
    const r = create(createResolver(fetchFn));
    let out = await r.runLookup('');
    assert.equal(out.ok, false);
    assert.match(out.lines.join('\n'), /Usage: dns/);
    assert.equal(calls.length, 0);
    out = await r.runLookup('not a valid..host!!');
    assert.equal(out.ok, false);
    assert.equal(calls.length, 0);
  });

  it('Cloudflare first then Google fallback', async () => {
    const dnsMap = {
      failCloudflare: true,
      'example.com|1': jsonAnswer('example.com', 1, '192.0.2.1'),
      default: emptyDns(),
      googleDefault: emptyDns(),
    };
    for (const t of ['28', '5', '15', '2', '6', '16', '257']) {
      dnsMap[`example.com|${t}`] = emptyDns();
      dnsMap[`_dmarc.example.com|16`] = emptyDns();
    }
    const ipapi = ipapiHandler({ ips: { '192.0.2.1': { asn: 'AS64496', org: 'Example Org' } } });
    const { fetchFn, calls } = makeFetch([
      cloudflareHandler(dnsMap),
      googleHandler(dnsMap),
      ipapi.handler,
    ]);
    const r = createResolver(fetchFn);
    await r.runLookup('example.com');
    const cf = calls.filter((c) => c.url.includes('cloudflare-dns.com'));
    const gg = calls.filter((c) => c.url.includes('dns.google'));
    assert.ok(cf.length > 0);
    assert.ok(gg.length > 0);
  });

  it('session cache prevents duplicate DoH fetches', async () => {
    const dnsMap = { default: emptyDns() };
    dnsMap['example.com|1'] = jsonAnswer('example.com', 1, '192.0.2.1');
    const { fetchFn, calls } = makeFetch([cloudflareHandler(dnsMap), googleHandler(dnsMap)]);
    const r = createResolver(fetchFn);
    await r.dohQuery('example.com', 'A');
    await r.dohQuery('example.com', 'A');
    const aQueries = calls.filter(
      (c) => c.url.includes('name=example.com') && /type=(1|A)/.test(c.url),
    );
    assert.equal(aQueries.length, 1);
  });

  it('SPF parser counts mechanisms, include walk, and over-10 warning', async () => {
    const root =
      'v=spf1 include:spf1.example.org include:spf2.example.org a mx ptr exists:%{i} -all extra';
    const parsed = DnsLookup.parseSpfRecord(root);
    assert.ok(parsed.mechanismCount >= 6);
    assert.equal(parsed.allWord, 'fail (-all)');

    const onlyAll = DnsLookup.parseSpfRecord('v=spf1 -all');
    assert.equal(onlyAll.mechanismCount, 0);
    assert.equal(onlyAll.allWord, 'fail (-all)');

    const over = 'v=spf1 ' + Array.from({ length: 12 }, (_, i) => `include:inc${i}.example.org`).join(' ') + ' -all';
    const overParsed = DnsLookup.parseSpfRecord(over);
    assert.equal(overParsed.mechanismCount, 12);
    assert.ok(overParsed.warnings.length > 0);
    assert.equal(overParsed.displayCount, '12 / 10');

    const resolveTxt = async (name) => {
      if (name === 'spf1.example.org') return ['v=spf1 include:deep.example.org -all'];
      if (name === 'deep.example.org') return ['v=spf1 -all'];
      return [];
    };
    const r = createResolver(async () => ({ ok: true, json: async () => ({}) }));
    const walked = await r.walkSpfIncludes(root, resolveTxt, 10);
    assert.ok(walked.chain.length >= 2);
    assert.match(walked.displayCount, /\/ 10/);
  });

  it('DMARC parser extracts policy tags', () => {
    const txts = ['v=DMARC1; p=reject; pct=100; sp=quarantine; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com'];
    const d = DnsLookup.parseDmarcFromTxts(txts);
    assert.equal(d.p, 'reject');
    assert.equal(d.pct, '100');
    assert.equal(d.sp, 'quarantine');
    assert.match(d.rua, /example.com/);
    assert.match(d.ruf, /example.com/);
  });

  it('DKIM selector list has 16 probes and accepts TXT or CNAME', async () => {
    assert.equal(DnsLookup.DKIM_SELECTORS.length, 16);
    assert.ok(DnsLookup.DKIM_SELECTORS.includes('google'));
    assert.ok(DnsLookup.DKIM_SELECTORS.includes('zendesk1'));

    const dnsMap = { default: emptyDns() };
    dnsMap['google._domainkey.example.com|16'] = jsonAnswer(
      'google._domainkey.example.com',
      16,
      'v=DKIM1; k=rsa; p=abc',
    );
    dnsMap['selector1._domainkey.example.org|5'] = jsonAnswer(
      'selector1._domainkey.example.org',
      5,
      'dkim.example.org.',
    );
    for (const t of ['1', '28', '5', '15', '2', '6', '16', '257']) {
      dnsMap[`example.com|${t}`] = emptyDns();
      dnsMap[`example.org|${t}`] = emptyDns();
      dnsMap[`_dmarc.example.com|16`] = emptyDns();
      dnsMap[`_dmarc.example.org|16`] = emptyDns();
    }
    dnsMap['example.com|1'] = jsonAnswer('example.com', 1, '192.0.2.1');
    dnsMap['example.org|1'] = jsonAnswer('example.org', 1, '192.0.2.2');
    const { fetchFn } = makeFetch([cloudflareHandler(dnsMap), googleHandler(dnsMap)]);
    const r = createResolver(fetchFn);
    const comReport = await r.runLookup('example.com');
    assert.match(comReport.lines.join('\n'), /google: TXT/);
    const orgReport = await r.runLookup('example.org');
    assert.match(orgReport.lines.join('\n'), /selector1: CNAME/);
  });

  it('PTR builders for documentation IPs', () => {
    assert.equal(DnsLookup.buildIpv4Ptr('192.0.2.10'), '10.2.0.192.in-addr.arpa');
    const v6 = DnsLookup.buildIpv6Ptr('2001:db8::10');
    assert.ok(v6.endsWith('.ip6.arpa'));
    assert.ok(v6.split('.').length > 32);
  });

  it('never requests crt.sh during dns lookup', async () => {
    const dnsMap = { default: emptyDns() };
    dnsMap['example.org|1'] = jsonAnswer('example.org', 1, '192.0.2.5');
    const ipapi = ipapiHandler({});
    const { fetchFn, calls } = makeFetch([
      cloudflareHandler(dnsMap),
      googleHandler(dnsMap),
      ipapi.handler,
    ]);
    const r = createResolver(fetchFn);
    await r.runLookup('example.org');
    assert.ok(!calls.some((c) => c.url.includes('crt.sh')));
  });

  it('ASN budget stops after 429 but still prints IPs', async () => {
    const dnsMap = { default: emptyDns() };
    const ips = [];
    for (let i = 1; i <= 16; i += 1) {
      const ip = `192.0.2.${i}`;
      ips.push(ip);
      dnsMap[`example.com|1`] = {
        Status: 0,
        Answer: ips.map((addr) => ({ name: 'example.com.', type: 1, TTL: 60, data: addr })),
      };
    }
    const ipapi = ipapiHandler({ stopAfter: 1 });
    const { fetchFn } = makeFetch([cloudflareHandler(dnsMap), googleHandler(dnsMap), ipapi.handler]);
    const r = createResolver(fetchFn);
    const report = await r.runLookup('example.com');
    const text = report.lines.join('\n');
    assert.match(text, /192\.0\.2\./);
    const state = r._getAsnState();
    assert.ok(state.asnStopped || state.asnBudgetRemaining < 15);
  });

  it('formatter includes section headers and does not invent IPs', async () => {
    const dnsMap = { default: emptyDns() };
    dnsMap['example.com|1'] = jsonAnswer('example.com', 1, '192.0.2.1');
    const ipapi = ipapiHandler({ ips: { '192.0.2.1': { asn: 'AS64496', org: 'Example Org' } } });
    const { fetchFn } = makeFetch([cloudflareHandler(dnsMap), googleHandler(dnsMap), ipapi.handler]);
    const r = createResolver(fetchFn);
    const report = await r.runLookup('example.com');
    const text = report.lines.join('\n');
    for (const header of ['[A / AAAA]', '[MX]', '[NS]', '[SOA]', '[TXT]', '[CAA]', '[SPF]', '[DMARC]', '[DKIM]']) {
      assert.match(text, new RegExp(header.replace(/[[\]]/g, '\\$&')));
    }
    assert.match(text, /AS64496/);
    assert.ok(!text.includes('10.0.0.1'));
    assert.ok(!text.includes('198.51.100'));
  });

  it('IPv4 and IPv6 targets produce reverse reports', async () => {
    const ptr4 = '10.2.0.192.in-addr.arpa';
    const dnsMap = {
      default: emptyDns(),
      [`${ptr4}|12`]: jsonAnswer(ptr4, 12, 'host.example.com'),
      'host.example.com|1': jsonAnswer('host.example.com', 1, '192.0.2.10'),
      'host.example.com|28': emptyDns(),
    };
    const ptr6 = DnsLookup.buildIpv6Ptr('2001:db8::5');
    dnsMap[`${ptr6}|12`] = jsonAnswer(ptr6, 12, 'v6.example.org');
    dnsMap['v6.example.org|28'] = jsonAnswer('v6.example.org', 28, '2001:db8::5');
    dnsMap['v6.example.org|1'] = emptyDns();

    const ipapi = ipapiHandler({
      ips: {
        '192.0.2.10': { asn: 'AS64496', org: 'Example Org' },
        '2001:db8::5': { asn: 'AS64496', org: 'Example Org' },
      },
    });
    const { fetchFn } = makeFetch([cloudflareHandler(dnsMap), googleHandler(dnsMap), ipapi.handler]);
    const r = createResolver(fetchFn);

    const v4 = await r.runLookup('192.0.2.10');
    assert.match(v4.lines.join('\n'), /\[PTR\]/);
    assert.match(v4.lines.join('\n'), /\[Forward confirm\]/);

    const v6 = await r.runLookup('2001:db8::5');
    assert.match(v6.lines.join('\n'), /Reverse DNS report/);
  });

  it('extra arguments add ignore note', async () => {
    const dnsMap = { default: emptyDns() };
    dnsMap['example.com|1'] = jsonAnswer('example.com', 1, '192.0.2.1');
    const { fetchFn } = makeFetch([cloudflareHandler(dnsMap), googleHandler(dnsMap)]);
    const r = createResolver(fetchFn);
    const report = await r.runLookup('example.com', ['MX', 'ignored']);
    assert.match(report.lines.join('\n'), /extra arguments ignored/);
  });

  it('normalizes trailing-dot MX hosts for follow-up A lookups', async () => {
    const dnsMap = { default: emptyDns() };
    dnsMap['example.com|15'] = {
      Status: 0,
      Answer: [{ name: 'example.com.', type: 15, TTL: 300, data: '10 mail.example.com.' }],
    };
    dnsMap['mail.example.com|1'] = jsonAnswer('mail.example.com', 1, '192.0.2.55');
    for (const t of ['1', '28', '5', '2', '6', '16', '257']) {
      if (t !== '15') dnsMap[`example.com|${t}`] = emptyDns();
    }
    dnsMap['_dmarc.example.com|16'] = emptyDns();
  const ptr = '55.2.0.192.in-addr.arpa';
    dnsMap[`${ptr}|12`] = jsonAnswer(ptr, 12, 'mail.example.com');
    const ipapi = ipapiHandler({ ips: { '192.0.2.55': { asn: 'AS64496', org: 'Example Org' } } });
    const { fetchFn, calls } = makeFetch([
      cloudflareHandler(dnsMap),
      googleHandler(dnsMap),
      ipapi.handler,
    ]);
    const r = createResolver(fetchFn);
    const report = await r.runLookup('example.com');
    const text = report.lines.join('\n');
    assert.match(text, /192\.0\.2\.55/);
    assert.match(text, /AS64496/);
    assert.ok(calls.some((c) => c.url.includes('name=mail.example.com')));
    assert.ok(!calls.some((c) => c.url.includes('mail.example.com.')));
  });

  it('shows ASN/PTR on apex A and MX rows', async () => {
    const dnsMap = { default: emptyDns() };
    dnsMap['example.com|1'] = jsonAnswer('example.com', 1, '192.0.2.1');
    dnsMap['example.com|15'] = jsonAnswer('example.com', 15, '10 mx.example.com');
    dnsMap['mx.example.com|1'] = jsonAnswer('mx.example.com', 1, '192.0.2.20');
    for (const t of ['28', '5', '2', '6', '16', '257']) dnsMap[`example.com|${t}`] = emptyDns();
    dnsMap['_dmarc.example.com|16'] = emptyDns();
    const ipapi = ipapiHandler({
      ips: {
        '192.0.2.1': { asn: 'AS64496', org: 'Apex Org' },
        '192.0.2.20': { asn: 'AS64496', org: 'Mx Org' },
      },
    });
    const { fetchFn } = makeFetch([cloudflareHandler(dnsMap), googleHandler(dnsMap), ipapi.handler]);
    const r = createResolver(fetchFn);
    const text = (await r.runLookup('example.com')).lines.join('\n');
    assert.match(text, /\[A \/ AAAA\][\s\S]*192\.0\.2\.1[\s\S]*Apex Org/);
    assert.match(text, /\[MX\][\s\S]*192\.0\.2\.20[\s\S]*Mx Org/);
  });

  it('does not cache failed DoH lookups', async () => {
    const dnsMap = {
      default: emptyDns(),
      failNames: new Set(['fail.example.com']),
    };
    const cf = async (url) => {
      if (!url.includes('cloudflare-dns.com')) return undefined;
      const u = new URL(url);
      const name = u.searchParams.get('name');
      if (dnsMap.failNames.has(name)) {
        return { ok: false, status: 500, json: async () => ({}) };
      }
      return { ok: true, json: async () => emptyDns() };
    };
    const gg = async (url) => {
      if (!url.includes('dns.google')) return undefined;
      const u = new URL(url);
      if (dnsMap.failNames.has(u.searchParams.get('name'))) {
        return { ok: false, status: 500, json: async () => ({}) };
      }
      return { ok: true, json: async () => emptyDns() };
    };
    const { fetchFn } = makeFetch([cf, gg]);
    const r = createResolver(fetchFn);
    await r.dohQueryCatch('fail.example.com', 'A');
    assert.ok(!r._dnsCache.has('fail.example.com|A'));
    await r.dohQueryCatch('fail.example.com', 'A');
    const failed = (await r.dohQueryCatch('fail.example.com', 'A')).error;
    assert.ok(failed);
  });

  it('keeps report sections when one record type fails', async () => {
    const dnsMap = { default: emptyDns() };
    dnsMap['example.com|1'] = jsonAnswer('example.com', 1, '192.0.2.1');
    dnsMap['example.com|6'] = 'THROW';
    const cf = async (url) => {
      if (!url.includes('cloudflare-dns.com')) return undefined;
      const u = new URL(url);
      const key = `${u.searchParams.get('name')}|${u.searchParams.get('type')}`;
      if (dnsMap[key] === 'THROW') {
        return { ok: false, status: 503, json: async () => ({}) };
      }
      const body = dnsMap[key] ?? dnsMap.default;
      return { ok: true, json: async () => body };
    };
    const gg = async (url) => {
      if (!url.includes('dns.google')) return undefined;
      const u = new URL(url);
      const type = u.searchParams.get('type');
      const name = u.searchParams.get('name');
      const key = `${name}|${type === 'SOA' ? '6' : type}`;
      if (dnsMap[`${name}|6`] === 'THROW' && type === 'SOA') {
        return { ok: false, status: 503, json: async () => ({}) };
      }
      const body = dnsMap[`${name}|1`] && type === 'A' ? dnsMap[`${name}|1`] : dnsMap.default;
      return { ok: true, json: async () => (type === 'A' && name === 'example.com' ? dnsMap['example.com|1'] : emptyDns()) };
    };
    for (const t of ['28', '5', '15', '2', '16', '257']) dnsMap[`example.com|${t}`] = emptyDns();
    dnsMap['_dmarc.example.com|16'] = emptyDns();
    const { fetchFn } = makeFetch([cf, gg]);
    const r = createResolver(fetchFn);
    const text = (await r.runLookup('example.com')).lines.join('\n');
    assert.match(text, /\[A \/ AAAA\]/);
    assert.match(text, /\[SOA\]/);
    assert.match(text, /(Lookup failed|No records)/);
  });

  it('reuses a single resolver for repeated DnsLookup.lookup calls', async () => {
    DnsLookup.resetSessionForTests();
    const dnsMap = { default: emptyDns() };
    dnsMap['example.com|1'] = jsonAnswer('example.com', 1, '192.0.2.1');
    dnsMap['example.org|1'] = jsonAnswer('example.org', 1, '192.0.2.2');
    for (const t of ['28', '5', '15', '2', '6', '16', '257']) {
      dnsMap[`example.com|${t}`] = emptyDns();
      dnsMap[`example.org|${t}`] = emptyDns();
    }
    dnsMap['_dmarc.example.com|16'] = emptyDns();
    dnsMap['_dmarc.example.org|16'] = emptyDns();
    const { fetchFn } = makeFetch([cloudflareHandler(dnsMap), googleHandler(dnsMap)]);
    const sessionA = DnsLookup.getSessionResolver({ fetch: fetchFn });
    await sessionA.runLookup('example.com');
    const sessionB = DnsLookup.getSessionResolver({ fetch: fetchFn });
    await sessionB.runLookup('example.org');
    assert.strictEqual(sessionA, sessionB);
    const cacheKeysAfterTwo = [...sessionB._dnsCache.keys()];
    assert.ok(cacheKeysAfterTwo.length > 0);
  });

  it('resets ASN budget on each dns run so later runs still get owners', async () => {
    const dnsMap = { default: emptyDns() };
    const makeARecords = (domain, count, base) => {
      const answers = [];
      for (let i = 0; i < count; i += 1) {
        answers.push({ name: `${domain}.`, type: 1, TTL: 60, data: `192.0.2.${base + i}` });
      }
      dnsMap[`${domain}|1`] = { Status: 0, Answer: answers };
    };
    makeARecords('heavy-a.example', 10, 1);
    makeARecords('heavy-b.example', 10, 20);
    for (const domain of ['heavy-a.example', 'heavy-b.example']) {
      for (const t of ['28', '5', '15', '2', '6', '16', '257']) dnsMap[`${domain}|${t}`] = emptyDns();
      dnsMap[`_dmarc.${domain}|16`] = emptyDns();
    }
    const ipapi = ipapiHandler({});
    const { fetchFn } = makeFetch([cloudflareHandler(dnsMap), googleHandler(dnsMap), ipapi.handler]);
    const r = createResolver(fetchFn);
    const textA = (await r.runLookup('heavy-a.example')).lines.join('\n');
    const textB = (await r.runLookup('heavy-b.example')).lines.join('\n');
    assert.match(textA, /AS64496/);
    assert.match(textB, /AS64496/);
    assert.ok(ipapi.getCount() > 15);
    assert.equal(r._getAsnState().asnBudgetRemaining, 5);
    const callsBeforeCachedRerun = ipapi.getCount();
    await r.runLookup('heavy-a.example');
    assert.equal(r._getAsnState().asnBudgetRemaining, 15);
    assert.equal(ipapi.getCount(), callsBeforeCachedRerun);
  });

  it('runs wave-one queries through the DoH pool', async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    const dnsMap = { default: emptyDns() };
    dnsMap['example.com|1'] = jsonAnswer('example.com', 1, '192.0.2.1');
    const cf = async (url) => {
      if (!url.includes('cloudflare-dns.com')) return undefined;
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 5));
      inFlight -= 1;
      const u = new URL(url);
      const key = `${u.searchParams.get('name')}|${u.searchParams.get('type')}`;
      return { ok: true, json: async () => (dnsMap[key] ?? dnsMap.default) };
    };
    for (const t of ['28', '5', '15', '2', '6', '16', '257']) dnsMap[`example.com|${t}`] = emptyDns();
    dnsMap['_dmarc.example.com|16'] = emptyDns();
    const { fetchFn } = makeFetch([cf, googleHandler(dnsMap)]);
    const r = createResolver(fetchFn);
    await r.runLookup('example.com');
    assert.ok(maxInFlight > 1);
    assert.ok(maxInFlight <= 6);
  });
});

function createResolver(fetchFn) {
  return DnsLookup.createResolver({ fetch: fetchFn, dohTimeoutMs: 50, asnTimeoutMs: 50 });
}

function create(r) {
  return r;
}