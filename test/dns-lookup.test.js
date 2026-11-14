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

    const over = 'v=spf1 ' + Array.from({ length: 12 }, (_, i) => `include:inc${i}.example.org`).join(' ') + ' -all';
    const overParsed = DnsLookup.parseSpfRecord(over);
    assert.ok(overParsed.mechanismCount > 10);
    assert.ok(overParsed.warnings.length > 0);

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
});

function createResolver(fetchFn) {
  return DnsLookup.createResolver({ fetch: fetchFn, dohTimeoutMs: 50, asnTimeoutMs: 50 });
}

function create(r) {
  return r;
}