'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { osintTools, resolveToolUrl } = require('../js/osint.js');
const { buildHypotheses, kqlList, keywords, threatName } = require('../js/hypothesis.js');
const { analyzeKql } = require('./kql.js');

test('OSINT keyboard covers A-Z exactly once with https home pages', () => {
  assert.deepEqual(osintTools.map((t) => t.key).join(''), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  osintTools.forEach((t) => assert.match(t.home, /^https:\/\//, t.name));
});

test('every tool builds an https URL for each type it claims to support', () => {
  const samples = {
    ipv4: '8.8.8.8', ipv6: '2001:db8::1', domain: 'evil.com', url: 'https://evil.com/a?b=c',
    md5: 'd41d8cd98f00b204e9800998ecf8427e', sha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
    sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    sha512: 'a'.repeat(128), cve: 'CVE-2021-44228'
  };
  for (const tool of osintTools) {
    for (const type of tool.types) {
      const r = resolveToolUrl(tool, samples[type]);
      assert.equal(r.pivot, true, `${tool.name} ${type}`);
      assert.match(r.url, /^https:\/\/[^/]+\//, `${tool.name} ${type}`);
      assert.doesNotThrow(() => new URL(r.url));
    }
  }
});

test('defanged input is refanged before pivoting; unsupported types fall back to home', () => {
  const vt = osintTools.find((t) => t.key === 'V');
  assert.equal(resolveToolUrl(vt, '8[.]8[.]8[.]8').url, 'https://www.virustotal.com/gui/search/8.8.8.8');
  const greynoise = osintTools.find((t) => t.key === 'G');
  const r = resolveToolUrl(greynoise, 'evil.com');
  assert.equal(r.pivot, false);
  assert.equal(r.url, greynoise.home);
  assert.equal(resolveToolUrl(vt, '').url, vt.home);
});

test('kqlList escapes quotes and backslashes', () => {
  assert.equal(kqlList(['a"b', 'c\\d']), 'dynamic(["a\\"b", "c\\\\d"])');
  assert.deepEqual(analyzeKql('print x = ' + kqlList(['a"b', 'c\\d', "it's"])), []);
});

test('keywords drop stopwords and keep distinctive words', () => {
  assert.deepEqual(keywords('Hackers exploit new Fortinet FortiGate flaw in attacks'), ['fortinet', 'fortigate']);
});

const articles = [
  { title: 'Ivanti fixes CVE-2025-0282 and CVE-2025-0283 exploited in the wild', description: '', source: 'BleepingComputer', date: new Date('2026-11-05T10:00:00Z') },
  { title: 'New loader uses C2 at 185[.]220[.]101[.]4 and update-check[.]net', description: 'Researchers saw beacons to hxxps://update-check[.]net/a', source: 'The Hacker News' },
  { title: 'Akira ransomware hits manufacturer', description: '', source: 'SecurityWeek', tags: [{ name: 'Ransomware', type: 'critical' }] },
  { title: 'Phishing campaign impersonates "DocuSign" invoices', description: '', source: 'Dark Reading' },
  { title: 'Malicious npm packages steal tokens', description: 'supply chain attack', source: 'Krebs on Security' },
  { title: 'Chinese state-sponsored group deploys backdoor', description: '', source: 'BleepingComputer' },
  { title: 'Infostealer malware spreads via fake game cheats', description: '', source: 'BleepingComputer' },
  { title: 'Company announces quarterly results', description: 'Nothing security related; contact press@example.com or see https://example.com', source: 'x' }
];

test('hypotheses pick the right rule from article content', () => {
  const h = buildHypotheses(articles, 20);
  assert.deepEqual(h.map((x) => x.rule), ['cve', 'ioc', 'ransomware', 'phishing', 'supply-chain', 'apt', 'malware', 'exfil']);
  assert.match(h[0].query, /CVE-2025-0282/);
  // Indicators appear only defanged in the generated query (refanged by KQL at run time).
  assert.ok(h[1].query.includes('185[.]220[.]101[.]4') && h[1].query.includes('update-check[.]net'), h[1].query);
  assert.ok(!h[1].query.includes('185.220.101.4') && !h[1].query.includes('update-check.net'), 'live indicator shown on the page');
  assert.doesNotMatch(h[7].query, /example\.com/, 'plain (non-defanged) vendor links are not treated as IOCs');
});

test('every generated hypothesis query parses and type-checks', () => {
  for (const h of buildHypotheses(articles, 20)) {
    assert.deepEqual(analyzeKql(h.query), [], h.rule);
  }
});

test('limit is respected and empty input is safe', () => {
  assert.equal(buildHypotheses(articles, 3).length, 3);
  assert.deepEqual(buildHypotheses([], 10), []);
  assert.deepEqual(buildHypotheses(undefined, 10), []);
});

const queryBody = (q) => q.split('\n').filter((l) => !l.startsWith('//')).join('\n');
const news = (titles, tagName) => titles.map((title, i) => ({
  title, description: '', source: 'BleepingComputer', date: new Date(Date.UTC(2026, 10, 6, 12 - i)),
  tags: tagName && new RegExp(tagName, 'i').test(title) ? [{ name: tagName, type: 'critical' }] : []
}));

test('similar stories never produce the same query twice', () => {
  const batches = [
    news(['Qilin ransomware claims attack on brewer', 'Akira ransomware abuses SonicWall VPN accounts', 'Ransomware gang leaks hospital data',
      'Play ransomware hits city council', 'Medusa ransomware demands $4 million', 'Ransomware attack disrupts school district',
      'LockBit ransomware returns', 'Ransomware gang exploits Veeam flaw', 'Hospital diverts ambulances after ransomware attack',
      'Interlock ransomware uses fake CAPTCHA'], 'Ransomware'),
    news(['Microsoft fixes Windows flaw exploited in attacks', 'FBI warns of rise in tech support scams', 'Company reports quarterly results',
      'Retailer says customer passwords were stolen', 'Lumma stealer returns after takedown', 'New Android banking trojan targets 400 apps',
      'Chinese espionage group targets telecoms with new backdoor', 'North Korean hackers pose as recruiters on LinkedIn',
      'Cisco patches critical bug in ASA', 'City government shares outage update'])
  ];
  for (const articles of batches) {
    const h = buildHypotheses(articles, 10);
    assert.ok(h.length >= 8, 'expected most articles to yield a hypothesis, got ' + h.length);
    assert.equal(new Set(h.map((x) => queryBody(x.query))).size, h.length, 'duplicate query');
    assert.equal(new Set(h.map((x) => x.title)).size, h.length, 'duplicate title');
    h.forEach((x) => {
      assert.match(x.title, /^[A-Z]/, 'title should start with a capital: ' + x.title);
      assert.deepEqual(analyzeKql(x.query), [], x.title);
    });
  }
});

test('repeated ransomware stories rotate hunt angles and name the group', () => {
  const h = buildHypotheses(news(['Qilin ransomware hits maker', 'Akira ransomware targets VPNs', 'Play ransomware claims attack', 'Medusa ransomware demands ransom'], 'Ransomware'), 10);
  assert.deepEqual(h.map((x) => x.rule), ['ransomware', 'ransomware', 'ransomware', 'ransomware']);
  ['Qilin', 'Akira', 'Play', 'Medusa'].forEach((name, i) => assert.ok(h[i].title.startsWith(name + ' ransomware'), h[i].title));
  assert.equal(new Set(h.map((x) => queryBody(x.query))).size, 4);
});

test('threatName picks real family names and ignores generic words', () => {
  assert.equal(threatName('Qilin ransomware claims attack'), 'Qilin');
  assert.equal(threatName('Lumma stealer returns after takedown'), 'Lumma');
  assert.equal(threatName('New Android banking trojan targets apps'), null);
  assert.equal(threatName('Infostealer malware spreads via fake cheats'), null);
  assert.equal(threatName('Ransomware attack disrupts school district'), null);
});

test('headline keywords skip generic security words', () => {
  assert.deepEqual(keywords('Ransomware gang exploits Veeam flaw'), ['veeam']);
  assert.deepEqual(keywords('Microsoft fixes Windows flaw exploited in attacks'), ['microsoft', 'windows']);
});
