'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { osintTools, resolveToolUrl } = require('../js/osint.js');
const { buildHypotheses, kqlList, keywords } = require('../js/hypothesis.js');
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
  assert.match(h[1].query, /185\.220\.101\.4/);
  assert.match(h[1].query, /update-check\.net/);
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
