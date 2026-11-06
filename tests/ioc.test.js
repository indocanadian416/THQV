'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const I = require('../js/ioc.js');

test('refang handles common defanging styles', () => {
  assert.equal(I.refang('8[.]8[.]8[.]8'), '8.8.8.8');
  assert.equal(I.refang('evil[dot]com'), 'evil.com');
  assert.equal(I.refang('evil(.)com'), 'evil.com');
  assert.equal(I.refang('evil{.}com'), 'evil.com');
  assert.equal(I.refang('evil [.] com'), 'evil.com');
  assert.equal(I.refang('hxxps[:]//a[.]b'), 'https://a.b');
  assert.equal(I.refang('hXXp[://]a.b'), 'http://a.b');
  assert.equal(I.refang('user[at]corp[.]com'), 'user@corp.com');
  assert.equal(I.refang('user[@]corp.com'), 'user@corp.com');
  assert.equal(I.refang('fxp://files.example.net'), 'ftp://files.example.net');
});

test('defang is the inverse of refang for typical values', () => {
  for (const v of ['https://evil.com/x', '8.8.8.8', 'a@b.org', 'sub.evil.co.uk']) {
    assert.equal(I.refang(I.defang(v)), v);
  }
  assert.equal(I.defang('https://evil.com/x'), 'hxxps[://]evil[.]com/x');
});

test('extracts every type from mixed, defanged text', () => {
  const r = I.extractIOCs([
    'C2 8[.]8[.]8[.]8 and 2001:db8::1, beacon to hxxps[:]//bad[.]site/a,b.',
    'Domain evil[dot]com, contact a@b.org, report.docx and run.ps1 dropped.',
    'md5 D41D8CD98F00B204E9800998ECF8427E sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709',
    'sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 exploits cve-2024-3400'
  ].join('\n'));
  assert.deepEqual(r.ipv4, ['8.8.8.8']);
  assert.deepEqual(r.ipv6, ['2001:db8::1']);
  assert.deepEqual(r.urls, ['https://bad.site/a,b']);
  assert.deepEqual(r.emails, ['a@b.org']);
  assert.deepEqual(r.domains.sort(), ['bad.site', 'evil.com']);
  assert.deepEqual(r.md5, ['d41d8cd98f00b204e9800998ecf8427e']);
  assert.deepEqual(r.sha1, ['da39a3ee5e6b4b0d3255bfef95601890afd80709']);
  assert.deepEqual(r.sha256, ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']);
  assert.deepEqual(r.cves, ['CVE-2024-3400']);
});

test('rejects things that only look like indicators', () => {
  const r = I.extractIOCs('version 1.2.3.4.5, bad 1.2.3.999, leading 01.2.3.4, time 10:30:00, mac 00:1a:2b:3c:4d:5e, e.g. i.e. invoice.pdf setup.exe notes.txt');
  assert.deepEqual(r.ipv4, []);
  assert.deepEqual(r.ipv6, []);
  assert.deepEqual(r.domains, []);
});

test('hash classification by length and hex-only content', () => {
  assert.equal(I.hashType('a'.repeat(32)), 'md5');
  assert.equal(I.hashType('a'.repeat(40)), 'sha1');
  assert.equal(I.hashType('a'.repeat(64)), 'sha256');
  assert.equal(I.hashType('a'.repeat(128)), 'sha512');
  assert.equal(I.hashType('a'.repeat(50)), null);
  assert.equal(I.hashType('g'.repeat(32)), null);
});

test('detectIndicatorType', () => {
  assert.equal(I.detectIndicatorType('8[.]8[.]8[.]8'), 'ipv4');
  assert.equal(I.detectIndicatorType('2001:db8::1'), 'ipv6');
  assert.equal(I.detectIndicatorType('evil[.]com'), 'domain');
  assert.equal(I.detectIndicatorType('hxxps://evil.com/a'), 'url');
  assert.equal(I.detectIndicatorType('a@b.org'), 'email');
  assert.equal(I.detectIndicatorType('CVE-2021-44228'), 'cve');
  assert.equal(I.detectIndicatorType('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'), 'sha256');
  assert.equal(I.detectIndicatorType('run.ps1'), null);
  assert.equal(I.detectIndicatorType(''), null);
});

test('CSV export quotes values and blocks formula injection', () => {
  const r = I.emptyResult();
  r.urls = ['https://x.com/a,b', 'https://x.com/"q"'];
  r.domains = ['=cmd|calc', '+evil.com', '@evil.com', '-evil.com'];
  const csv = I.toCSV(r);
  const lines = csv.trim().split('\r\n');
  assert.equal(lines[0], 'type,value');
  assert.ok(lines.includes('DOMAIN,\'=cmd|calc'));
  assert.ok(lines.includes('DOMAIN,\'+evil.com'));
  assert.ok(lines.includes('DOMAIN,\'@evil.com'));
  assert.ok(lines.includes('DOMAIN,\'-evil.com'));
  assert.ok(lines.includes('URL,"https://x.com/a,b"'));
  assert.ok(lines.includes('URL,"https://x.com/""q"""'));
});

test('TXT/JSON export, with and without defanging', () => {
  const r = I.extractIOCs('8.8.8.8 evil.com');
  assert.match(I.toTXT(r), /=== IPv4 Addresses ===\n8\.8\.8\.8/);
  assert.deepEqual(JSON.parse(I.toJSON(r, { defang: true })).ipv4, ['8[.]8[.]8[.]8']);
  assert.equal(I.countIOCs(r), 2);
});
