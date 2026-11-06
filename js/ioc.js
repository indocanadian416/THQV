/*
 * IOC extraction: re-fanging, extraction, classification and export.
 * Pure functions - no DOM access - so they can be unit tested under Node.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.THQV = Object.assign(root.THQV || {}, api);
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /** Display order, labels and export names for every IOC category. */
  const IOC_TYPES = [
    { key: 'ipv4', label: 'IPv4 Addresses', badge: 'IPv4' },
    { key: 'ipv6', label: 'IPv6 Addresses', badge: 'IPv6' },
    { key: 'domains', label: 'Domains', badge: 'DOMAIN' },
    { key: 'urls', label: 'URLs', badge: 'URL' },
    { key: 'emails', label: 'Email Addresses', badge: 'EMAIL' },
    { key: 'md5', label: 'MD5 Hashes', badge: 'MD5' },
    { key: 'sha1', label: 'SHA-1 Hashes', badge: 'SHA1' },
    { key: 'sha256', label: 'SHA-256 Hashes', badge: 'SHA256' },
    { key: 'sha512', label: 'SHA-512 Hashes', badge: 'SHA512' },
    { key: 'cves', label: 'CVE IDs', badge: 'CVE' }
  ];

  const HASH_LENGTHS = { 32: 'md5', 40: 'sha1', 64: 'sha256', 128: 'sha512' };

  /*
   * "Domains" ending in these are almost always file names in threat-intel
   * text (invoice.pdf, run.ps1). A few are also real TLDs (.zip, .sh, .py) -
   * those are still treated as files because that is far more common in IOC
   * reports; search the URL list if you expect such a domain.
   */
  const FILE_EXTENSIONS = new Set((
    'exe dll sys drv ocx cpl scr pif com.exe bat cmd ps1 psm1 psd1 vbs vbe js jse wsf wsh hta msi msp lnk jar ' +
    'py pyc sh bash elf so dylib apk ipa dmg pkg deb rpm iso img vhd vhdx ova zip rar 7z gz tgz bz2 xz tar cab ' +
    'doc docx docm dot dotm xls xlsx xlsm xlsb xlam ppt pptx pptm rtf pdf odt ods txt log ini cfg conf config ' +
    'json xml yml yaml csv tsv tmp dat bin bak old db sqlite mdb jpg jpeg png gif bmp svg ico webp tif tiff ' +
    'mp3 mp4 avi mov wav mkv htm html xhtml php asp aspx jsp css eml msg one onepkg key pem crt cer pfx p12 ' +
    'evtx etl pcap pcapng dmp lock md rst c cpp h cs go rs rb pl lua'
  ).split(/\s+/));

  /**
   * Turn defanged indicators back into their real form:
   * hxxp -> http, fxp -> ftp, [.] (.) {.} [dot] (dot) -> ".", [:] -> ":",
   * [://] -> "://", [@] [at] (at) -> "@", "\." -> ".".
   */
  function refang(text) {
    return String(text || '')
      .replace(/\bhxxp(s?)/gi, 'http$1')
      .replace(/\bh\*\*p(s?)/gi, 'http$1')
      .replace(/\bfxp\b/gi, 'ftp')
      .replace(/\[\s*:\s*\/\s*\/\s*\]/g, '://')
      .replace(/[\[\(\{]\s*:\s*[\]\)\}]/g, ':')
      .replace(/\s*[\[\(\{]\s*(?:\.\.?|dot)\s*[\]\)\}]\s*/gi, '.')
      .replace(/\s*[\[\(\{]\s*(?:@|at)\s*[\]\)\}]\s*/gi, '@')
      .replace(/\\\./g, '.');
  }

  /** Make an indicator safe to paste into tickets/chat (the reverse of refang). */
  function defang(value) {
    return String(value)
      .replace(/^http/i, (m) => (m[0] === 'H' ? 'Hxxp' : 'hxxp'))
      .replace(/^ftp/i, 'fxp')
      .replace(/:\/\//, '[://]')
      .replace(/\./g, '[.]')
      .replace(/@/g, '[@]');
  }

  function isValidIPv4(ip) {
    const parts = ip.split('.');
    return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255 && !(p.length > 1 && p[0] === '0'));
  }

  function isValidIPv6(ip) {
    if (!/^[0-9a-f:]+$/i.test(ip) || !/[0-9a-f]/i.test(ip)) return false;
    const halves = ip.split('::');
    if (halves.length > 2) return false;
    const groups = (s) => (s === '' ? [] : s.split(':'));
    const head = groups(halves[0]);
    const tail = halves.length === 2 ? groups(halves[1]) : [];
    const all = head.concat(tail);
    if (!all.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return false;
    return halves.length === 2 ? all.length <= 7 : all.length === 8;
  }

  function hashType(value) {
    return /^[0-9a-f]+$/i.test(value) ? HASH_LENGTHS[value.length] || null : null;
  }

  function isLikelyDomain(domain) {
    const labels = domain.split('.');
    if (labels.length < 2 || domain.length > 253) return false;
    const tld = labels[labels.length - 1].toLowerCase();
    if (!/^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/.test(tld)) return false;
    return !FILE_EXTENSIONS.has(tld);
  }

  function uniq(list, normalise) {
    const seen = new Set();
    const out = [];
    for (const item of list) {
      const v = normalise ? normalise(item) : item;
      if (!seen.has(v)) { seen.add(v); out.push(v); }
    }
    return out;
  }

  function emptyResult() {
    const r = {};
    IOC_TYPES.forEach((t) => { r[t.key] = []; });
    return r;
  }

  /** Extract every supported indicator type from free text. */
  function extractIOCs(input) {
    const text = refang(input);
    const result = emptyResult();

    // URLs first; trailing sentence punctuation is not part of the URL.
    const urls = (text.match(/\b(?:https?|ftp):\/\/[^\s<>"'`{}|\\^\[\]]+/gi) || [])
      .map((u) => u.replace(/[.,;:!?'")\]}>]+$/, ''))
      .filter((u) => u.length > 8);
    result.urls = uniq(urls);

    result.emails = uniq(text.match(/\b[a-z0-9._%+-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi) || [], (e) => e.toLowerCase());

    result.ipv4 = uniq((text.match(/(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)/g) || []).filter(isValidIPv4));

    result.ipv6 = uniq(
      (text.match(/(?<![0-9a-z:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-z:])/gi) || []).filter(isValidIPv6),
      (ip) => ip.toLowerCase()
    );

    const domains = [];
    const domainRe = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]\b/gi;
    let m;
    while ((m = domainRe.exec(text)) !== null) {
      const before = text[m.index - 1];
      if (before === '@' || before === '.' || before === '-') continue; // part of an email / longer token
      if (isLikelyDomain(m[0])) domains.push(m[0]);
    }
    result.domains = uniq(domains, (d) => d.toLowerCase());

    const hashes = text.match(/(?<![0-9a-z])[0-9a-f]{32,128}(?![0-9a-z])/gi) || [];
    hashes.forEach((h) => {
      const type = hashType(h);
      if (type) result[type].push(h.toLowerCase());
    });
    Object.values(HASH_LENGTHS).forEach((k) => { result[k] = uniq(result[k]); });

    result.cves = uniq(text.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || [], (c) => c.toUpperCase());

    return result;
  }

  function countIOCs(result) {
    return IOC_TYPES.reduce((n, t) => n + ((result && result[t.key]) || []).length, 0);
  }

  /** Flatten to [{type, value}] in display order, optionally defanged. */
  function flatten(result, opts) {
    const out = [];
    IOC_TYPES.forEach((t) => {
      (result[t.key] || []).forEach((value) => {
        out.push({ type: t.badge, value: opts && opts.defang ? defang(value) : value });
      });
    });
    return out;
  }

  /**
   * One CSV cell. Quotes when needed (commas, quotes, newlines) and neutralises
   * spreadsheet formula injection (cells starting with = + - @ tab CR).
   */
  function csvCell(value) {
    let v = String(value == null ? '' : value);
    if (/^[=+\-@\t\r]/.test(v)) v = "'" + v;
    return /[",\r\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
  }

  function toCSV(result, opts) {
    const rows = [['type', 'value']].concat(flatten(result, opts).map((r) => [r.type, r.value]));
    return rows.map((r) => r.map(csvCell).join(',')).join('\r\n') + '\r\n';
  }

  function toTXT(result, opts) {
    return IOC_TYPES.filter((t) => result[t.key].length)
      .map((t) => '=== ' + t.label + ' ===\n' + result[t.key].map((v) => (opts && opts.defang ? defang(v) : v)).join('\n'))
      .join('\n\n') + '\n';
  }

  function toJSON(result, opts) {
    const out = {};
    IOC_TYPES.forEach((t) => {
      out[t.key] = result[t.key].map((v) => (opts && opts.defang ? defang(v) : v));
    });
    return JSON.stringify(out, null, 2) + '\n';
  }

  /** Classify a single indicator (used by the OSINT pivot box). */
  function detectIndicatorType(raw) {
    const v = refang(String(raw || '').trim());
    if (!v) return null;
    if (/^CVE-\d{4}-\d{4,7}$/i.test(v)) return 'cve';
    if (/^(?:https?|ftp):\/\//i.test(v)) return 'url';
    if (/^[^\s@]+@[^\s@]+\.[a-z]{2,63}$/i.test(v)) return 'email';
    if (isValidIPv4(v)) return 'ipv4';
    if (v.includes(':') && isValidIPv6(v)) return 'ipv6';
    const h = hashType(v);
    if (h) return h;
    if (/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/i.test(v) && isLikelyDomain(v)) return 'domain';
    return null;
  }

  return {
    IOC_TYPES, refang, defang, extractIOCs, countIOCs, flatten, csvCell, toCSV, toTXT, toJSON,
    isValidIPv4, isValidIPv6, hashType, detectIndicatorType, emptyResult
  };
});
