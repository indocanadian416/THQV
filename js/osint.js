/*
 * OSINT tool keyboard (A-Z) with indicator pivoting.
 *
 * Each tool may define build(value, type) returning a lookup URL for that
 * indicator type, or null when the tool has no stable deep link for it. In
 * that case the UI opens the tool's home page and copies the indicator to the
 * clipboard so it can be pasted.
 */
(function (root, factory) {
  const deps = typeof module === 'object' && module.exports ? require('./ioc.js') : root.THQV;
  const api = factory(deps);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.THQV = Object.assign(root.THQV || {}, api);
})(typeof self !== 'undefined' ? self : this, function (ioc) {
  'use strict';

  const enc = encodeURIComponent;
  const IP = ['ipv4', 'ipv6'];
  const HASH = ['md5', 'sha1', 'sha256', 'sha512'];
  const isIP = (t) => IP.includes(t);
  const isHash = (t) => HASH.includes(t);

  function b64(text) {
    if (typeof btoa === 'function') return btoa(unescape(encodeURIComponent(text)));
    return Buffer.from(text, 'utf8').toString('base64');
  }

  const osintTools = [
    { key: 'A', name: 'AbuseIPDB', home: 'https://www.abuseipdb.com/', types: [...IP, 'domain'],
      build: (v) => 'https://www.abuseipdb.com/check/' + enc(v) },
    { key: 'B', name: 'BGP Toolkit (HE)', home: 'https://bgp.he.net/', types: [...IP, 'domain'],
      build: (v, t) => (isIP(t) ? 'https://bgp.he.net/ip/' + enc(v) : 'https://bgp.he.net/dns/' + enc(v)) },
    { key: 'C', name: 'Censys', home: 'https://search.censys.io/', types: [] },
    { key: 'D', name: 'SecurityTrails', home: 'https://securitytrails.com/', types: [...IP, 'domain'],
      build: (v, t) => (isIP(t) ? 'https://securitytrails.com/list/ip/' + enc(v) : 'https://securitytrails.com/domain/' + enc(v) + '/dns') },
    { key: 'E', name: 'IPVoid', home: 'https://www.ipvoid.com/', types: [] },
    { key: 'F', name: 'FOFA', home: 'https://en.fofa.info/', types: [...IP, 'domain'],
      build: (v, t) => 'https://en.fofa.info/result?qbase64=' + enc(b64((isIP(t) ? 'ip="' : 'domain="') + v + '"')) },
    { key: 'G', name: 'GreyNoise', home: 'https://viz.greynoise.io/', types: IP,
      build: (v) => 'https://viz.greynoise.io/ip/' + enc(v) },
    { key: 'H', name: 'Hybrid Analysis', home: 'https://www.hybrid-analysis.com/', types: [...HASH, ...IP, 'domain', 'url'],
      build: (v) => 'https://www.hybrid-analysis.com/search?query=' + enc(v) },
    { key: 'I', name: 'IPinfo', home: 'https://ipinfo.io/', types: IP,
      build: (v) => 'https://ipinfo.io/' + enc(v) },
    { key: 'J', name: 'Joe Sandbox', home: 'https://www.joesandbox.com/', types: [] },
    { key: 'K', name: 'Kaspersky OpenTIP', home: 'https://opentip.kaspersky.com/', types: [...IP, 'domain', ...HASH],
      build: (v) => 'https://opentip.kaspersky.com/' + enc(v) + '/' },
    { key: 'L', name: 'DNSlytics', home: 'https://dnslytics.com/', types: [...IP, 'domain'],
      build: (v, t) => 'https://dnslytics.com/' + (isIP(t) ? 'ip/' : 'domain/') + enc(v) },
    { key: 'M', name: 'Maltiverse', home: 'https://maltiverse.com/', types: [] },
    { key: 'N', name: 'Netlas', home: 'https://app.netlas.io/', types: [] },
    { key: 'O', name: 'ONYPHE', home: 'https://www.onyphe.io/', types: [] },
    { key: 'P', name: 'Pulsedive', home: 'https://pulsedive.com/', types: [] },
    { key: 'Q', name: 'Cisco Talos', home: 'https://talosintelligence.com/reputation_center', types: [...IP, 'domain'],
      build: (v) => 'https://talosintelligence.com/reputation_center/lookup?search=' + enc(v) },
    { key: 'R', name: 'AlienVault OTX', home: 'https://otx.alienvault.com/', types: [...IP, 'domain', 'url', ...HASH, 'cve'],
      build: (v, t) => {
        const kind = t === 'ipv4' ? 'ip' : t === 'ipv6' ? 'ipv6' : isHash(t) ? 'file' : t;
        return 'https://otx.alienvault.com/indicator/' + kind + '/' + enc(v);
      } },
    { key: 'S', name: 'Shodan', home: 'https://www.shodan.io/', types: [...IP, 'domain'],
      build: (v, t) => (isIP(t) ? 'https://www.shodan.io/host/' + enc(v) : 'https://www.shodan.io/domain/' + enc(v)) },
    { key: 'T', name: 'ThreatFox', home: 'https://threatfox.abuse.ch/', types: [...IP, 'domain', 'url', ...HASH],
      build: (v) => 'https://threatfox.abuse.ch/browse.php?search=' + enc('ioc:' + v) },
    { key: 'U', name: 'urlscan.io', home: 'https://urlscan.io/', types: [...IP, 'domain'],
      build: (v, t) => 'https://urlscan.io/' + (isIP(t) ? 'ip/' : 'domain/') + enc(v) },
    { key: 'V', name: 'VirusTotal', home: 'https://www.virustotal.com/', types: [...IP, 'domain', 'url', ...HASH],
      build: (v) => 'https://www.virustotal.com/gui/search/' + enc(v) },
    { key: 'W', name: 'DomainTools Whois', home: 'https://whois.domaintools.com/', types: [...IP, 'domain'],
      build: (v) => 'https://whois.domaintools.com/' + enc(v) },
    { key: 'X', name: 'IBM X-Force', home: 'https://exchange.xforce.ibmcloud.com/', types: [...IP, 'domain', 'url', ...HASH],
      build: (v, t) => {
        if (isIP(t)) return 'https://exchange.xforce.ibmcloud.com/ip/' + enc(v);
        if (isHash(t)) return 'https://exchange.xforce.ibmcloud.com/malware/' + enc(v);
        return 'https://exchange.xforce.ibmcloud.com/url/' + enc(v);
      } },
    { key: 'Y', name: 'YARAify', home: 'https://yaraify.abuse.ch/', types: [] },
    { key: 'Z', name: 'ZoomEye', home: 'https://www.zoomeye.ai/', types: [] }
  ];

  /**
   * Work out where a tool should go for an indicator.
   * Returns { url, pivot } - pivot is true when the URL is a direct lookup,
   * false when it is the home page (caller should copy the indicator).
   */
  function resolveToolUrl(tool, rawIndicator) {
    const value = ioc.refang(String(rawIndicator || '').trim());
    const type = value ? ioc.detectIndicatorType(value) : null;
    if (type && tool.build && tool.types.includes(type)) {
      return { url: tool.build(value, type), pivot: true, value, type };
    }
    return { url: tool.home, pivot: false, value, type };
  }

  return { osintTools, resolveToolUrl };
});
