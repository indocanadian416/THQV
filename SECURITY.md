# Security Policy

CyberGator1 is a static, browser-only site: there is no backend, no login and no data is sent anywhere except the RSS requests to rss2json.com. Pasted IOCs and text never leave your browser.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Report them privately through
[GitHub Security Advisories](https://github.com/indocanadian416/THQV/security/advisories/new).

Include what you found, how to reproduce it, and the impact. You should get a reply within a week.

## What is in scope

- Script injection (XSS) through feed content, pasted text, cached data or URL fragments
- Ways to bypass the Content-Security-Policy or Subresource Integrity checks
- OSINT links or exports that leak data or let another site control this page
- Hunting queries that are dangerously wrong (for example, would never fire for the technique they claim to detect)

## Defences already in place

- All untrusted content is rendered with `textContent`; links are limited to `http(s)` (see `js/utils.js`)
- Strict CSP: scripts only from this site, no inline script, network only to rss2json.com
- Font Awesome loaded with SRI
- External links and OSINT tabs use `noopener noreferrer`
- Browser end-to-end tests feed hostile data to the page on every push (`tests/e2e/`)
