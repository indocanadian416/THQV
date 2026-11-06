/*
 * THQV / CyberGator1 - shared helpers.
 *
 * Every module in js/ uses the same small wrapper: in the browser it adds its
 * exports to window.THQV, and under Node (tests) it uses module.exports. This
 * keeps the site build-free (plain <script> tags) while staying testable.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.THQV = Object.assign(root.THQV || {}, api);
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

  /** Escape a value for safe insertion into HTML text or attribute context. */
  function escapeHtml(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
  }

  /**
   * Return a normalised http(s) URL string, or null for anything else
   * (javascript:, data:, vbscript:, relative paths, garbage).
   */
  function safeHttpUrl(value) {
    if (typeof value !== 'string' || !value.trim()) return null;
    try {
      const url = new URL(value.trim());
      return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : null;
    } catch (e) {
      return null;
    }
  }

  const NAMED_ENTITIES = {
    amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', ndash: '–', mdash: '—',
    hellip: '…', lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”', copy: '©', reg: '®', trade: '™'
  };

  function decodeEntities(text) {
    return text.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (match, body) => {
      if (body[0] === '#') {
        const code = body[1] === 'x' || body[1] === 'X' ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
        try { return Number.isFinite(code) && code > 0 ? String.fromCodePoint(code) : match; } catch (e) { return match; }
      }
      const named = NAMED_ENTITIES[body.toLowerCase()];
      return named !== undefined ? named : match;
    });
  }

  /**
   * Convert an HTML fragment (e.g. an RSS description) to plain text.
   * The result is plain text and must still be rendered with textContent,
   * never innerHTML - decoding entities can re-create "<" characters.
   */
  function htmlToText(html) {
    if (html == null) return '';
    let text = String(html)
      .replace(/<(script|style|noscript|iframe)[\s\S]*?<\/\1\s*>/gi, ' ')
      .replace(/<!--[\s\S]*?-->/g, ' ')
      .replace(/<\/?(p|div|br|li|h[1-6])\b[^>]*>/gi, ' ')
      .replace(/<[^>]*>/g, '');
    text = decodeEntities(text);
    return text.replace(/\s+/g, ' ').trim();
  }

  /**
   * Parse a feed date. rss2json returns "YYYY-MM-DD HH:MM:SS" which is UTC
   * but carries no zone marker - browsers would otherwise read it as local time
   * (Chrome) or reject it (Safari). Returns a Date or null.
   */
  function parseFeedDate(value) {
    if (value instanceof Date) return isNaN(value) ? null : value;
    if (typeof value !== 'string' || !value.trim()) return null;
    const v = value.trim();
    const m = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?$/.exec(v);
    const d = m ? new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0))) : new Date(v);
    return isNaN(d) ? null : d;
  }

  /** Human "5m ago" style label. Handles missing and future dates. */
  function timeAgo(date, now) {
    if (!(date instanceof Date) || isNaN(date)) return 'Unknown time';
    const ref = now instanceof Date ? now : new Date();
    const seconds = Math.floor((ref - date) / 1000);
    if (seconds < 0) return 'Just now';
    if (seconds < 60) return seconds + 's ago';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
    if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
    if (seconds < 604800) return Math.floor(seconds / 86400) + 'd ago';
    return date.toLocaleDateString();
  }

  /**
   * localStorage wrapper. Storage can be missing or throw (private windows,
   * blocked site data, file:// in some browsers); the app must keep working.
   */
  const storage = {
    get(key, fallback) {
      try {
        const raw = globalThis.localStorage && globalThis.localStorage.getItem(key);
        return raw == null ? fallback : JSON.parse(raw);
      } catch (e) {
        return fallback;
      }
    },
    set(key, value) {
      try {
        if (globalThis.localStorage) globalThis.localStorage.setItem(key, JSON.stringify(value));
        return true;
      } catch (e) {
        return false;
      }
    }
  };

  return { escapeHtml, safeHttpUrl, htmlToText, decodeEntities, parseFeedDate, timeAgo, storage };
});
