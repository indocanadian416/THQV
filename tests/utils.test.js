'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const U = require('../js/utils.js');

test('escapeHtml escapes all HTML-significant characters', () => {
  assert.equal(U.escapeHtml('<img src=x onerror="a()">\'&'), '&lt;img src=x onerror=&quot;a()&quot;&gt;&#39;&amp;');
  assert.equal(U.escapeHtml(null), '');
});

test('safeHttpUrl only allows http(s)', () => {
  assert.equal(U.safeHttpUrl('https://example.com/a?b=1'), 'https://example.com/a?b=1');
  assert.equal(U.safeHttpUrl('http://example.com'), 'http://example.com/');
  assert.equal(U.safeHttpUrl('javascript:alert(1)'), null);
  assert.equal(U.safeHttpUrl(' JaVaScRiPt:alert(1)'), null);
  assert.equal(U.safeHttpUrl('data:text/html,<script>alert(1)</script>'), null);
  assert.equal(U.safeHttpUrl('/relative'), null);
  assert.equal(U.safeHttpUrl(''), null);
  assert.equal(U.safeHttpUrl(undefined), null);
});

test('htmlToText strips markup, scripts and decodes entities', () => {
  assert.equal(U.htmlToText('<p>Hello <b>world</b></p><script>evil()</script>'), 'Hello world');
  assert.equal(U.htmlToText('AT&amp;T &lt;b&gt; &#8217; &#x27;'), 'AT&T <b> ’ \'');
  assert.equal(U.htmlToText('<img src=x onerror=alert(1)>Title'), 'Title');
  assert.equal(U.htmlToText(null), '');
});

test('parseFeedDate treats rss2json timestamps as UTC', () => {
  assert.equal(U.parseFeedDate('2026-11-05 14:30:00').toISOString(), '2026-11-05T14:30:00.000Z');
  assert.equal(U.parseFeedDate('2026-11-05T14:30:00Z').toISOString(), '2026-11-05T14:30:00.000Z');
  assert.equal(U.parseFeedDate('Thu, 05 Nov 2026 14:30:00 GMT').toISOString(), '2026-11-05T14:30:00.000Z');
  assert.equal(U.parseFeedDate('not a date'), null);
  assert.equal(U.parseFeedDate(''), null);
});

test('timeAgo handles past, future and missing dates', () => {
  const now = new Date('2026-11-06T12:00:00Z');
  assert.equal(U.timeAgo(new Date('2026-11-06T11:55:00Z'), now), '5m ago');
  assert.equal(U.timeAgo(new Date('2026-11-06T09:00:00Z'), now), '3h ago');
  assert.equal(U.timeAgo(new Date('2026-11-04T12:00:00Z'), now), '2d ago');
  assert.equal(U.timeAgo(new Date('2026-11-06T13:00:00Z'), now), 'Just now');
  assert.equal(U.timeAgo(null, now), 'Unknown time');
});

test('storage never throws when localStorage is unavailable', () => {
  assert.equal(U.storage.get('x', 'fallback'), 'fallback');
  assert.equal(typeof U.storage.set('x', 1), 'boolean');
});
