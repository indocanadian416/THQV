/*
 * End-to-end tests: load the real index.html in headless Chromium with the
 * network mocked (rss2json returns hostile/odd data, the icon CDN is blocked)
 * and drive the UI like a user would.
 *
 * Run: npm run test:e2e   (needs: npx playwright install chromium)
 */
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const { chromium } = require('playwright');

const PAGE_URL = pathToFileURL(path.join(__dirname, '..', '..', 'index.html')).href;
const fmt = (d) => d.toISOString().replace('T', ' ').slice(0, 19); // rss2json style, UTC, no zone

let browser;
test.before(async () => { browser = await chromium.launch(); });
test.after(async () => { if (browser) await browser.close(); });

/** Fresh page with mocked network. failingFeed: substring of a feed URL that should 429. */
async function openPage(opts = {}) {
  const context = await browser.newContext({ acceptDownloads: true, viewport: opts.viewport || { width: 1280, height: 900 } });
  const page = await context.newPage();
  const problems = [];
  page.on('pageerror', (e) => problems.push('pageerror: ' + e.message));
  page.on('console', (m) => {
    if (/Content Security Policy/i.test(m.text())) problems.push('csp: ' + m.text());
  });
  await page.route('https://cdn.jsdelivr.net/**', (r) => r.abort());
  const now = Date.now();
  await page.route('**/api.rss2json.com/**', (route) => {
    const url = decodeURIComponent(route.request().url());
    if (opts.failingFeed && url.includes(opts.failingFeed)) return route.fulfill({ status: 429, body: 'rate limited' });
    if (opts.allFail) return route.fulfill({ status: 503, body: 'down' });
    const tag = url.slice(-25);
    route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({
        status: 'ok',
        items: [
          {
            title: '<img src=x onerror="window.__pwned=1">Akira ransomware exploits CVE-2025-1111 ' + tag,
            link: 'javascript:window.__pwned=2',
            pubDate: fmt(new Date(now - 2 * 3600e3)),
            description: '&lt;img src=x onerror=window.__pwned=3&gt; C2 at 185[.]220[.]101[.]4'
          },
          {
            title: '&lt;img src=x onerror=window.__pwned=6&gt;Phishing wave abuses DocuSign lures ' + tag,
            link: 'https://example.com/phish?p=' + encodeURIComponent(tag),
            pubDate: fmt(new Date(now - 30 * 3600e3)),
            description: '<p>Details <script>window.__pwned=4</script></p>'
          },
          { title: 'Undated story ' + tag, link: 'https://example.com/undated?p=' + encodeURIComponent(tag), pubDate: 'garbage', description: '' }
        ]
      })
    });
  });
  await page.goto(PAGE_URL + (opts.hash || ''));
  return { page, context, problems };
}

/** True if any element has a bare "null" text node (an optional child passed to replaceChildren). */
function strayNullText() {
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  for (let n = walker.nextNode(); n; n = walker.nextNode()) if (n.textContent.trim() === 'null') return true;
  return false;
}

async function waitForFeeds(page) {
  await page.waitForFunction(() => /^(Loaded|Could not|Showing)/.test(document.getElementById('feedStatus').textContent), null, { timeout: 30000 });
}

test('feeds render safely: no script execution, no javascript: links, UTC times', async () => {
  const { page, context, problems } = await openPage({ failingFeed: 'krebsonsecurity' });
  await waitForFeeds(page);
  assert.match(await page.textContent('#feedStatus'), /from 4\/5 sources.*Failed: Krebs on Security/);
  assert.equal(await page.evaluate(() => window.__pwned), undefined, 'feed content executed script');
  // The CSP would block inline handlers anyway; this checks the rendering itself never creates markup.
  await page.selectOption('#feedFilter', 'all');
  assert.equal(await page.locator('#tab-intel img, #tab-intel script').count(), 0, 'feed text was rendered as HTML');
  await page.selectOption('#feedFilter', '24h');
  assert.equal(await page.evaluate(() => [...document.querySelectorAll('a')].some((a) => /^\s*javascript:/i.test(a.getAttribute('href') || ''))), false);
  const first = page.locator('.feed-item').first();
  assert.equal(await first.locator('.title').evaluate((n) => n.tagName), 'SPAN', 'unsafe link should render as plain text');
  assert.match(await first.locator('.title').textContent(), /^Akira ransomware exploits CVE-2025-1111/);
  assert.equal(await first.locator('time').textContent(), '2h ago');
  // 24h filter: only the 2h-old story per feed; undated stories only appear under "All Time"
  assert.equal(await page.locator('.feed-item').count(), 4);
  await page.selectOption('#feedFilter', 'all');
  assert.equal(await page.locator('.feed-item').count(), 12);
  assert.ok((await page.locator('.threat-card').count()) >= 1, 'active threats derived from feeds');
  assert.ok((await page.locator('.metric-row').count()) >= 1, 'metrics derived from feeds');
  assert.equal(await page.evaluate(strayNullText), false, 'no stray "null" text in the intel tab');
  assert.deepEqual(problems, []);
  await context.close();
});

test('when every feed fails, the page explains why instead of showing nothing', async () => {
  const { page, context } = await openPage({ allFail: true });
  await waitForFeeds(page);
  assert.match(await page.textContent('#feedStatus'), /Could not load any feeds/);
  await page.click('#tabbtn-hypothesis');
  await page.click('#generateHypotheses');
  assert.match(await page.textContent('#hypothesisContainer'), /No articles are loaded/);
  await context.close();
});

test('tabs: icon clicks, ARIA state, arrow keys and #hash deep links', async () => {
  const { page, context } = await openPage({ hash: '#ioc' });
  assert.equal(await page.getAttribute('#tabbtn-ioc', 'aria-selected'), 'true');
  assert.equal(await page.isVisible('#tab-ioc'), true);
  await page.dispatchEvent('#tabbtn-osint i', 'click');
  assert.equal(await page.getAttribute('#tabbtn-osint', 'aria-selected'), 'true');
  assert.equal(await page.getAttribute('#tabbtn-ioc', 'aria-selected'), 'false');
  assert.equal(await page.isVisible('#tab-ioc'), false);
  assert.equal(await page.evaluate(() => location.hash), '#osint');
  await page.focus('#tabbtn-osint');
  await page.keyboard.press('ArrowRight');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'tabbtn-ioc');
  assert.equal(await page.getAttribute('#tabbtn-ioc', 'aria-selected'), 'true');
  await context.close();
});

test('OSINT: indicator pivots, typing does not trigger shortcuts, popups get no opener', async () => {
  const { page, context } = await openPage({ hash: '#osint' });
  await page.fill('#osintIndicator', '8[.]8[.]8[.]8');
  assert.equal(await page.textContent('#osintType'), 'IPv4');
  assert.equal(await page.getAttribute('.osint-key[data-key="V"]', 'href'), 'https://www.virustotal.com/gui/search/8.8.8.8');
  assert.equal(await page.getAttribute('.osint-key[data-key="V"]', 'rel'), 'noopener noreferrer');
  assert.equal(await page.textContent('.osint-key[data-key="C"] .mode'), 'home');

  await context.route(/^https:\/\/(?!cdn\.jsdelivr)/, (r) => r.fulfill({ contentType: 'text/html', body: '<title>stub</title>' }));
  const before = context.pages().length;
  await page.press('#osintIndicator', 's');
  await page.waitForTimeout(300);
  assert.equal(context.pages().length, before, 'shortcut fired while typing');

  await page.fill('#osintIndicator', '8.8.8.8');
  await page.locator('#tab-osint h2').click();
  const [popup] = await Promise.all([context.waitForEvent('page'), page.keyboard.press('s')]);
  await popup.waitForLoadState();
  assert.equal(popup.url(), 'https://www.shodan.io/host/8.8.8.8');
  assert.equal(await popup.evaluate(() => window.opener), null);
  await context.close();
});

test('IOC extractor: extraction, no HTML injection, CSV export', async () => {
  const { page, context } = await openPage({ hash: '#ioc' });
  await page.fill('#iocInput', 'C2 185[.]220[.]101[.]4 hxxps://evil[.]com/a,b <img src=x onerror=window.__pwned=5> evil[dot]org report.pdf e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 CVE-2024-3400');
  await page.click('#extractIocs');
  assert.equal(await page.textContent('.success-banner'), 'Extracted 6 IOCs');
  assert.equal(await page.locator('#iocResults img').count(), 0);
  assert.deepEqual(await page.$$eval('.ioc-type', (e) => e.map((x) => x.textContent)), ['IPv4', 'DOMAIN', 'DOMAIN', 'URL', 'SHA256', 'CVE']);
  assert.equal(await page.evaluate(() => window.__pwned), undefined);
  const [download] = await Promise.all([page.waitForEvent('download'), page.click('[data-export="csv"]')]);
  const csv = fs.readFileSync(await download.path(), 'utf8');
  assert.match(download.suggestedFilename(), /^iocs_\d{4}-\d{2}-\d{2}\.csv$/);
  assert.match(csv, /^type,value\r\n/);
  assert.match(csv, /URL,"https:\/\/evil\.com\/a,b"/);
  await page.check('#exportDefanged');
  const [d2] = await Promise.all([page.waitForEvent('download'), page.click('[data-export="json"]')]);
  assert.deepEqual(JSON.parse(fs.readFileSync(await d2.path(), 'utf8')).ipv4, ['185[.]220[.]101[.]4']);
  await context.close();
});

test('query library: stats are computed and selecting a query shows it', async () => {
  const { page, context } = await openPage({ hash: '#queries' });
  const stats = await page.$$eval('#queryStats .value', (e) => e.map((x) => Number(x.textContent)));
  const expected = require('../../js/queries.js').queryStats();
  assert.deepEqual(stats, [expected.platforms, expected.categories, expected.queries, expected.techniques]);
  await page.selectOption('#queryPlatform', 'sentinel');
  await page.selectOption('#queryCategory', 'Credential Access');
  await page.selectOption('#queryName', '0');
  assert.equal(await page.isVisible('#queryDetailsContainer'), true);
  assert.match(await page.textContent('#queryOutput'), /^\/\/ Hunt: MFA fatigue/);
  assert.match(await page.textContent('#queryRequires'), /SigninLogs/);
  await context.close();
});

test('hypotheses are built from loaded articles', async () => {
  const { page, context } = await openPage();
  await waitForFeeds(page);
  await page.selectOption('#feedFilter', 'all');
  await page.click('#tabbtn-hypothesis');
  await page.click('#generateHypotheses');
  const titles = await page.$$eval('.hypothesis-item h4', (e) => e.map((x) => x.textContent));
  assert.ok(titles.length >= 2);
  assert.match(titles[0], /CVE-2025-1111/);
  assert.equal(await page.locator('#hypothesisContainer img, #hypothesisContainer script').count(), 0);
  assert.equal(await page.evaluate(() => window.__pwned), undefined);
  await context.close();
});

test('theme toggle persists across reloads; second load uses the feed cache', async () => {
  const { page, context } = await openPage();
  await waitForFeeds(page);
  const start = await page.evaluate(() => document.documentElement.dataset.theme);
  await page.click('#themeToggle');
  const toggled = start === 'dark' ? 'light' : 'dark';
  assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), toggled);
  await page.reload();
  await waitForFeeds(page);
  assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), toggled);
  assert.match(await page.textContent('#feedStatus'), /^Showing \d+ cached articles/);
  await context.close();
});

test('phone width: no horizontal page scroll', async () => {
  const { page, context } = await openPage({ viewport: { width: 375, height: 800 } });
  await waitForFeeds(page);
  for (const tab of ['intel', 'hypothesis', 'osint', 'ioc', 'queries', 'schema']) {
    await page.click('#tabbtn-' + tab);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
    assert.equal(overflow, false, 'horizontal scroll on ' + tab);
  }
  await context.close();
});

test('query search finds queries by ATT&CK ID and opens them', async () => {
  const { page, context } = await openPage({ hash: '#queries' });
  await page.fill('#querySearch', 'T1003.001');
  const hits = page.locator('#querySearchResults .search-hit');
  assert.ok((await hits.count()) >= 3, 'expected several LSASS hunts across platforms');
  await page.fill('#querySearch', 'TicketEncryptionType');
  assert.equal(await hits.count(), 1);
  await hits.first().click();
  assert.equal(await page.isVisible('#queryDetailsContainer'), true);
  assert.equal(await page.textContent('#queryTitle'), 'Kerberoasting - RC4 Service Ticket Requests');
  assert.equal(await page.inputValue('#queryPlatform'), 'sentinel');
  await page.fill('#querySearch', 'zzzz-no-such-query');
  assert.match(await page.textContent('#querySearchResults'), /No queries match/);
  await context.close();
});

test('table reference: Defender and CrowdStrike tables, filter and related-query links', async () => {
  const { page, context } = await openPage({ hash: '#schema' });
  const { defenderTables, crowdstrikeEvents } = require('../../js/tables.js');
  assert.equal(await page.locator('.schema-item').count(), defenderTables.length);
  assert.match(await page.textContent('#schemaDetail h3'), /^DeviceProcessEvents/);
  assert.equal(await page.evaluate(strayNullText), false, 'optional sections must not render as "null"');
  assert.ok((await page.locator('#schemaDetail .field-table tbody tr').count()) >= 5);

  await page.fill('#schemaFilter', 'QRCode');
  assert.equal(await page.locator('.schema-item').count(), 1);
  assert.match(await page.textContent('#schemaDetail h3'), /^EmailUrlInfo/);
  await page.fill('#schemaFilter', '');

  await page.click('[data-schema-platform="crowdstrike"]');
  assert.equal(await page.getAttribute('[data-schema-platform="crowdstrike"]', 'aria-pressed'), 'true');
  assert.equal(await page.locator('.schema-item').count(), crowdstrikeEvents.length);
  assert.match(await page.textContent('#schemaDetail'), /How Falcon events join together/);
  assert.equal(await page.evaluate(strayNullText), false, 'optional sections must not render as "null"');
  await page.locator('.schema-item', { hasText: 'AsepValueUpdate' }).click();
  assert.ok((await page.locator('#schemaDetail .verify-badge').count()) >= 1, 'unconfirmed fields are flagged');

  await page.locator('.schema-item', { hasText: 'DnsRequest' }).click();
  const related = page.locator('#schemaDetail .related-list .search-hit');
  assert.ok((await related.count()) >= 1);
  await related.first().click();
  assert.equal(await page.getAttribute('#tabbtn-queries', 'aria-selected'), 'true');
  assert.equal(await page.inputValue('#queryPlatform'), 'crowdstrike');
  assert.match(await page.textContent('#queryOutput'), /#event_simpleName=DnsRequest/);
  await context.close();
});

test('table/event catalog is shown by default on the query page and links to search', async () => {
  const { page, context } = await openPage({ hash: '#queries' });
  const { defenderCatalog, crowdstrikeCatalog } = require('../../js/catalog.js');
  const count = (c) => c.reduce((n, g) => n + g.items.reduce((m, i) => m + i.names.length, 0), 0);
  assert.equal(await page.isVisible('#defenderCatalog'), true);
  assert.equal(await page.isVisible('#crowdstrikeCatalog'), true);
  assert.equal(await page.locator('#defenderCatalog .catalog-name').count(), count(defenderCatalog));
  assert.equal(await page.locator('#crowdstrikeCatalog .catalog-name').count(), count(crowdstrikeCatalog));
  await page.locator('#crowdstrikeCatalog .catalog-name', { hasText: /^DnsRequest$/ }).click();
  assert.equal(await page.inputValue('#querySearch'), 'DnsRequest');
  assert.ok((await page.locator('#querySearchResults .search-hit').count()) >= 1);
  assert.equal(await page.evaluate(strayNullText), false);
  await context.close();
});
