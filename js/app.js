/*
 * CyberGator1 - UI wiring. Depends on utils.js, ioc.js, queries.js, osint.js
 * and hypothesis.js (loaded before this file, all attached to window.THQV).
 *
 * Security rule for this file: untrusted data (feed content, user input) is
 * only ever placed in the DOM with textContent / setAttribute via el(), never
 * through innerHTML. Links are passed through safeHttpUrl().
 */
(function () {
  'use strict';

  const T = window.THQV;
  const $ = (id) => document.getElementById(id);

  // ---------------------------------------------------------------- helpers

  /** Create an element. props: className, text, attrs{}, on{}, dataset{}. */
  function el(tag, props, ...children) {
    const node = document.createElement(tag);
    const p = props || {};
    if (p.className) node.className = p.className;
    if (p.text != null) node.textContent = p.text;
    if (p.attrs) Object.entries(p.attrs).forEach(([k, v]) => { if (v != null && v !== false) node.setAttribute(k, v === true ? '' : v); });
    if (p.dataset) Object.assign(node.dataset, p.dataset);
    if (p.on) Object.entries(p.on).forEach(([evt, fn]) => node.addEventListener(evt, fn));
    children.flat().forEach((c) => { if (c != null && c !== false) node.append(c instanceof Node ? c : document.createTextNode(String(c))); });
    return node;
  }

  /** replaceChildren that skips null/false - optional sections would otherwise render as the text "null". */
  function setChildren(node, ...kids) {
    node.replaceChildren(...kids.flat().filter((k) => k != null && k !== false));
  }

  const icon = (cls) => el('i', { className: cls, attrs: { 'aria-hidden': 'true' } });

  /** External link that cannot reach back into this page. Falls back to plain text for unsafe URLs. */
  function extLink(href, text, className) {
    const url = T.safeHttpUrl(href);
    if (!url) return el('span', { className, text });
    return el('a', { className, text, attrs: { href: url, target: '_blank', rel: 'noopener noreferrer' } });
  }

  function mitreUrl(id) {
    const [tech, sub] = id.split('.');
    return 'https://attack.mitre.org/techniques/' + tech + '/' + (sub ? sub + '/' : '');
  }

  function mitreTag(id, name) {
    return extLink(mitreUrl(id), name ? id + ' ' + name : id, 'tag high');
  }

  let toastTimer = null;
  function toast(message) {
    const t = $('toast');
    t.textContent = message;
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 3500);
  }

  async function copyText(text) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (e) { /* fall through to legacy path */ }
    const ta = el('textarea', { attrs: { readonly: true, 'aria-hidden': 'true' } });
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.append(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    ta.remove();
    return ok;
  }

  function copyButton(getText) {
    const btn = el('button', { className: 'copy-btn', attrs: { type: 'button' } }, icon('fas fa-copy'), ' Copy');
    btn.addEventListener('click', async () => {
      const ok = await copyText(getText());
      btn.replaceChildren(icon(ok ? 'fas fa-check' : 'fas fa-times'), ok ? ' Copied!' : ' Copy failed');
      setTimeout(() => btn.replaceChildren(icon('fas fa-copy'), ' Copy'), 2000);
    });
    return btn;
  }

  // ---------------------------------------------------------------- theme

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    const dark = theme === 'dark';
    $('themeIcon').className = dark ? 'fas fa-sun' : 'fas fa-moon';
    $('themeText').textContent = dark ? 'Light' : 'Dark';
    $('themeToggle').setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
  }

  function initTheme() {
    applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light');
    $('themeToggle').addEventListener('click', () => {
      const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      applyTheme(next);
      T.storage.set('thqv.theme', next);
    });
  }

  // ---------------------------------------------------------------- tabs

  let currentTab = 'intel';
  const tabButtons = () => Array.from(document.querySelectorAll('[role="tab"]'));

  function switchTab(tab, opts) {
    const buttons = tabButtons();
    if (!buttons.some((b) => b.dataset.tab === tab)) tab = 'intel';
    buttons.forEach((b) => {
      const active = b.dataset.tab === tab;
      b.setAttribute('aria-selected', String(active));
      b.tabIndex = active ? 0 : -1;
      $('tab-' + b.dataset.tab).hidden = !active;
      if (active && opts && opts.focus) b.focus();
    });
    currentTab = tab;
    if (!(opts && opts.fromHash)) {
      try { history.replaceState(null, '', '#' + tab); } catch (e) { /* file:// in some browsers */ }
    }
  }

  function initTabs() {
    const buttons = tabButtons();
    buttons.forEach((b) => b.addEventListener('click', (e) => switchTab(e.currentTarget.dataset.tab)));
    $('tabList').addEventListener('keydown', (e) => {
      const idx = buttons.indexOf(document.activeElement);
      if (idx < 0) return;
      let next = null;
      if (e.key === 'ArrowRight') next = (idx + 1) % buttons.length;
      else if (e.key === 'ArrowLeft') next = (idx - 1 + buttons.length) % buttons.length;
      else if (e.key === 'Home') next = 0;
      else if (e.key === 'End') next = buttons.length - 1;
      if (next !== null) {
        e.preventDefault();
        switchTab(buttons[next].dataset.tab, { focus: true });
      }
    });
    window.addEventListener('hashchange', () => switchTab(location.hash.slice(1), { fromHash: true }));
    switchTab(location.hash.slice(1) || 'intel', { fromHash: true });
  }

  // ---------------------------------------------------------------- feeds

  const FEEDS = [
    { name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/' },
    { name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews' },
    { name: 'Krebs on Security', url: 'https://krebsonsecurity.com/feed/' },
    { name: 'SecurityWeek', url: 'https://www.securityweek.com/feed/' },
    { name: 'Dark Reading', url: 'https://www.darkreading.com/rss.xml' }
  ];
  const RSS_PROXY = 'https://api.rss2json.com/v1/api.json?rss_url=';
  const CACHE_KEY = 'thqv.feedCache';
  const CACHE_FRESH_MS = 15 * 60 * 1000;
  const DAY = 86400000;

  const TAG_RULES = [
    { name: 'Ransomware', type: 'critical', re: /ransom|lockbit|blackcat|alphv|qilin|clop|akira|play ransomware|black ?basta/ },
    { name: 'Zero-Day', type: 'critical', re: /zero[- ]?day|0-day/ },
    { name: 'Vulnerability', type: 'high', re: /\bcve-\d{4}-\d{4,}|vulnerabilit|\brce\b|remote code execution/ },
    { name: 'APT', type: 'high', re: /\bapt[\s-]?\d+\b|\bapt\b|state[- ]sponsored|nation[- ]state|espionage/ },
    { name: 'Phishing', type: 'high', re: /phish|smish|vishing|credential harvest/ },
    { name: 'Malware', type: 'high', re: /malware|stealer|trojan|botnet|backdoor|loader\b/ },
    { name: 'Data Breach', type: '', re: /breach|leak(ed)?\b|exposed data|stolen data/ },
    { name: 'Supply Chain', type: '', re: /supply[- ]chain|\bnpm\b|pypi|malicious package/ }
  ];

  function autoTag(text) {
    const lower = text.toLowerCase();
    return TAG_RULES.filter((r) => r.re.test(lower)).map((r) => ({ name: r.name, type: r.type }));
  }

  function normaliseItem(item, feed) {
    const title = T.htmlToText(item.title) || 'Untitled';
    let description = T.htmlToText(item.description || item.content || '');
    if (description.length > 450) description = description.slice(0, 447).replace(/\s+\S*$/, '') + '…';
    return {
      title,
      link: T.safeHttpUrl(item.link),
      date: T.parseFeedDate(item.pubDate),
      description,
      source: feed.name,
      tags: autoTag(title + ' ' + description)
    };
  }

  async function fetchJsonWithTimeout(url, ms) {
    const ctrl = typeof AbortController === 'function' ? new AbortController() : null;
    const timer = ctrl ? setTimeout(() => ctrl.abort(), ms) : null;
    try {
      const resp = await fetch(url, ctrl ? { signal: ctrl.signal } : undefined);
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      return await resp.json();
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async function fetchFeed(feed) {
    let lastError = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const data = await fetchJsonWithTimeout(RSS_PROXY + encodeURIComponent(feed.url), 12000);
        if (!data || data.status !== 'ok' || !Array.isArray(data.items)) throw new Error((data && data.message) || 'bad response');
        return data.items.slice(0, 15).map((item) => normaliseItem(item, feed));
      } catch (e) {
        lastError = e;
        if (attempt === 0) await new Promise((r) => setTimeout(r, 1500));
      }
    }
    throw lastError;
  }

  function dedupe(articles) {
    const seen = new Set();
    return articles.filter((a) => {
      // Ignore fragments and tracking parameters, keep real ones like WordPress ?p=123.
      const key = (a.link || a.title).toLowerCase().replace(/#.*$/, '').replace(/([?&])utm_[^&]*/g, '$1').replace(/[?&]+$/, '');
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  const byDateDesc = (a, b) => (b.date ? b.date.getTime() : -Infinity) - (a.date ? a.date.getTime() : -Infinity);

  function saveCache(articles) {
    T.storage.set(CACHE_KEY, { savedAt: Date.now(), articles: articles.map((a) => Object.assign({}, a, { date: a.date ? a.date.toISOString() : null })) });
  }

  function loadCache() {
    const c = T.storage.get(CACHE_KEY, null);
    if (!c || !Array.isArray(c.articles)) return null;
    // Re-validate cached data: storage is under the user's control, treat it as untrusted.
    const articles = c.articles.filter((a) => a && typeof a.title === 'string').map((a) => ({
      title: String(a.title),
      link: T.safeHttpUrl(a.link),
      date: T.parseFeedDate(a.date),
      description: String(a.description || ''),
      source: String(a.source || ''),
      tags: autoTag(String(a.title) + ' ' + String(a.description || ''))
    }));
    return { savedAt: Number(c.savedAt) || 0, articles };
  }

  let allArticles = [];
  let visibleArticles = [];
  let feedLoading = false;

  function setFeedStatus(text, warn) {
    const s = $('feedStatus');
    s.textContent = text;
    s.classList.toggle('warn', !!warn);
  }

  async function loadFeeds(force) {
    if (feedLoading) return;
    const cached = loadCache();
    if (!force && cached && Date.now() - cached.savedAt < CACHE_FRESH_MS && cached.articles.length) {
      allArticles = cached.articles.sort(byDateDesc);
      setFeedStatus(`Showing ${allArticles.length} cached articles from ${new Date(cached.savedAt).toLocaleTimeString()} (refreshes every 15 min - press Refresh to update now).`);
      onArticlesChanged();
      return;
    }

    feedLoading = true;
    $('feedRefresh').disabled = true;
    $('feedArea').replaceChildren(el('div', { className: 'loading' }, icon('fas fa-spinner'), el('p', { text: 'Loading feeds...' })));
    setFeedStatus('Fetching ' + FEEDS.length + ' sources...');

    const results = await Promise.allSettled(FEEDS.map(fetchFeed));
    const failed = [];
    let fresh = [];
    results.forEach((r, i) => {
      if (r.status === 'fulfilled') fresh = fresh.concat(r.value);
      else { failed.push(FEEDS[i].name); console.warn('[feeds] ' + FEEDS[i].name + ' failed:', r.reason); }
    });

    if (fresh.length) {
      allArticles = dedupe(fresh).sort(byDateDesc);
      saveCache(allArticles);
      const ok = FEEDS.length - failed.length;
      setFeedStatus(
        `Loaded ${allArticles.length} articles from ${ok}/${FEEDS.length} sources at ${new Date().toLocaleTimeString()}.` +
          (failed.length ? ' Failed: ' + failed.join(', ') + '.' : ''),
        failed.length > 0
      );
    } else if (cached && cached.articles.length) {
      allArticles = cached.articles.sort(byDateDesc);
      setFeedStatus(`Could not reach the feed service (rss2json.com may be rate-limiting or down). Showing ${allArticles.length} cached articles from ${new Date(cached.savedAt).toLocaleString()}.`, true);
    } else {
      allArticles = [];
      setFeedStatus('Could not load any feeds. The free rss2json.com service may be rate-limiting or down, or your network/ad-blocker is blocking it. Try Refresh in a minute.', true);
    }

    feedLoading = false;
    $('feedRefresh').disabled = false;
    onArticlesChanged();
  }

  function onArticlesChanged() {
    applyFeedFilters();
    renderActiveThreats();
    renderMetrics();
  }

  function applyFeedFilters() {
    const range = $('feedFilter').value;
    const term = $('feedSearch').value.trim().toLowerCase();
    const now = Date.now();
    const today = new Date().toDateString();
    visibleArticles = allArticles.filter((a) => {
      if (range !== 'all') {
        if (!a.date) return false;
        const age = now - a.date.getTime();
        if (range === 'today' && a.date.toDateString() !== today) return false;
        if (range === '24h' && age > DAY) return false;
        if (range === '7d' && age > 7 * DAY) return false;
      }
      return !term || (a.title + ' ' + a.description + ' ' + a.source).toLowerCase().includes(term);
    });
    renderFeeds(visibleArticles.slice(0, 60), range);
  }

  function renderFeeds(articles, range) {
    const area = $('feedArea');
    if (!articles.length) {
      const children = [el('p', { text: allArticles.length ? 'No articles match the current filters.' : 'No articles loaded.' })];
      if (allArticles.length && range !== 'all') {
        children.push(el('button', {
          className: 'stack-top', attrs: { type: 'button' },
          on: { click: () => { $('feedFilter').value = range === '7d' ? 'all' : '7d'; applyFeedFilters(); } }
        }, range === '7d' ? 'Show all time' : 'Show last 7 days'));
      }
      area.replaceChildren(el('div', { className: 'empty-state' }, children));
      return;
    }
    area.replaceChildren(...articles.map((a) => el('article', { className: 'feed-item' },
      a.link ? extLink(a.link, a.title, 'title') : el('span', { className: 'title', text: a.title }),
      a.description ? el('div', { className: 'description', text: a.description }) : null,
      el('div', { className: 'meta' },
        el('span', null, icon('fas fa-clock'), ' ', el('time', { text: T.timeAgo(a.date), attrs: { datetime: a.date ? a.date.toISOString() : null, title: a.date ? a.date.toLocaleString() : null } })),
        el('span', null, icon('fas fa-globe'), ' ', a.source)
      ),
      a.tags.length ? el('div', { className: 'tags' }, a.tags.map((t) => el('span', { className: 'tag ' + t.type, text: t.name }))) : null
    )));
  }

  function lastWeek() {
    const cutoff = Date.now() - 7 * DAY;
    return allArticles.filter((a) => a.date && a.date.getTime() >= cutoff);
  }

  function renderActiveThreats() {
    const box = $('activeThreatCards');
    const weighted = lastWeek()
      .map((a) => ({ a, score: a.tags.reduce((s, t) => s + (t.type === 'critical' ? 3 : t.type === 'high' ? 1 : 0), 0) }))
      .filter((x) => x.score >= 3)
      .slice(0, 8);
    if (!weighted.length) {
      box.replaceChildren(el('p', { className: 'empty-state', text: allArticles.length ? 'No ransomware or zero-day stories in the last 7 days of feeds.' : 'No feed data yet.' }));
      return;
    }
    box.replaceChildren(...weighted.map(({ a }) => {
      const critical = a.tags.some((t) => t.type === 'critical');
      const cves = T.extractIOCs(a.title + ' ' + a.description).cves;
      return el('div', { className: 'threat-card ' + (critical ? 'critical' : 'high') },
        el('h4', null, a.link ? extLink(a.link, a.title) : a.title),
        el('div', { className: 'description', text: a.source + ' · ' + T.timeAgo(a.date) + (cves.length ? ' · ' + cves.join(', ') : '') }),
        el('div', { className: 'tags' }, a.tags.map((t) => el('span', { className: 'tag ' + t.type, text: t.name })))
      );
    }));
  }

  function renderMetrics() {
    const box = $('threatMetrics');
    const week = lastWeek();
    if (!week.length) {
      box.replaceChildren(el('p', { className: 'empty-state', text: 'No dated articles from the last 7 days.' }));
      return;
    }
    const counts = TAG_RULES.map((r) => ({ name: r.name, n: week.filter((a) => a.tags.some((t) => t.name === r.name)).length }))
      .filter((c) => c.n > 0)
      .sort((x, y) => y.n - x.n);
    const max = Math.max(1, ...counts.map((c) => c.n));
    const cves = new Set();
    week.forEach((a) => T.extractIOCs(a.title + ' ' + a.description).cves.forEach((c) => cves.add(c)));

    const bar = (name, n) => {
      const fill = el('div', { className: 'metric-fill' });
      fill.style.width = Math.round((n / max) * 100) + '%';
      return el('div', { className: 'metric-row' },
        el('span', { className: 'metric-label', text: name }),
        el('div', { className: 'metric-bar', attrs: { role: 'img', 'aria-label': name + ': ' + n + ' articles' } }, fill),
        el('span', { className: 'metric-value', text: String(n) }));
    };

    setChildren(box,
      el('div', { className: 'stats-grid' },
        el('div', { className: 'stat-card' }, el('div', { className: 'value', text: String(week.length) }), el('div', { className: 'label', text: 'Articles' })),
        el('div', { className: 'stat-card' }, el('div', { className: 'value', text: String(cves.size) }), el('div', { className: 'label', text: 'CVEs mentioned' })),
        el('div', { className: 'stat-card' }, el('div', { className: 'value', text: String(new Set(week.map((a) => a.source)).size) }), el('div', { className: 'label', text: 'Sources' }))
      ),
      ...counts.map((c) => bar(c.name, c.n)),
      cves.size ? el('p', { className: 'small muted stack-top', text: 'CVEs: ' + Array.from(cves).slice(0, 12).join(', ') + (cves.size > 12 ? '…' : '') }) : null
    );
  }

  function initFeeds() {
    $('feedFilter').addEventListener('change', applyFeedFilters);
    $('feedSearch').addEventListener('input', applyFeedFilters);
    $('feedRefresh').addEventListener('click', () => loadFeeds(true));
    loadFeeds(false);
  }

  // ---------------------------------------------------------------- hypotheses

  function renderHypotheses() {
    const box = $('hypothesisContainer');
    const source = visibleArticles.length ? visibleArticles : allArticles;
    if (!source.length) {
      box.replaceChildren(el('div', { className: 'alert warning' }, icon('fas fa-exclamation-triangle'),
        el('div', null,
          el('p', { text: feedLoading ? 'Feeds are still loading - try again in a few seconds.' : 'No articles are loaded, so there is nothing to build hypotheses from.' }),
          feedLoading ? null : el('button', { className: 'stack-top', attrs: { type: 'button' }, on: { click: () => { switchTab('intel'); loadFeeds(true); } } }, 'Retry loading feeds')
        )));
      return;
    }
    const items = T.buildHypotheses(source, 10);
    box.replaceChildren(...items.map((h, i) => el('div', { className: 'hypothesis-item' },
      el('h4', { text: (i + 1) + '. ' + h.title }),
      el('p', null, el('strong', { text: 'Hypothesis: ' }), h.hypothesis),
      el('p', { className: 'small' }, el('strong', { text: 'Based on: ' }), h.article.link ? extLink(h.article.link, h.article.title) : h.article.title, ' (' + h.article.source + ', ' + T.timeAgo(h.article.date) + ')'),
      el('div', { className: 'tags' }, h.ttps.map((t) => mitreTag(t.id, t.name))),
      el('div', { className: 'code-block' }, copyButton(() => h.query), el('pre', { text: h.query, attrs: { tabindex: '0' } })),
      el('p', { className: 'small' }, el('strong', { text: 'Next: ' }), h.next)
    )));
  }

  // ---------------------------------------------------------------- OSINT

  const TYPE_LABELS = { ipv4: 'IPv4', ipv6: 'IPv6', domain: 'Domain', url: 'URL', email: 'Email', md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256', sha512: 'SHA-512', cve: 'CVE' };

  function updateOsintTiles() {
    const raw = $('osintIndicator').value;
    const type = raw.trim() ? T.detectIndicatorType(raw) : null;
    $('osintType').textContent = raw.trim() ? (type ? TYPE_LABELS[type] : 'Unrecognised') : 'No indicator';
    document.querySelectorAll('.osint-key').forEach((tile) => {
      const tool = T.osintTools.find((t) => t.key === tile.dataset.key);
      const r = T.resolveToolUrl(tool, raw);
      tile.href = r.url;
      tile.classList.toggle('pivot', r.pivot);
      tile.classList.toggle('dim', !!type && !r.pivot);
      tile.querySelector('.mode').textContent = r.pivot ? 'lookup' : 'home';
      tile.setAttribute('aria-label', tool.name + (r.pivot ? ' - look up ' + r.value : ' - open home page') + ' (shortcut ' + tool.key + ')');
    });
  }

  function afterOpen(tool, r) {
    if (!r.pivot && r.value) {
      copyText(r.value).then((ok) => toast(ok ? `${tool.name} has no direct lookup for this - indicator copied, paste it there.` : `Opened ${tool.name}.`));
    }
  }

  function openTool(tool) {
    const r = T.resolveToolUrl(tool, $('osintIndicator').value);
    window.open(r.url, '_blank', 'noopener,noreferrer');
    afterOpen(tool, r);
  }

  function initOsint() {
    $('osintKeyboard').replaceChildren(...T.osintTools.map((tool) => el('a', {
      className: 'osint-key',
      dataset: { key: tool.key },
      attrs: { href: tool.home, target: '_blank', rel: 'noopener noreferrer' },
      on: { click: () => afterOpen(tool, T.resolveToolUrl(tool, $('osintIndicator').value)) }
    }, el('span', { className: 'letter', text: tool.key }), el('span', { className: 'tool-name', text: tool.name }), el('span', { className: 'mode', text: 'home' }))));
    $('osintIndicator').addEventListener('input', updateOsintTiles);
    updateOsintTiles();

    document.addEventListener('keydown', (e) => {
      if (currentTab !== 'osint' || e.ctrlKey || e.altKey || e.metaKey || e.repeat) return;
      const t = e.target;
      if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
      if (!/^[a-z]$/i.test(e.key)) return;
      const tool = T.osintTools.find((x) => x.key === e.key.toUpperCase());
      if (tool) { e.preventDefault(); openTool(tool); }
    });
  }

  // ---------------------------------------------------------------- IOC

  let extracted = T.emptyResult();

  function runExtraction() {
    const text = $('iocInput').value;
    const box = $('iocResults');
    if (!text.trim()) {
      box.replaceChildren(el('p', { className: 'empty-state', text: 'Paste some text first.' }));
      return;
    }
    extracted = T.extractIOCs(text);
    const total = T.countIOCs(extracted);
    if (!total) {
      box.replaceChildren(el('p', { className: 'empty-state', text: 'No IOCs found.' }));
      return;
    }
    const parts = [el('div', { className: 'success-banner', text: `Extracted ${total} IOC${total === 1 ? '' : 's'}` })];
    T.IOC_TYPES.forEach((t) => {
      const list = extracted[t.key];
      if (!list.length) return;
      parts.push(el('div', { className: 'ioc-group-title', text: `${t.label} (${list.length})` }));
      list.forEach((v) => parts.push(el('div', { className: 'ioc-item' }, el('code', { text: v }), el('span', { className: 'ioc-type', text: t.badge }))));
    });
    box.replaceChildren(...parts);
  }

  function exportIOCs(format) {
    if (!T.countIOCs(extracted)) { toast('No IOCs to export - run Extract first.'); return; }
    const opts = { defang: $('exportDefanged').checked };
    const content = format === 'json' ? T.toJSON(extracted, opts) : format === 'csv' ? T.toCSV(extracted, opts) : T.toTXT(extracted, opts);
    const type = format === 'json' ? 'application/json' : format === 'csv' ? 'text/csv' : 'text/plain';
    const blob = new Blob([content], { type: type + ';charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = el('a', { attrs: { href: url, download: `iocs_${new Date().toISOString().slice(0, 10)}.${format}` } });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function initIoc() {
    $('extractIocs').addEventListener('click', runExtraction);
    $('iocInput').addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) runExtraction(); });
    document.querySelectorAll('[data-export]').forEach((b) => b.addEventListener('click', () => exportIOCs(b.dataset.export)));
  }

  // ---------------------------------------------------------------- queries

  function option(value, text) { return el('option', { text, attrs: { value } }); }

  function resetQueryView() {
    $('queryDetailsContainer').hidden = true;
    $('queryPlaceholder').hidden = false;
  }

  function initQueries() {
    const stats = T.queryStats();
    const tile = (value, label) => el('div', { className: 'stat-card' }, el('div', { className: 'value', text: String(value) }), el('div', { className: 'label', text: label }));
    $('queryStats').replaceChildren(tile(stats.platforms, 'Platforms'), tile(stats.categories, 'Hunt Categories'), tile(stats.queries, 'Hunt Queries'), tile(stats.techniques, 'ATT&CK Techniques'));

    const platform = $('queryPlatform');
    const category = $('queryCategory');
    const name = $('queryName');
    Object.entries(T.PLATFORMS).forEach(([key, p]) => platform.append(option(key, p.label)));

    platform.addEventListener('change', () => {
      category.replaceChildren(option('', '-- Select Category --'));
      name.replaceChildren(option('', '-- Select Hunt Query --'));
      name.disabled = true;
      resetQueryView();
      const cats = T.huntingQueries[platform.value];
      category.disabled = !cats;
      if (cats) Object.keys(cats).forEach((c) => category.append(option(c, `${c} (${cats[c].length})`)));
    });

    category.addEventListener('change', () => {
      name.replaceChildren(option('', '-- Select Hunt Query --'));
      resetQueryView();
      const list = (T.huntingQueries[platform.value] || {})[category.value];
      name.disabled = !list;
      if (list) list.forEach((q, i) => name.append(option(String(i), q.name)));
    });

    name.addEventListener('change', () => {
      const list = (T.huntingQueries[platform.value] || {})[category.value];
      const q = list && list[Number(name.value)];
      if (!q || name.value === '') { resetQueryView(); return; }
      $('queryTitle').textContent = q.name;
      $('queryDescription').textContent = q.desc;
      $('queryRequires').textContent = q.requires;
      $('queryPlatformTag').textContent = T.PLATFORMS[platform.value].label;
      setChildren($('queryMitre'), q.mitre.length ? q.mitre.map((t) => mitreTag(t)) : el('span', { className: 'tag', text: 'Triage / correlation' }));
      $('queryOutput').textContent = q.query;
      $('queryDetailsContainer').hidden = false;
      $('queryPlaceholder').hidden = true;
    });

    document.querySelectorAll('[data-copy]').forEach((btn) => btn.addEventListener('click', async () => {
      const ok = await copyText($(btn.dataset.copy).textContent);
      btn.replaceChildren(icon(ok ? 'fas fa-check' : 'fas fa-times'), ok ? ' Copied!' : ' Copy failed');
      setTimeout(() => btn.replaceChildren(icon('fas fa-copy'), ' Copy'), 2000);
    }));
  }

  // ---------------------------------------------------------------- query search + deep links

  /** Flat list of every query with the text used for searching. */
  function queryIndex() {
    const out = [];
    Object.entries(T.huntingQueries).forEach(([platform, cats]) => {
      Object.entries(cats).forEach(([category, list]) => {
        list.forEach((q, index) => out.push({
          platform, category, index, q,
          text: [q.name, q.desc, q.requires, category, T.PLATFORMS[platform].label, q.mitre.join(' '), q.query].join(' ').toLowerCase()
        }));
      });
    });
    return out;
  }

  /** Select a query in the library UI (switches to the Detection Queries tab). */
  function openQuery(platform, category, index) {
    switchTab('queries');
    const fire = (el, value) => { el.value = value; el.dispatchEvent(new Event('change')); };
    fire($('queryPlatform'), platform);
    fire($('queryCategory'), category);
    fire($('queryName'), String(index));
    const details = $('queryDetailsContainer');
    if (details.scrollIntoView) details.scrollIntoView({ behavior: 'smooth', block: 'start' });
    $('queryOutput').focus({ preventScroll: true });
  }

  function hitButton(hit) {
    return el('button', {
      className: 'search-hit', attrs: { type: 'button' },
      on: { click: () => openQuery(hit.platform, hit.category, hit.index) }
    },
    el('span', { className: 'hit-title', text: hit.q.name }),
    el('span', { className: 'hit-meta', text: [T.PLATFORMS[hit.platform].label, hit.category, hit.q.mitre.join(', ') || 'Triage'].join(' · ') }));
  }

  function initQuerySearch() {
    const index = queryIndex();
    const input = $('querySearch');
    const box = $('querySearchResults');
    input.addEventListener('input', () => {
      const terms = input.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
      if (!terms.length) { box.replaceChildren(); return; }
      const hits = index.filter((x) => terms.every((t) => x.text.includes(t)));
      if (!hits.length) { box.replaceChildren(el('p', { className: 'muted small', text: 'No queries match.' })); return; }
      box.replaceChildren(
        el('p', { className: 'muted small', text: `${hits.length} match${hits.length === 1 ? '' : 'es'}${hits.length > 30 ? ' - showing 30' : ''}` }),
        ...hits.slice(0, 30).map(hitButton)
      );
    });
  }

  // ---------------------------------------------------------------- table / event catalog

  function renderCatalog(containerId, catalog) {
    const search = $('querySearch');
    const nameButton = (name) => el('button', {
      className: 'catalog-name', attrs: { type: 'button', title: 'Find queries that use ' + name },
      on: { click: () => {
        search.value = name;
        search.dispatchEvent(new Event('input'));
        search.scrollIntoView({ behavior: 'smooth', block: 'center' });
        search.focus({ preventScroll: true });
      } }
    }, name);
    $(containerId).replaceChildren(...catalog.flatMap((group) => [
      el('h4', { text: group.category }),
      el('div', { className: 'field-table-wrap' }, el('table', { className: 'field-table catalog-table' },
        el('tbody', null, group.items.map((item) => el('tr', null,
          el('td', null, el('div', { className: 'catalog-names' }, item.names.map(nameButton))),
          el('td', { text: item.desc })
        )))))
    ]));
  }

  function initCatalog() {
    renderCatalog('defenderCatalog', T.defenderCatalog);
    renderCatalog('crowdstrikeCatalog', T.crowdstrikeCatalog);
  }

  // ---------------------------------------------------------------- table reference

  let schemaPlatform = 'defender';
  let schemaSelected = { defender: null, crowdstrike: null };

  function schemaItems() {
    return schemaPlatform === 'defender' ? T.defenderTables : T.crowdstrikeEvents;
  }

  function relatedQueries(item) {
    const index = queryIndex();
    if (schemaPlatform === 'defender') {
      const re = new RegExp('\\b' + item.name + '\\b');
      return index.filter((x) => T.PLATFORMS[x.platform].language === 'kql' && re.test(x.q.query));
    }
    const names = item.name.split(' / ');
    return index.filter((x) => x.platform === 'crowdstrike' && names.some((n) => x.q.query.includes(n)));
  }

  function itemMatches(item, term) {
    if (!term) return true;
    const fields = (item.columns || item.fields).map((c) => c.name + ' ' + c.desc).join(' ');
    return (item.name + ' ' + item.summary + ' ' + item.huntFor.join(' ') + ' ' + fields).toLowerCase().includes(term);
  }

  function renderSchemaList() {
    const term = $('schemaFilter').value.trim().toLowerCase();
    const items = schemaItems().filter((i) => itemMatches(i, term));
    const list = $('schemaList');
    if (!items.length) {
      list.replaceChildren(el('p', { className: 'muted small', text: 'Nothing matches the filter.' }));
      $('schemaDetail').replaceChildren();
      return;
    }
    let selected = schemaSelected[schemaPlatform];
    if (!items.some((i) => i.name === selected)) selected = items[0].name;
    schemaSelected[schemaPlatform] = selected;
    list.replaceChildren(...items.map((item) => el('button', {
      className: 'schema-item',
      attrs: { type: 'button', 'aria-current': item.name === selected ? 'true' : 'false' },
      on: { click: () => { schemaSelected[schemaPlatform] = item.name; renderSchemaList(); } }
    }, el('span', { className: 'item-name', text: item.name }), el('span', { className: 'item-source', text: item.source }))));
    renderSchemaDetail(items.find((i) => i.name === selected));
  }

  function renderSchemaDetail(item) {
    const isDefender = schemaPlatform === 'defender';
    const rows = (item.columns || item.fields).map((c) => el('tr', null,
      el('td', null, c.name, c.verify ? el('span', { className: 'tag high verify-badge', text: 'verify', attrs: { title: 'Not confirmed in public sources - check the Falcon Event Data Dictionary' } }) : null),
      isDefender ? el('td', { className: 'type', text: c.type }) : null,
      el('td', { text: c.desc })
    ));
    const related = relatedQueries(item);
    setChildren($('schemaDetail'),
      !isDefender ? el('div', null, el('h4', { text: 'How Falcon events join together' }),
        el('ul', { className: 'join-notes' }, T.crowdstrikeJoinNotes.map((n) => el('li', { text: n })))) : null,
      el('h3', null, item.name, el('span', { className: 'tag accent', text: item.source }),
        item.docs ? extLink(item.docs, 'Microsoft docs', 'tag') : null),
      el('p', { text: item.summary }),
      el('h4', { text: 'Use it to hunt for' }),
      el('ul', null, item.huntFor.map((h) => el('li', { text: h }))),
      el('h4', { text: isDefender ? 'Key columns' : 'Key fields' }),
      el('div', { className: 'field-table-wrap' }, el('table', { className: 'field-table' },
        el('thead', null, el('tr', null, el('th', { text: isDefender ? 'Column' : 'Field' }), isDefender ? el('th', { text: 'Type' }) : null, el('th', { text: 'What it tells you' }))),
        el('tbody', null, rows))),
      item.actionTypes && item.actionTypes.length ? el('div', null, el('h4', { text: 'Common ActionType values' }),
        el('div', { className: 'tags' }, item.actionTypes.map((a) => el('code', { className: 'tag', text: a })))) : null,
      el('h4', { text: 'Sample record (illustrative)' }),
      el('div', { className: 'code-block' }, copyButton(() => JSON.stringify(item.sample, null, 2)), el('pre', { text: JSON.stringify(item.sample, null, 2), attrs: { tabindex: '0' } })),
      el('h4', { text: 'Starter query' }),
      el('div', { className: 'code-block' }, copyButton(() => item.starter), el('pre', { text: item.starter, attrs: { tabindex: '0' } })),
      el('h4', { text: `Library queries using ${isDefender ? 'this table' : 'this event'} (${related.length})` }),
      related.length
        ? el('div', { className: 'related-list' }, related.map(hitButton))
        : el('p', { className: 'muted small', text: 'None yet - the starter query above is a good place to begin.' })
    );
  }

  function initSchema() {
    document.querySelectorAll('[data-schema-platform]').forEach((btn) => btn.addEventListener('click', () => {
      schemaPlatform = btn.dataset.schemaPlatform;
      document.querySelectorAll('[data-schema-platform]').forEach((b) => b.setAttribute('aria-pressed', String(b === btn)));
      renderSchemaList();
    }));
    $('schemaFilter').addEventListener('input', renderSchemaList);
    renderSchemaList();
  }

  // ---------------------------------------------------------------- clock + boot

  function tickClock() {
    const now = new Date();
    const c = $('clock');
    c.textContent = now.toLocaleString(undefined, { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    c.setAttribute('datetime', now.toISOString());
  }

  function boot() {
    initTheme();
    initTabs();
    tickClock();
    setInterval(tickClock, 15000);
    initOsint();
    initIoc();
    initQueries();
    initQuerySearch();
    initCatalog();
    initSchema();
    $('generateHypotheses').addEventListener('click', renderHypotheses);
    initFeeds();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
