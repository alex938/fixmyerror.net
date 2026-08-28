#!/usr/bin/env node
/**
 * Behavioural tests for the search app and the generated static pages.
 *
 *   npm install   (pulls in jsdom)
 *   npm test
 *
 * scripts/validate.mjs covers data and link integrity with no dependencies.
 * This file covers the behaviour that only appears once the page is running:
 * search, filtering, pagination, deep links, tabs and theming.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { JSDOM, VirtualConsole } from 'jsdom';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

const results = [];
const pageErrors = [];
const check = (name, condition, detail = '') => results.push({ name, ok: !!condition, detail });

function virtualConsole(label) {
    const vc = new VirtualConsole();
    vc.on('jsdomError', e => pageErrors.push(`${label}: ${e.message}`));
    vc.on('error', (...args) => pageErrors.push(`${label}: console.error ${args.join(' ')}`));
    return vc;
}

/** Boot index.html with its deferred scripts loaded, as a browser would. */
function bootApp(url = 'https://fixmyerror.net/') {
    const dom = new JSDOM(read('index.html'), {
        runScripts: 'dangerously',
        url,
        virtualConsole: virtualConsole(url),
        pretendToBeVisual: true
    });
    for (const src of ['assets/fuse.min.js', 'embedded-data.js']) {
        const el = dom.window.document.createElement('script');
        el.textContent = read(src);
        dom.window.document.head.appendChild(el);
    }
    // jsdom has no layout engine.
    dom.window.Element.prototype.scrollIntoView = function () {};
    // jsdom already fired DOMContentLoaded while parsing, before the deferred
    // scripts above existed; boot once now that they do.
    dom.window.eval('window.__app = undefined; window.__app = new ErrorCheatsheet();');
    return dom.window;
}

function loadPage(rel, { withScript = null } = {}) {
    const dom = new JSDOM(read(rel), {
        runScripts: withScript ? 'dangerously' : 'outside-only',
        url: `https://fixmyerror.net/${rel}`,
        virtualConsole: virtualConsole(rel),
        pretendToBeVisual: true
    });
    if (withScript) {
        const el = dom.window.document.createElement('script');
        el.textContent = read(withScript);
        dom.window.document.body.appendChild(el);
    }
    return dom.window;
}

const click = (window, el) => el.dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
const key = (window, target, k) => target.dispatchEvent(new window.KeyboardEvent('keydown', { key: k, bubbles: true }));

const errors = JSON.parse(read('data/errors.json'));
const TOTAL = errors.length;
const CATEGORIES = new Set(errors.map(e => e.category)).size;
const K8S = errors.filter(e => e.category === 'Kubernetes').length;

/* ------------------------------------------------------------ boot state -- */
{
    const w = bootApp();
    const d = w.document;
    const $ = (s) => d.querySelector(s);
    const $$ = (s) => [...d.querySelectorAll(s)];

    check('dataset size reported', $('#totalErrors').textContent === String(TOTAL), $('#totalErrors').textContent);
    check('category count reported', $('#totalCategories').textContent === String(CATEGORIES), $('#totalCategories').textContent);
    check('loading spinner removed', $('#loadingState').style.display === 'none');
    check('only the first page is rendered', $$('.error-card').length === 60, String($$('.error-card').length));
    check('load-more offered', $('#loadMoreWrap').style.display !== 'none');
    check('load-more names the remainder', $('#loadMoreBtn').textContent.includes(String(TOTAL - 60)), $('#loadMoreBtn').textContent);
    check('visible count is the full match set', $('#visibleErrors').textContent === String(TOTAL), $('#visibleErrors').textContent);

    click(w, $('#loadMoreBtn'));
    check('load-more appends exactly one page', $$('.error-card').length === 120, String($$('.error-card').length));

    check('browse grid covers every category', $$('#browseGrid a').length === CATEGORIES, String($$('#browseGrid a').length));
    check('C# slugged as c-sharp', $$('#browseGrid a').some(a => a.getAttribute('href') === 'categories/c-sharp.html'));
    check('C++ slugged as c-plus-plus', $$('#browseGrid a').some(a => a.getAttribute('href') === 'categories/c-plus-plus.html'));
    check('CI/CD slugged as ci-cd', $$('#browseGrid a').some(a => a.getAttribute('href') === 'categories/ci-cd.html'));

    check('filter row starts collapsed', $('#categoryFilters').classList.contains('collapsed'));
    check('overflow filters are marked', $$('.category-filter.is-overflow').length === CATEGORIES - 12, String($$('.category-filter.is-overflow').length));
    click(w, $('.filter-toggle'));
    check('expanding reveals every filter', !$('#categoryFilters').classList.contains('collapsed'));
    check('toggle label flips', $('.filter-toggle').textContent === 'Show fewer', $('.filter-toggle').textContent);

    check('cards link to their permalink page', /^errors\/[a-z0-9-]+\.html$/.test($('.error-card .card-action[href]').getAttribute('href')), $('.error-card .card-action[href]').getAttribute('href'));
    check('cards offer a Markdown copy', $$('.markdown-btn').length === 120);
    check('New badge window matches the build', w.__app.errors.filter(e => w.__app.isRecent(e.dateAdded)).length > 0);
}

/* ------------------------------------------------- filtering and searching - */
{
    const w = bootApp();
    const d = w.document;
    const app = w.__app;

    const k8sBtn = [...d.querySelectorAll('.category-filter')].find(b => b.dataset.category === 'Kubernetes');
    click(w, k8sBtn);
    check('category filter narrows the set', d.getElementById('visibleErrors').textContent === String(K8S), d.getElementById('visibleErrors').textContent);
    check('category filter marks itself active', k8sBtn.classList.contains('active') && k8sBtn.getAttribute('aria-pressed') === 'true');
    check('load-more hidden when everything fits', d.getElementById('loadMoreWrap').style.display === 'none');

    click(w, [...d.querySelectorAll('.category-filter')].find(b => b.dataset.category === 'all'));
    d.getElementById('searchInput').value = 'certificate signed by unknown authority';
    app.performSearch();
    check('search ranks the exact entry first', d.querySelector('.error-card').id === 'ssl-certificate-unknown-authority', d.querySelector('.error-card').id);
    check('result count is announced', /Found \d+ results/.test(d.getElementById('resultsCount').textContent), d.getElementById('resultsCount').textContent);

    d.getElementById('searchInput').value = 'zzzznotarealthing';
    app.performSearch();
    check('empty state shown when nothing matches', d.getElementById('emptyState').style.display === 'block');

    app.clearSearch();
    check('clearing restores the full set', d.getElementById('visibleErrors').textContent === String(TOTAL), d.getElementById('visibleErrors').textContent);

    click(w, d.getElementById('recentBtn'));
    check('recently-added keeps every entry', new RegExp(`Showing all ${TOTAL} errors, newest first`).test(d.getElementById('resultsCount').textContent), d.getElementById('resultsCount').textContent);
    check('recently-added puts the newest first', w.__app.pendingResults[0].dateAdded >= (w.__app.pendingResults[1].dateAdded || ''));

    click(w, d.querySelector('.favorite-btn'));
    check('favouriting updates the counter', d.getElementById('favoritesCount').textContent === '1', d.getElementById('favoritesCount').textContent);
}

/* --------------------------------------------------------- Markdown export */
{
    const w = bootApp();
    const app = w.__app;
    const md = app.toMarkdown(app.errors.find(e => e.id === '502-bad-gateway'));
    check('Markdown starts with the title heading', md.startsWith('## 502 Bad Gateway'));
    check('Markdown fences the fix', md.includes('```bash'));
    check('Markdown cites the permalink', md.includes('https://fixmyerror.net/errors/502-bad-gateway.html'));

    const withWindows = app.errors.find(e => e.fix_snippet_windows);
    check('Markdown includes the Windows fix when present', app.toMarkdown(withWindows).includes('```powershell'));
    check('permalink is derived from the current origin', app.permalinkFor('x') === 'https://fixmyerror.net/errors/x.html', app.permalinkFor('x'));
}

/* ----------------------------------------------------------- URL parameters */
{
    const w = bootApp('https://fixmyerror.net/?search=timeout&category=Kubernetes');
    const d = w.document;
    check('search parameter is applied', d.getElementById('searchInput').value === 'timeout');
    check('category parameter is applied', w.__app.currentCategory === 'Kubernetes', w.__app.currentCategory);
    check('category button reflects the parameter', d.querySelector('.category-filter.active').dataset.category === 'Kubernetes');
    check('results honour both parameters', [...d.querySelectorAll('.error-card')].every(c => errors.find(e => e.id === c.id).category === 'Kubernetes'));
    check('clear button is shown for a query', d.getElementById('clearSearch').style.display === 'block');
}
{
    const w = bootApp('https://fixmyerror.net/?category=%3Cscript%3Ealert(1)%3C/script%3E');
    check('unknown category falls back to all', w.__app.currentCategory === 'all', w.__app.currentCategory);
    check('category parameter cannot inject markup', !w.document.body.innerHTML.includes('alert(1)'));
}

/* ---------------------------------------------------------------- deep link */
{
    const w = bootApp();
    const last = errors[errors.length - 1].id;
    w.__app.scrollToError(last);
    check('deep link renders past the first page', !!w.document.getElementById(last), last);
    check('deep-linked card is expanded', w.document.querySelector(`#${last} .error-body`).classList.contains('expanded'));
}

/* ------------------------------------------------------- keyboard shortcuts */
{
    const w = bootApp();
    const d = w.document;
    d.documentElement.setAttribute('data-theme', 'dark');

    key(w, d.body, 't');
    check('T toggles the theme', d.documentElement.getAttribute('data-theme') === 'light', d.documentElement.getAttribute('data-theme'));

    click(w, d.getElementById('keyboardShortcutsBtn'));
    const before = d.documentElement.getAttribute('data-theme');
    key(w, d.body, 't');
    check('single-key shortcuts are inert behind the dialog', d.documentElement.getAttribute('data-theme') === before);
    key(w, d.body, 'Escape');
    check('Escape closes the dialog', !d.getElementById('shortcutsModal').classList.contains('show'));

    key(w, d.body, 'r');
    check('R toggles the recently-added view', d.getElementById('recentBtn').getAttribute('aria-pressed') === 'true');
}

/* ------------------------------------------------- generated error page ---- */
{
    const withWindows = errors.find(e => e.fix_snippet_windows);
    const w = loadPage(`errors/${withWindows.id}.html`, { withScript: 'assets/page.js' });
    const d = w.document;

    check('error page has exactly one h1', d.querySelectorAll('h1').length === 1);
    check('error page h1 is the error itself', d.querySelector('h1').textContent.trim() === withWindows.title, d.querySelector('h1').textContent.trim());
    check('error page carries the category guide', d.body.textContent.includes(`How to diagnose ${withWindows.category} errors`));
    check('error page links its category hub', !!d.querySelector(`a[href="../categories/${withWindows.category.toLowerCase()}.html"]`));
    check('error page emits TechArticle JSON-LD', [...d.querySelectorAll('script[type="application/ld+json"]')].some(s => JSON.parse(s.textContent)['@type'] === 'TechArticle'));
    check('error page emits BreadcrumbList JSON-LD', [...d.querySelectorAll('script[type="application/ld+json"]')].some(s => JSON.parse(s.textContent)['@type'] === 'BreadcrumbList'));

    const tabs = [...d.querySelectorAll('[role="tab"]')];
    check('platform tabs are rendered', tabs.length === 2, String(tabs.length));
    check('the Windows panel starts hidden', d.getElementById('panel-win').hidden);
    click(w, tabs[1]);
    check('clicking a tab swaps the panels', !d.getElementById('panel-win').hidden && d.getElementById('panel-unix').hidden);
    check('aria-selected follows the active tab', tabs[1].getAttribute('aria-selected') === 'true' && tabs[0].getAttribute('aria-selected') === 'false');

    d.documentElement.setAttribute('data-theme', 'dark');
    click(w, d.getElementById('themeToggle'));
    check('static pages toggle theme too', d.documentElement.getAttribute('data-theme') === 'light', d.documentElement.getAttribute('data-theme'));
}

/* ------------------------------------------------------ generated hub pages */
{
    const w = loadPage('categories/kubernetes.html');
    const d = w.document;
    check('category page lists every entry it owns', d.querySelectorAll('.block .link-list li').length === K8S, String(d.querySelectorAll('.block .link-list li').length));
    check('category page emits an ItemList', [...d.querySelectorAll('script[type="application/ld+json"]')].some(s => JSON.parse(s.textContent).mainEntity?.['@type'] === 'ItemList'));
    check('category page links to the other hubs', d.querySelectorAll('.card-grid a').length === CATEGORIES - 1, String(d.querySelectorAll('.card-grid a').length));
}
{
    const d = loadPage('all-errors.html').document;
    check('A–Z index links every error', d.querySelectorAll('.index-list a').length === TOTAL, String(d.querySelectorAll('.index-list a').length));
}
{
    const html = read('404.html');
    check('404 is noindex', html.includes('content="noindex, follow"'));
    check('404 uses root-relative links so it works at any depth', !/(href|src)="(?!https?:|mailto:|data:|#|\/)/.test(html));
}

/* -------------------------------------------------------------------- report */

let failed = 0;
for (const r of results) {
    if (!r.ok) failed++;
    console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.name}${r.detail ? `  -> ${r.detail}` : ''}`);
}
if (pageErrors.length) {
    console.log('\nPage errors:');
    for (const e of pageErrors) console.log(`  ${e}`);
}
console.log(`\n${results.length - failed}/${results.length} passed${pageErrors.length ? `, ${pageErrors.length} page error(s)` : ''}`);
process.exit(failed || pageErrors.length ? 1 : 0);
