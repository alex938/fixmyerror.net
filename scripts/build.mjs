#!/usr/bin/env node
/**
 * Static site generator for fixmyerror.net.
 *
 * Source of truth:
 *   data/errors.json      - every documented error
 *   data/categories.json  - authored guide content, one entry per category
 *
 * Generated (all committed, because deployment is a plain S3 sync):
 *   embedded-data.js          - dataset for the single-page search app
 *   errors/<id>.html          - one indexable page per error
 *   categories/<slug>.html    - one hub page per category
 *   categories.html           - category directory
 *   all-errors.html           - full A-Z index
 *   about.html, 404.html
 *   sitemap.xml, feed.xml
 *
 * Every error previously lived only behind a URL fragment (#id), which search
 * engines collapse into the homepage. Real files per error are the whole point
 * of this generator.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { COUNT_RULES, countPattern } from './counts.mjs';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const ORIGIN = 'https://fixmyerror.net';
const SITE_NAME = 'FixMyError.net';
const OG_IMAGE = `${ORIGIN}/og-image.png`;
const CONTACT = 'alex@slash-root.com';

const BUILD_DATE = process.env.BUILD_DATE || new Date().toISOString().slice(0, 10);
/** Entries added within this many days get a "New" badge. */
const NEW_WINDOW_DAYS = 60;

const errors = readJson('data/errors.json');
const categoryGuides = readJson('data/categories.json');

/* ------------------------------------------------------------------ utils */

function readJson(rel) {
    return JSON.parse(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
}

function write(rel, content) {
    const full = path.join(ROOT, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
}

function esc(value) {
    return String(value == null ? '' : value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

/** JSON-LD payloads are escaped so a "</script>" in the data cannot break out. */
function jsonLd(obj) {
    return JSON.stringify(obj)
        .replace(/</g, '\\u003c')
        .replace(/>/g, '\\u003e')
        .replace(/&/g, '\\u0026');
}

function stripTags(html) {
    return String(html).replace(/<[^>]+>/g, '');
}

/** Truncate on a word boundary so meta descriptions do not end mid-word. */
function truncate(text, max) {
    const clean = stripTags(text).replace(/\s+/g, ' ').trim();
    if (clean.length <= max) return clean;
    const cut = clean.slice(0, max - 1);
    const lastSpace = cut.lastIndexOf(' ');
    return `${(lastSpace > max * 0.6 ? cut.slice(0, lastSpace) : cut).replace(/[,;:.\s]+$/, '')}…`;
}

function slugify(value) {
    return String(value)
        .replace(/\+\+/g, '-plus-plus')
        .replace(/#/g, '-sharp')
        .replace(/\//g, '-')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '');
}

function isSafeUrl(url) {
    try {
        const u = new URL(url);
        return u.protocol === 'https:' || u.protocol === 'http:';
    } catch {
        return false;
    }
}

function daysSince(dateStr) {
    if (!dateStr) return Infinity;
    const d = Date.parse(`${dateStr}T00:00:00Z`);
    if (Number.isNaN(d)) return Infinity;
    return (Date.parse(`${BUILD_DATE}T00:00:00Z`) - d) / 86400000;
}

function isNew(err) {
    const age = daysSince(err.dateAdded);
    return age >= 0 && age <= NEW_WINDOW_DAYS;
}

function humanDate(dateStr) {
    const d = new Date(`${dateStr}T00:00:00Z`);
    return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' });
}

function rfc822(dateStr) {
    return new Date(`${dateStr}T00:00:00Z`).toUTCString();
}

function xmlEsc(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;');
}

/* --------------------------------------------------------------- indexing */

const categories = [...new Set(errors.map(e => e.category))].sort((a, b) => a.localeCompare(b));

const catMeta = new Map();
for (const name of categories) {
    const guide = categoryGuides[name];
    if (!guide) throw new Error(`No guide authored for category "${name}" in data/categories.json`);
    const slug = slugify(name);
    catMeta.set(name, {
        name,
        slug,
        url: `${ORIGIN}/categories/${slug}.html`,
        href: (depth) => `${'../'.repeat(depth)}categories/${slug}.html`,
        ...guide
    });
}

{   // Fail fast on collisions rather than silently overwriting a page.
    const seen = new Map();
    for (const [name, meta] of catMeta) {
        if (seen.has(meta.slug)) throw new Error(`Category slug collision: "${name}" and "${seen.get(meta.slug)}"`);
        seen.set(meta.slug, name);
    }
    const ids = new Set();
    for (const e of errors) {
        if (ids.has(e.id)) throw new Error(`Duplicate error id: ${e.id}`);
        if (!/^[a-z0-9][a-z0-9-]*$/.test(e.id)) throw new Error(`Unsafe error id: ${e.id}`);
        ids.add(e.id);
    }
}

const byCategory = new Map(categories.map(c => [c, []]));
for (const e of errors) byCategory.get(e.category).push(e);
for (const list of byCategory.values()) list.sort((a, b) => a.title.localeCompare(b.title));

const errorUrl = (id) => `${ORIGIN}/errors/${id}.html`;
const errorHref = (id, depth) => `${'../'.repeat(depth)}errors/${id}.html`;

/**
 * Link back to the search page (the site root).
 *
 * At depth 0 the naive `'../'.repeat(0)` is an empty string, and an empty href
 * resolves to *the current page*, which is why the header brand and the
 * "Search" nav link used to do nothing on categories.html, all-errors.html and
 * about.html. "./" resolves to the directory index in every case.
 */
const homeHref = (depth) => (depth === 0 ? './' : '../'.repeat(depth));

/* ------------------------------------------------------------------ shell */

/**
 * @param {object} o
 * @param {number} o.depth  directory depth of the page, for relative links
 */
function layout(o) {
    const rel = '../'.repeat(o.depth);
    const structured = (o.structuredData || [])
        .map(d => `    <script type="application/ld+json">${jsonLd(d)}</script>`)
        .join('\n');

    return `<!DOCTYPE html>
<html lang="en-GB">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${esc(o.title)}</title>
    <meta name="description" content="${esc(o.description)}">
    <meta name="robots" content="index, follow, max-image-preview:large, max-snippet:-1">
    <link rel="canonical" href="${esc(o.canonical)}">

    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; manifest-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;">
    <meta name="referrer" content="strict-origin-when-cross-origin">

    <meta property="og:type" content="${o.ogType || 'article'}">
    <meta property="og:url" content="${esc(o.canonical)}">
    <meta property="og:title" content="${esc(o.ogTitle || o.title)}">
    <meta property="og:description" content="${esc(o.description)}">
    <meta property="og:image" content="${OG_IMAGE}">
    <meta property="og:image:type" content="image/png">
    <meta property="og:image:width" content="1200">
    <meta property="og:image:height" content="630">
    <meta property="og:image:alt" content="FixMyError.net: instant developer error solutions">
    <meta property="og:site_name" content="${SITE_NAME}">
    <meta property="og:locale" content="en_GB">

    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="${esc(o.ogTitle || o.title)}">
    <meta name="twitter:description" content="${esc(o.description)}">
    <meta name="twitter:image" content="${OG_IMAGE}">

    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🚀</text></svg>">
    <link rel="apple-touch-icon" href="${rel}apple-touch-icon.png">
    <link rel="manifest" href="${rel}manifest.json">
    <link rel="alternate" type="application/rss+xml" title="${SITE_NAME}: Recently Added Errors" href="${rel}feed.xml">
    <meta name="theme-color" content="#0d1117">
    <link rel="stylesheet" href="${rel}assets/site.css">
${structured}
</head>
<body>
    <a href="#main" class="skip-link">Skip to content</a>

    <div class="safety-warning">
        <div class="container-wide">
            <span aria-hidden="true">⚠️</span>
            <strong>SECURITY WARNING:</strong> Never run commands you don't understand. Always review code before execution. Use at your own risk.
        </div>
    </div>

    <header class="site-header">
        <div class="site-header-inner">
            <a class="site-brand" href="${homeHref(o.depth)}"><span aria-hidden="true">🚀</span> ${SITE_NAME}</a>
            <nav class="site-nav" aria-label="Primary">
                <a href="${homeHref(o.depth)}#searchInput">Search</a>
                <a href="${rel}categories.html">Categories</a>
                <a href="${rel}all-errors.html">All errors</a>
                <a href="${rel}about.html">About</a>
            </nav>
        </div>
    </header>

    <main id="main">
${o.body}
    </main>

    <footer class="site-footer">
        <div class="container-wide">
            <div class="footer-cols">
                <div>
                    <h2>Browse</h2>
                    <ul>
                        <li><a href="${homeHref(o.depth)}">Search all errors</a></li>
                        <li><a href="${rel}categories.html">Categories</a></li>
                        <li><a href="${rel}all-errors.html">Full A-Z index</a></li>
                        <li><a href="${rel}feed.xml">RSS feed</a></li>
                    </ul>
                </div>
                <div>
                    <h2>Popular</h2>
                    <ul>
${['HTTP', 'Kubernetes', 'Docker', 'TLS', 'Database']
        .filter(c => catMeta.has(c))
        .map(c => `                        <li><a href="${rel}categories/${catMeta.get(c).slug}.html">${esc(c)} errors</a></li>`)
        .join('\n')}
                    </ul>
                </div>
                <div>
                    <h2>Contribute</h2>
                    <ul>
                        <li><a href="mailto:${CONTACT}?subject=FixMyError.net%20%E2%80%93%20submit%20an%20error%20or%20fix">Submit an error or fix</a></li>
                        <li><a href="mailto:${CONTACT}?subject=FixMyError.net%20%E2%80%93%20correction">Report a correction</a></li>
                        <li><a href="${rel}about.html">About this site</a></li>
                    </ul>
                    <!-- A mailto: link does nothing at all when the browser has no
                         mail handler registered, so the address is always shown in
                         full and can be copied without one. -->
                    <p class="footer-contact">Or email <span id="footerEmail">${CONTACT}</span><button class="copy-button" type="button" data-copy-target="footerEmail">Copy</button></p>
                </div>
            </div>
            <div class="footer-bottom">
                <p>${SITE_NAME} has ${errors.length} documented errors across ${categories.length} categories. Last updated ${esc(humanDate(BUILD_DATE))}.</p>
                <p>Commands and configuration shown here are starting points, not guarantees. Always understand a command before running it in production.</p>
            </div>
        </div>
    </footer>

    <button class="theme-toggle" id="themeToggle" type="button" aria-label="Toggle light/dark theme"><span id="themeToggleIcon" aria-hidden="true">🌙</span></button>
    <div class="toast" id="toast" role="status" aria-live="polite"></div>
    <script src="${rel}assets/page.js" defer></script>
</body>
</html>
`;
}

/**
 * @param {string} container  the same wrapper class the page body uses, so the
 *                            crumbs line up with the text block beneath them
 *                            instead of sitting flush against the viewport.
 */
function breadcrumb(trail, depth, container = 'container') {
    const rel = '../'.repeat(depth);
    const items = trail.map((t, i) => {
        const last = i === trail.length - 1;
        const label = esc(t.label);
        // An empty href means "the site root": resolve it properly rather than
        // producing href="" , which points back at the current page.
        const target = t.href ? `${rel}${t.href}` : homeHref(depth);
        return last
            ? `<li aria-current="page">${label}</li>`
            : `<li><a href="${target}">${label}</a></li>`;
    }).join('');
    return `        <nav class="breadcrumb" aria-label="Breadcrumb"><div class="${container}"><ol>${items}</ol></div></nav>`;
}

function breadcrumbLd(trail) {
    return {
        '@context': 'https://schema.org',
        '@type': 'BreadcrumbList',
        itemListElement: trail.map((t, i) => ({
            '@type': 'ListItem',
            position: i + 1,
            name: t.label,
            item: t.url
        }))
    };
}

function codeBlock(code, label, id) {
    return `<div class="code-wrap">
                    <div class="code-head"><span>${esc(label)}</span><button class="copy-button" type="button" data-copy-target="${esc(id)}">Copy</button></div>
                    <pre class="code-block" id="${esc(id)}"><code>${esc(code)}</code></pre>
                </div>`;
}

/* ------------------------------------------------------------ error pages */

/**
 * Error titles are the error text itself, so many are already long. Only pad
 * short ones with descriptive words and the brand; leave long ones alone
 * rather than pushing the distinctive part out of the search result.
 */
function errorPageTitle(title) {
    if (title.length <= 40) return `${title}: Cause and Fix | ${SITE_NAME}`;
    if (title.length <= 58) return `${title} | ${SITE_NAME}`;
    return title;
}

function renderErrorPage(err) {
    const meta = catMeta.get(err.category);
    const depth = 1;
    const canonical = errorUrl(err.id);
    const description = truncate(`${err.explanation} Includes a copy-paste fix and how to diagnose it.`, 158);

    const trail = [
        { label: 'Home', href: '', url: `${ORIGIN}/` },
        { label: `${err.category} errors`, href: `categories/${meta.slug}.html`, url: meta.url },
        { label: err.title, href: '', url: canonical }
    ];

    const hasWindows = typeof err.fix_snippet_windows === 'string' && err.fix_snippet_windows.length > 0;
    const fixBlock = hasWindows
        ? `<div class="tabs" role="tablist" aria-label="Platform">
                    <button class="tab" type="button" role="tab" id="tab-unix" aria-controls="panel-unix" aria-selected="true">Linux / macOS</button>
                    <button class="tab" type="button" role="tab" id="tab-win" aria-controls="panel-win" aria-selected="false">Windows</button>
                </div>
                <div class="tabpanel" id="panel-unix" role="tabpanel" aria-labelledby="tab-unix">
                    ${codeBlock(err.fix_snippet, 'Linux / macOS', `fix-${err.id}`)}
                </div>
                <div class="tabpanel" id="panel-win" role="tabpanel" aria-labelledby="tab-win" hidden>
                    ${codeBlock(err.fix_snippet_windows, 'Windows', `fixwin-${err.id}`)}
                </div>`
        : codeBlock(err.fix_snippet, 'Quick fix', `fix-${err.id}`);

    const related = byCategory.get(err.category).filter(e => e.id !== err.id).slice(0, 8);
    const relatedBlock = related.length === 0 ? '' : `
        <section class="block">
            <h2>Related ${esc(err.category)} errors</h2>
            <ul class="link-list">
${related.map(r => `                <li><a href="${errorHref(r.id, depth)}">${esc(r.title)}<span class="sub">${esc(truncate(r.explanation, 95))}</span></a></li>`).join('\n')}
            </ul>
            <p style="margin-top:14px"><a href="${meta.href(depth)}">See all ${byCategory.get(err.category).length} ${esc(err.category)} errors →</a></p>
        </section>`;

    const sources = (err.sources || []).filter(isSafeUrl);
    const sourcesBlock = sources.length === 0 ? '' : `
        <section class="block">
            <h2>Authoritative references</h2>
            <p>Primary documentation for this error, worth reading before applying any fix in production.</p>
            <p>${sources.map(s => `<a class="source-link" href="${esc(s)}" target="_blank" rel="noopener noreferrer nofollow"><span aria-hidden="true">📖</span> ${esc(new URL(s).hostname.replace(/^www\./, ''))}</a>`).join(' ')}</p>
        </section>`;

    const otherCategories = categories
        .filter(c => c !== err.category)
        .sort((a, b) => byCategory.get(b).length - byCategory.get(a).length)
        .slice(0, 12);

    const body = `${breadcrumb(trail, depth)}
        <div class="container">
        <article>
            <div class="meta-row">
                <a class="badge" href="${meta.href(depth)}">${esc(err.category)}</a>
                ${isNew(err) ? '<span class="badge badge-new">New</span>' : ''}
                ${err.dateAdded ? `<span class="badge badge-muted">Added ${esc(humanDate(err.dateAdded))}</span>` : ''}
            </div>
            <h1 class="page-title">${esc(err.title)}</h1>
            <p class="page-lede">${esc(err.explanation)}</p>

            <section class="block">
                <h2>Quick fix</h2>
                <p>Read the commands before running them. Anything that restarts a service, deletes data or changes permissions should be tried on a non-production system first.</p>
                ${fixBlock}
            </section>

            <section class="block">
                <h2>How to diagnose ${esc(err.category)} errors</h2>
                <p>${meta.intro}</p>
                <p>If the quick fix above does not resolve it, work through these steps. They apply to this whole class of error, not just to this one message, which is usually what saves the time.</p>
                <ol>
${meta.howToDebug.map(step => `                    <li>${step}</li>`).join('\n')}
                </ol>
                <h3>Tools worth reaching for</h3>
                <ul class="tool-list">
${meta.tools.map(t => `                    <li><code>${esc(t)}</code></li>`).join('\n')}
                </ul>
            </section>
${sourcesBlock}
${relatedBlock}

            <section class="block">
                <h2>Browse other categories</h2>
                <ul class="card-grid">
${otherCategories.map(c => {
        const m = catMeta.get(c);
        return `                    <li><a href="${m.href(depth)}"><span class="card-title">${esc(c)} <span class="card-count">${byCategory.get(c).length}</span></span><span class="card-desc">${esc(truncate(m.tagline, 80))}</span></a></li>`;
    }).join('\n')}
                </ul>
            </section>

            <section class="block">
                <h2>Something missing or wrong?</h2>
                <p>This entry is maintained by hand. If the fix is out of date, incomplete, or you have a better one, <a href="mailto:${CONTACT}?subject=${encodeURIComponent(`FixMyError.net: ${err.title}`)}">email a correction</a> and it will be reviewed.</p>
            </section>
        </article>
        </div>`;

    const article = {
        '@context': 'https://schema.org',
        '@type': 'TechArticle',
        headline: err.title,
        name: err.title,
        description,
        url: canonical,
        mainEntityOfPage: { '@type': 'WebPage', '@id': canonical },
        inLanguage: 'en-GB',
        articleSection: err.category,
        proficiencyLevel: 'Expert',
        datePublished: err.dateAdded || '2026-06-25',
        dateModified: BUILD_DATE,
        image: OG_IMAGE,
        author: { '@type': 'Organization', name: SITE_NAME, url: `${ORIGIN}/` },
        publisher: {
            '@type': 'Organization',
            name: SITE_NAME,
            url: `${ORIGIN}/`,
            logo: { '@type': 'ImageObject', url: OG_IMAGE }
        },
        ...(sources.length ? { citation: sources } : {})
    };

    return layout({
        depth,
        title: errorPageTitle(err.title),
        ogTitle: `${err.title}: cause and fix`,
        description,
        canonical,
        structuredData: [article, breadcrumbLd(trail)],
        body
    });
}

/* --------------------------------------------------------- category pages */

function renderCategoryPage(name) {
    const meta = catMeta.get(name);
    const list = byCategory.get(name);
    const depth = 1;
    const canonical = meta.url;
    const description = truncate(`${list.length} documented ${name} errors with copy-paste fixes. ${stripTags(meta.tagline)}`, 158);

    const trail = [
        { label: 'Home', href: '', url: `${ORIGIN}/` },
        { label: 'Categories', href: 'categories.html', url: `${ORIGIN}/categories.html` },
        { label: `${name} errors`, href: '', url: canonical }
    ];

    const others = categories.filter(c => c !== name);

    const body = `${breadcrumb(trail, depth)}
        <div class="container">
        <article>
            <div class="meta-row">
                <span class="badge">${esc(name)}</span>
                <span class="badge badge-muted">${list.length} errors</span>
            </div>
            <h1 class="page-title">${esc(meta.title)}</h1>
            <p class="page-lede">${esc(meta.tagline)}</p>

            <section class="block">
                <h2>Understanding ${esc(name)} errors</h2>
                <p>${meta.intro}</p>
            </section>

            <section class="block">
                <h2>How to debug ${esc(name)} errors</h2>
                <ol>
${meta.howToDebug.map(step => `                    <li>${step}</li>`).join('\n')}
                </ol>
                <h3>Tools worth reaching for</h3>
                <ul class="tool-list">
${meta.tools.map(t => `                    <li><code>${esc(t)}</code></li>`).join('\n')}
                </ul>
            </section>

            <section class="block">
                <h2>All ${list.length} ${esc(name)} errors</h2>
                <ul class="link-list">
${list.map(e => `                    <li><a href="${errorHref(e.id, depth)}">${esc(e.title)}${isNew(e) ? ' <span class="badge badge-new">New</span>' : ''}<span class="sub">${esc(truncate(e.explanation, 120))}</span></a></li>`).join('\n')}
                </ul>
            </section>

            <section class="block">
                <h2>Other categories</h2>
                <ul class="card-grid">
${others.map(c => {
        const m = catMeta.get(c);
        return `                    <li><a href="${m.href(depth)}"><span class="card-title">${esc(c)} <span class="card-count">${byCategory.get(c).length}</span></span><span class="card-desc">${esc(truncate(m.tagline, 80))}</span></a></li>`;
    }).join('\n')}
                </ul>
            </section>
        </article>
        </div>`;

    const collection = {
        '@context': 'https://schema.org',
        '@type': 'CollectionPage',
        name: meta.title,
        description,
        url: canonical,
        inLanguage: 'en-GB',
        isPartOf: { '@type': 'WebSite', name: SITE_NAME, url: `${ORIGIN}/` },
        mainEntity: {
            '@type': 'ItemList',
            numberOfItems: list.length,
            itemListElement: list.map((e, i) => ({
                '@type': 'ListItem',
                position: i + 1,
                name: e.title,
                url: errorUrl(e.id)
            }))
        }
    };

    return layout({
        depth,
        title: `${meta.title}: ${list.length} Fixes | ${SITE_NAME}`,
        ogTitle: meta.title,
        description,
        canonical,
        ogType: 'website',
        structuredData: [collection, breadcrumbLd(trail)],
        body
    });
}

/* ------------------------------------------------------------- index pages */

function renderCategoriesIndex() {
    const depth = 0;
    const canonical = `${ORIGIN}/categories.html`;
    const trail = [
        { label: 'Home', href: '', url: `${ORIGIN}/` },
        { label: 'Categories', href: '', url: canonical }
    ];
    const description = `All ${categories.length} error categories on ${SITE_NAME}, from HTTP status codes and TLS to Kubernetes, databases, AI APIs and Windows.`;

    const body = `${breadcrumb(trail, depth, 'container-wide')}
        <div class="container-wide">
            <h1 class="page-title">Error categories</h1>
            <p class="page-lede">${errors.length} documented errors grouped into ${categories.length} categories. Each category page includes an authored guide to debugging that whole class of problem.</p>

            <section class="block">
                <ul class="card-grid">
${categories.map(c => {
        const m = catMeta.get(c);
        return `                    <li><a href="${m.href(depth)}"><span class="card-title">${esc(c)} <span class="card-count">${byCategory.get(c).length}</span></span><span class="card-desc">${esc(m.tagline)}</span></a></li>`;
    }).join('\n')}
                </ul>
            </section>

            <section class="block">
                <h2>Looking for something specific?</h2>
                <p><a href="./">Search the full database</a> or browse the <a href="all-errors.html">complete A-Z index</a>.</p>
            </section>
        </div>`;

    return layout({
        depth,
        title: `Error Categories: ${categories.length} Topics | ${SITE_NAME}`,
        ogTitle: 'Error categories',
        description,
        canonical,
        ogType: 'website',
        structuredData: [
            {
                '@context': 'https://schema.org',
                '@type': 'CollectionPage',
                name: 'Error categories',
                description,
                url: canonical,
                mainEntity: {
                    '@type': 'ItemList',
                    numberOfItems: categories.length,
                    itemListElement: categories.map((c, i) => ({
                        '@type': 'ListItem', position: i + 1, name: c, url: catMeta.get(c).url
                    }))
                }
            },
            breadcrumbLd(trail)
        ],
        body
    });
}

function renderAllErrors() {
    const depth = 0;
    const canonical = `${ORIGIN}/all-errors.html`;
    const trail = [
        { label: 'Home', href: '', url: `${ORIGIN}/` },
        { label: 'All errors', href: '', url: canonical }
    ];
    const description = `Complete index of all ${errors.length} error messages documented on ${SITE_NAME}, grouped by category with a fix for each.`;

    const body = `${breadcrumb(trail, depth, 'container-wide')}
        <div class="container-wide">
            <h1 class="page-title">All ${errors.length} errors</h1>
            <p class="page-lede">Every documented error, grouped by category. Use <a href="./">the search page</a> if you know the message you are looking for.</p>

            <nav class="az-nav" aria-label="Jump to category">
${categories.map(c => `                <a href="#cat-${catMeta.get(c).slug}">${esc(c)}</a>`).join('\n')}
            </nav>

${categories.map(c => `            <section class="index-group" id="cat-${catMeta.get(c).slug}">
                <h2><a href="${catMeta.get(c).href(depth)}">${esc(c)}</a> <span class="count">${byCategory.get(c).length} errors</span></h2>
                <ul class="index-list">
${byCategory.get(c).map(e => `                    <li><a href="${errorHref(e.id, depth)}">${esc(e.title)}</a></li>`).join('\n')}
                </ul>
            </section>`).join('\n')}
        </div>`;

    return layout({
        depth,
        title: `All ${errors.length} Documented Errors: A-Z Index | ${SITE_NAME}`,
        ogTitle: `All ${errors.length} documented errors`,
        description,
        canonical,
        ogType: 'website',
        structuredData: [breadcrumbLd(trail)],
        body
    });
}

function renderAbout() {
    const depth = 0;
    const canonical = `${ORIGIN}/about.html`;
    const trail = [
        { label: 'Home', href: '', url: `${ORIGIN}/` },
        { label: 'About', href: '', url: canonical }
    ];
    const description = `What ${SITE_NAME} is, how entries are written and verified, how to use the site effectively, and how to submit a correction.`;
    const newest = errors.filter(e => e.dateAdded).sort((a, b) => b.dateAdded.localeCompare(a.dateAdded)).slice(0, 6);

    const body = `${breadcrumb(trail, depth)}
        <div class="container">
            <h1 class="page-title">About FixMyError.net</h1>
            <p class="page-lede">A hand-maintained reference of ${errors.length} error messages across ${categories.length} categories, each with a plain-English explanation, a copy-paste fix, and a link to the authoritative documentation.</p>

            <section class="block">
                <h2>What this site is for</h2>
                <p>When you paste an error message into a search engine you usually get a forum thread from 2017 with three contradictory answers and no explanation of <em>why</em> any of them work. This site exists to be the other thing: a short, current, checkable answer that tells you what the message actually means before it tells you what to type.</p>
                <p>Every entry has the same shape: what the error means, a fix you can copy, and where to read more. Every category also has a debugging guide, because the most valuable thing is rarely the one command; it is knowing how to narrow down that whole class of problem next time.</p>
            </section>

            <section class="block">
                <h2>How to use it well</h2>
                <ul>
                    <li><strong>Search the literal message.</strong> The search is fuzzy, so paste the distinctive part of the error rather than a description of it: <code>x509: certificate signed by unknown authority</code> rather than "ssl broken".</li>
                    <li><strong>Read the explanation before the fix.</strong> Most errors have several causes; the explanation tells you which one you are looking at.</li>
                    <li><strong>Use the category guide.</strong> If the quick fix does not apply, the "how to diagnose" section on each page works for the whole class of error.</li>
                    <li><strong>Star what you use.</strong> Favourites are stored in your browser and can be exported as JSON from the toolbar.</li>
                    <li><strong>Keyboard shortcuts.</strong> Press <kbd>/</kbd> or <kbd>Ctrl</kbd>+<kbd>K</kbd> to search, <kbd>?</kbd> for the full list.</li>
                </ul>
            </section>

            <section class="block">
                <h2>How entries are written</h2>
                <p>Entries are written by hand, not generated in bulk. Each one is checked against primary documentation (the vendor's own docs, an RFC, or the project's issue tracker) and that source is linked on the page so you can verify it yourself rather than trusting this site.</p>
                <div class="callout">
                    <strong>Please read commands before running them.</strong> Fixes are starting points written without knowledge of your environment. Anything that restarts a service, changes permissions, deletes data or disables a security control deserves a careful read and a non-production test first. Commands marked as development-only should never reach production.
                </div>
            </section>

            <section class="block">
                <h2>Keeping it current</h2>
                <p>Software changes and fixes rot. Entries carry the date they were added, recent additions are flagged, and the <a href="feed.xml">RSS feed</a> lists new entries as they are published. The database was last rebuilt on ${esc(humanDate(BUILD_DATE))}.</p>
                <h3>Recently added</h3>
                <ul class="link-list">
${newest.map(e => `                    <li><a href="${errorHref(e.id, depth)}">${esc(e.title)}<span class="sub">${esc(e.category)} · added ${esc(humanDate(e.dateAdded))}</span></a></li>`).join('\n')}
                </ul>
            </section>

            <section class="block">
                <h2>Corrections and contributions</h2>
                <p>Corrections are genuinely welcome, particularly for entries that have gone stale. Email <a href="mailto:${CONTACT}">${CONTACT}</a> with the error title and what should change. New entries are most useful when they include the exact message text, a reproducible cause, and a link to primary documentation.</p>
            </section>

            <section class="block">
                <h2>Privacy</h2>
                <p>There is no analytics script, no advertising and no third-party tracking on this site. Favourites, search history and your theme preference are stored in your own browser's local storage and are never sent anywhere.</p>
            </section>
        </div>`;

    return layout({
        depth,
        title: `About: How This Error Database Works | ${SITE_NAME}`,
        ogTitle: 'About FixMyError.net',
        description,
        canonical,
        ogType: 'website',
        structuredData: [breadcrumbLd(trail)],
        body
    });
}

function render404() {
    const depth = 0;
    const body = `        <div class="container">
            <h1 class="page-title">404: page not found</h1>
            <p class="page-lede">That page does not exist. It may have been renamed, or the link may be from an older version of this site.</p>
            <section class="block">
                <h2>Try one of these</h2>
                <ul class="link-list">
                    <li><a href="/">Search all ${errors.length} errors<span class="sub">Fuzzy search across every error message and fix</span></a></li>
                    <li><a href="/categories.html">Browse ${categories.length} categories<span class="sub">Each with a guide to debugging that class of error</span></a></li>
                    <li><a href="/all-errors.html">Full A-Z index<span class="sub">Every documented error on one page</span></a></li>
                </ul>
            </section>
        </div>`;

    const html = layout({
        depth,
        title: `Page not found | ${SITE_NAME}`,
        description: 'That page does not exist on FixMyError.net. Search the error database or browse by category.',
        canonical: `${ORIGIN}/404.html`,
        ogType: 'website',
        body
    });
    // A 404 must never be indexed, and its links must work from any depth.
    return html.replace(
        '<meta name="robots" content="index, follow, max-image-preview:large, max-snippet:-1">',
        '<meta name="robots" content="noindex, follow">'
    ).replace(/(href|src)="((?!https?:|mailto:|data:|#|\/)[^"]*)"/g, '$1="/$2"');
}

/* ----------------------------------------------------------- data + feeds */

function renderEmbeddedData() {
    // Keep the payload the app downloads as small as is reasonable: it is
    // 690+ records fetched on every cold load.
    const compact = errors.map(e => {
        const o = {
            id: e.id,
            title: e.title,
            category: e.category,
            explanation: e.explanation,
            fix_snippet: e.fix_snippet
        };
        if (e.fix_snippet_windows) o.fix_snippet_windows = e.fix_snippet_windows;
        if (e.dateAdded) o.dateAdded = e.dateAdded;
        o.sources = e.sources;
        return o;
    });
    // One record per line: compact enough to keep the download small, but still
    // a readable diff when an entry changes.
    const body = compact.map(o => `  ${JSON.stringify(o)}`).join(',\n');
    return `// GENERATED FILE - do not edit by hand.\n// Source: data/errors.json  |  Regenerate: npm run build\nconst ERRORS_DATA = [\n${body}\n];\n`;
}

function renderSitemap() {
    const urls = [
        { loc: `${ORIGIN}/`, changefreq: 'daily', priority: '1.0' },
        { loc: `${ORIGIN}/categories.html`, changefreq: 'weekly', priority: '0.9' },
        { loc: `${ORIGIN}/all-errors.html`, changefreq: 'weekly', priority: '0.8' },
        { loc: `${ORIGIN}/about.html`, changefreq: 'monthly', priority: '0.5' },
        ...categories.map(c => ({ loc: catMeta.get(c).url, changefreq: 'weekly', priority: '0.8' })),
        ...errors.map(e => ({ loc: errorUrl(e.id), changefreq: 'monthly', priority: '0.7' }))
    ];

    return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map(u => `  <url>
    <loc>${xmlEsc(u.loc)}</loc>
    <lastmod>${BUILD_DATE}</lastmod>
    <changefreq>${u.changefreq}</changefreq>
    <priority>${u.priority}</priority>
  </url>`).join('\n')}
</urlset>
`;
}

function renderFeed() {
    const items = errors
        .filter(e => e.dateAdded)
        .sort((a, b) => (b.dateAdded.localeCompare(a.dateAdded)) || a.title.localeCompare(b.title))
        .slice(0, 60);

    return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>${xmlEsc(SITE_NAME)} &#8211; Recently Added Errors</title>
    <link>${ORIGIN}/</link>
    <atom:link href="${ORIGIN}/feed.xml" rel="self" type="application/rss+xml"/>
    <description>Newly added developer and infrastructure error fixes on ${xmlEsc(SITE_NAME)}.</description>
    <language>en-GB</language>
    <lastBuildDate>${rfc822(BUILD_DATE)}</lastBuildDate>
    <ttl>1440</ttl>
${items.map(e => `    <item>
      <title>${xmlEsc(e.title)}</title>
      <link>${xmlEsc(errorUrl(e.id))}</link>
      <guid isPermaLink="true">${xmlEsc(errorUrl(e.id))}</guid>
      <category>${xmlEsc(e.category)}</category>
      <pubDate>${rfc822(e.dateAdded)}</pubDate>
      <description>${xmlEsc(truncate(e.explanation, 300))}</description>
    </item>`).join('\n')}
  </channel>
</rss>
`;
}

function renderRobots() {
    return `User-agent: *
Allow: /

# Crawlers do not need the raw dataset or the build sources.
Disallow: /data/
Disallow: /scripts/

Sitemap: ${ORIGIN}/sitemap.xml
`;
}

/**
 * Rewrite the error and category counts quoted in the hand-written files, so
 * the title bar can never disagree with the page body again. Every rule must
 * still match something: if it does not, the copy was reworded and the rule in
 * scripts/counts.mjs needs updating rather than being quietly skipped.
 */
function syncCounts() {
    const value = { errors: String(errors.length), categories: String(categories.length) };
    const byFile = new Map();
    for (const rule of COUNT_RULES) {
        if (!byFile.has(rule.file)) byFile.set(rule.file, []);
        byFile.get(rule.file).push(rule);
    }

    let changed = 0;
    for (const [file, rules] of byFile) {
        const full = path.join(ROOT, file);
        const before = fs.readFileSync(full, 'utf8');
        let after = before;
        for (const rule of rules) {
            let hits = 0;
            after = after.replace(countPattern(rule), () => { hits++; return value[rule.kind]; });
            if (hits === 0) {
                throw new Error(`Count rule for "${file}" no longer matches: "…${rule.phrase}". Update scripts/counts.mjs.`);
            }
        }
        if (after !== before) { fs.writeFileSync(full, after); changed++; }
    }
    return changed;
}

/* ------------------------------------------------------------------- main */

function clean(dir) {
    const full = path.join(ROOT, dir);
    if (!fs.existsSync(full)) return;
    for (const name of fs.readdirSync(full)) {
        if (name.endsWith('.html')) fs.unlinkSync(path.join(full, name));
    }
}

clean('errors');
clean('categories');

for (const err of errors) write(`errors/${err.id}.html`, renderErrorPage(err));
for (const name of categories) write(`categories/${catMeta.get(name).slug}.html`, renderCategoryPage(name));

write('categories.html', renderCategoriesIndex());
write('all-errors.html', renderAllErrors());
write('about.html', renderAbout());
write('404.html', render404());
write('embedded-data.js', renderEmbeddedData());
write('sitemap.xml', renderSitemap());
write('feed.xml', renderFeed());
write('robots.txt', renderRobots());

const countFilesChanged = syncCounts();

console.log(`Built ${errors.length} error pages, ${categories.length} category pages`);
if (countFilesChanged) console.log(`Synced quoted counts in ${countFilesChanged} hand-written file(s)`);
console.log(`Indexable URLs in sitemap: ${errors.length + categories.length + 4}`);
console.log(`Build date: ${BUILD_DATE}`);
