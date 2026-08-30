#!/usr/bin/env node
/**
 * Consistency checks for the generated site. Run locally after `npm run build`
 * and in CI on every push.
 *
 * It verifies that the data is well formed, that every generated page exists,
 * that no internal link points at a missing file, and that the SEO essentials
 * (unique titles, unique canonicals, length-bounded descriptions) hold.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { COUNT_RULES, countPattern } from './counts.mjs';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const ORIGIN = 'https://fixmyerror.net';

const problems = [];
const warnings = [];
const fail = (m) => problems.push(m);
const warn = (m) => warnings.push(m);

const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

/** Measure what a search engine renders, not the escaped attribute source. */
const decodeEntities = (s) => String(s)
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#0?39;/g, "'")
    .replace(/&amp;/g, '&');
const exists = (rel) => fs.existsSync(path.join(ROOT, rel));

const errors = JSON.parse(read('data/errors.json'));
const guides = JSON.parse(read('data/categories.json'));

/* --------------------------------------------------------------- data ---- */

const REQUIRED = ['id', 'title', 'category', 'explanation', 'fix_snippet', 'sources'];
const seenIds = new Set();
const seenTitles = new Set();

for (const e of errors) {
    for (const key of REQUIRED) {
        if (!e[key] || (Array.isArray(e[key]) && e[key].length === 0)) {
            fail(`error "${e.id || '(no id)'}" is missing ${key}`);
        }
    }
    if (seenIds.has(e.id)) fail(`duplicate error id: ${e.id}`);
    seenIds.add(e.id);

    const t = String(e.title).toLowerCase();
    if (seenTitles.has(t)) fail(`duplicate error title: ${e.title}`);
    seenTitles.add(t);

    // ids become filenames and URL paths, so keep them boring.
    if (!/^[a-z0-9][a-z0-9-]*$/.test(e.id)) fail(`unsafe error id: ${e.id}`);
    if (!guides[e.category]) fail(`error "${e.id}" uses category "${e.category}" with no authored guide`);
    if (e.dateAdded && !/^\d{4}-\d{2}-\d{2}$/.test(e.dateAdded)) fail(`error "${e.id}" has a malformed dateAdded: ${e.dateAdded}`);

    for (const src of e.sources || []) {
        if (!/^https:\/\/[^\s"'<>]+$/.test(src)) fail(`error "${e.id}" has a non-HTTPS or malformed source: ${src}`);
    }

    if (e.explanation.length < 40) warn(`error "${e.id}" has a very short explanation (${e.explanation.length} chars)`);
    if (e.explanation.length > 600) warn(`error "${e.id}" has a very long explanation (${e.explanation.length} chars)`);
}

for (const [name, g] of Object.entries(guides)) {
    for (const key of ['title', 'tagline', 'intro', 'howToDebug', 'tools']) {
        if (!g[key] || (Array.isArray(g[key]) && g[key].length === 0)) fail(`category "${name}" guide is missing ${key}`);
    }
    if (Array.isArray(g.howToDebug) && g.howToDebug.length < 3) {
        warn(`category "${name}" has only ${g.howToDebug.length} debugging steps`);
    }
}

const usedCategories = new Set(errors.map(e => e.category));
for (const name of Object.keys(guides)) {
    if (!usedCategories.has(name)) warn(`category guide "${name}" has no errors`);
}

/* The hand-written files quote the dataset size in prose. The build rewrites
   those numbers; this proves none of them was missed, so the title bar can
   never claim a different total from the page body. */
{
    const expected = { errors: String(errors.length), categories: String(usedCategories.size) };
    for (const rule of COUNT_RULES) {
        const text = read(rule.file);
        const found = text.match(countPattern(rule)) || [];
        if (found.length === 0) {
            fail(`count rule for "${rule.file}" no longer matches: "…${rule.phrase}"`);
            continue;
        }
        for (const value of new Set(found)) {
            if (value !== expected[rule.kind]) {
                fail(`${rule.file} says "${value}${rule.phrase}" but there are ${expected[rule.kind]}`);
            }
        }
    }
}

/* -------------------------------------------------------------- pages ---- */

const pages = [
    'index.html', 'categories.html', 'all-errors.html', 'about.html', '404.html',
    ...errors.map(e => `errors/${e.id}.html`),
    ...fs.readdirSync(path.join(ROOT, 'categories')).map(f => `categories/${f}`)
];

for (const page of pages) {
    if (!exists(page)) { fail(`missing generated page: ${page}`); continue; }
}

/* --------------------------------------------- links, titles, canonicals -- */

const titles = new Map();
const canonicals = new Map();

for (const page of pages) {
    if (!exists(page)) continue;
    const html = read(page);
    const dir = path.dirname(page);

    const title = (html.match(/<title>([^<]*)<\/title>/) || [])[1];
    if (!title) fail(`${page}: no <title>`);
    else {
        if (titles.has(title)) fail(`${page}: duplicate <title> shared with ${titles.get(title)}`);
        titles.set(title, page);
        const titleLen = decodeEntities(title).length;
        if (titleLen > 80) warn(`${page}: title is ${titleLen} chars and will be truncated in results`);
    }

    const desc = (html.match(/<meta name="description" content="([^"]*)"/) || [])[1];
    if (!desc) fail(`${page}: no meta description`);
    else {
        const descLen = decodeEntities(desc).length;
        if (descLen > 165) warn(`${page}: meta description is ${descLen} chars`);
        else if (descLen < 70) warn(`${page}: meta description is only ${descLen} chars`);
    }

    const canonical = (html.match(/<link rel="canonical" href="([^"]*)"/) || [])[1];
    if (page !== '404.html') {
        if (!canonical) fail(`${page}: no canonical link`);
        else {
            if (canonicals.has(canonical)) fail(`${page}: canonical collides with ${canonicals.get(canonical)}`);
            canonicals.set(canonical, page);
            if (!canonical.startsWith(ORIGIN)) fail(`${page}: canonical does not point at ${ORIGIN}`);
        }
    }

    if (!/<h1[ >]/.test(html)) fail(`${page}: no <h1>`);

    // Every JSON-LD block must parse.
    for (const m of html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)) {
        try { JSON.parse(m[1]); } catch (err) { fail(`${page}: invalid JSON-LD (${err.message})`); }
    }

    // Internal links must resolve to a real file.
    for (const m of html.matchAll(/(?:href|src)="([^"#?]+)(?:[#?][^"]*)?"/g)) {
        const href = m[1];
        if (/^(https?:|mailto:|data:|tel:|\/\/)/.test(href) || href === '') continue;
        if (href.includes('${')) continue; // template literal inside an inline script
        const target = href.startsWith('/')
            ? path.join(ROOT, href.slice(1))
            : path.resolve(ROOT, dir, href);
        const candidate = target.endsWith('/') || !path.extname(target)
            ? path.join(target, 'index.html')
            : target;
        if (!fs.existsSync(candidate) && !fs.existsSync(target)) {
            fail(`${page}: broken internal link -> ${href}`);
        }
    }
}

/* ------------------------------------------------------ sitemap and feed -- */

const sitemap = read('sitemap.xml');
const locs = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map(m => m[1]);

if (locs.some(l => l.includes('#'))) {
    fail('sitemap contains fragment URLs, which search engines collapse into the parent page');
}
const dupLocs = locs.filter((l, i) => locs.indexOf(l) !== i);
if (dupLocs.length) fail(`sitemap has duplicate URLs: ${dupLocs.slice(0, 3).join(', ')}`);

for (const loc of locs) {
    const rel = loc.replace(`${ORIGIN}/`, '') || 'index.html';
    if (!exists(rel)) fail(`sitemap lists a URL with no file: ${loc}`);
}
for (const e of errors) {
    if (!locs.includes(`${ORIGIN}/errors/${e.id}.html`)) fail(`sitemap is missing ${e.id}`);
}

const feed = read('feed.xml');
if (feed.includes('<link>https://fixmyerror.net/#')) fail('feed still links to fragment URLs');
for (const m of feed.matchAll(/<link>([^<]+)<\/link>/g)) {
    const rel = m[1].replace(`${ORIGIN}/`, '') || 'index.html';
    if (!exists(rel)) fail(`feed links to a missing page: ${m[1]}`);
}

/* ------------------------------------------------------------- app data -- */

const embedded = read('embedded-data.js');
if (!embedded.startsWith('// GENERATED FILE')) fail('embedded-data.js is not the generated artefact — run npm run build');
const ids = new Set([...embedded.matchAll(/"id":\s*"([^"]+)"/g)].map(m => m[1]));
for (const e of errors) if (!ids.has(e.id)) fail(`embedded-data.js is missing ${e.id} — run npm run build`);

const index = read('index.html');
if (index.includes('cdn.jsdelivr.net')) fail('index.html still loads a third-party script');
if (index.includes('og-image.svg')) fail('index.html still references the SVG Open Graph image');
if (!index.includes('errors/${id}.html')) warn('index.html no longer links error cards to their permalink pages');

const robots = read('robots.txt');
if (!robots.includes(`Sitemap: ${ORIGIN}/sitemap.xml`)) fail('robots.txt does not declare the sitemap');

/* ---------------------------------------------------------------- output - */

for (const w of warnings) console.warn(`warn  ${w}`);
for (const p of problems) console.error(`FAIL  ${p}`);

console.log(`\n${errors.length} errors, ${Object.keys(guides).length} categories, ${pages.length} pages, ${locs.length} sitemap URLs`);
console.log(`${warnings.length} warning(s), ${problems.length} error(s)`);

process.exit(problems.length ? 1 : 0);
