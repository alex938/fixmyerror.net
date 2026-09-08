#!/usr/bin/env node
/**
 * Link rot check for data/errors.json.
 *
 * Every entry links to primary documentation, and vendors move their docs
 * constantly: a quarter of the original AWS, Microsoft and Terraform links
 * had already 404ed within a year. `npm run check` cannot catch this because
 * it never leaves the filesystem, so this is a separate, network-bound pass.
 *
 *   npm run check:sources              # everything
 *   npm run check:sources -- --since 2026-09-01   # only recently added entries
 *
 * A 403 or 429 is almost always a vendor blocking automated clients rather
 * than a dead page (dev.mysql.com, gnu.org and platform.openai.com all do
 * this), so those are reported separately and are not failures. Only 404 and
 * 410 mean the page is genuinely gone.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const CONCURRENCY = 8;
const TIMEOUT_MS = 20000;
const UA = 'Mozilla/5.0 (compatible; fixmyerror-linkcheck/1.0; +https://fixmyerror.net)';

const sinceArg = process.argv.indexOf('--since');
const since = sinceArg === -1 ? null : process.argv[sinceArg + 1];

const errors = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/errors.json'), 'utf8'));
const owners = new Map();          // url -> [error id, ...]

for (const e of errors) {
    if (since && (!e.dateAdded || e.dateAdded < since)) continue;
    for (const url of e.sources || []) {
        if (!owners.has(url)) owners.set(url, []);
        owners.get(url).push(e.id);
    }
}

const urls = [...owners.keys()];
const dead = [];
const blocked = [];
let done = 0;

async function status(url) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
        // Some CDNs reject HEAD outright, so ask for the document and drop it.
        const res = await fetch(url, {
            redirect: 'follow',
            signal: controller.signal,
            headers: { 'user-agent': UA, accept: 'text/html,*/*' },
        });
        return res.status;
    } catch {
        return 0;
    } finally {
        clearTimeout(timer);
    }
}

async function worker(queue) {
    for (;;) {
        const url = queue.shift();
        if (!url) return;
        const code = await status(url);
        done++;
        if (process.stdout.isTTY) process.stdout.write(`\r${done}/${urls.length} checked`);
        if (code === 404 || code === 410) dead.push({ url, code });
        else if (code !== 200 && code !== 0) blocked.push({ url, code });
    }
}

const queue = [...urls];
await Promise.all(Array.from({ length: CONCURRENCY }, () => worker(queue)));
if (process.stdout.isTTY) process.stdout.write('\r');

if (blocked.length) {
    console.log(`\n${blocked.length} link(s) answered something other than 200, probably bot protection:`);
    for (const { url, code } of blocked) console.log(`  ${code}  ${url}`);
}

if (dead.length) {
    console.log(`\n${dead.length} dead link(s). Find the page's new home and update data/errors.json:`);
    for (const { url, code } of dead) {
        console.log(`  ${code}  ${url}`);
        console.log(`        used by: ${owners.get(url).join(', ')}`);
    }
}

console.log(`\n${urls.length} unique source URLs, ${dead.length} dead, ${blocked.length} unverifiable`);
process.exit(dead.length ? 1 : 0);
