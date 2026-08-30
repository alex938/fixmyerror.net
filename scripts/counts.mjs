/**
 * Where the dataset size is quoted in prose.
 *
 * index.html, manifest.json and README.md are written by hand, so the build
 * does not regenerate them wholesale — but they all state how many errors and
 * categories the site has. Those numbers went stale the moment entries were
 * added (the title bar still said "690+" while the page itself said 731).
 *
 * Both the build (which rewrites these numbers) and the validator (which
 * proves none of them drifted) work from this single list. A rule that stops
 * matching means the surrounding copy was reworded: the build fails rather
 * than silently leaving a stale figure behind.
 */

/** @typedef {{ file: string, kind: 'errors'|'categories', phrase: string }} CountRule */

/** @type {CountRule[]} */
export const COUNT_RULES = [
    { file: 'index.html', kind: 'errors', phrase: ' Developer Error Fixes' },
    { file: 'index.html', kind: 'errors', phrase: ' developer and DevOps errors' },
    { file: 'index.html', kind: 'errors', phrase: ' developer &amp; infrastructure error fixes' },
    { file: 'index.html', kind: 'categories', phrase: ' categories' },
    { file: 'manifest.json', kind: 'errors', phrase: ' documented developer errors' },
    { file: 'README.md', kind: 'errors', phrase: ' developer and infrastructure error messages' },
    { file: 'README.md', kind: 'categories', phrase: ' categories' }
];

const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Matches a written-out count immediately before the rule's phrase, including
 * any thousands separator and a trailing "+" ("690+ developer and DevOps…").
 */
export function countPattern(rule) {
    return new RegExp(`\\b\\d[\\d,]*\\+?(?=${escapeRegex(rule.phrase)})`, 'g');
}
