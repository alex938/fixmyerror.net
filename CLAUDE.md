# CLAUDE.md

Guidance for agents working on fixmyerror.net.

## What this repository is

A static, hand-maintained reference of developer and infrastructure error messages. Each
entry has the literal error text, a plain-English explanation of what it means, a
copy-paste fix, and a link to primary documentation. Every entry also belongs to a
category that has its own authored debugging guide.

The site is deployed to S3 as a plain file sync. There is no runtime, no database, no
build step at request time and no third-party JavaScript. Every HTML file in the
repository root, `errors/` and `categories/` is **generated and committed**, because the
deploy is a file copy.

## The one rule

**The site must keep working and must keep looking exactly as it does.** Your job is to
keep the content current, not to redesign anything. Do not touch `assets/site.css`, the
page templates in `scripts/build.mjs`, the search behaviour in `index.html`, or the
navigation, unless the task explicitly asks for it. `npm run check` must pass with zero
failures before you commit; the DOM test suite exists precisely to catch a content change
that breaks the app.

## Your usual task: adding errors

1. Add objects to `data/errors.json`. Never edit generated HTML by hand.
2. If an entry needs a category that does not exist, add a guide to `data/categories.json`
   first. See "New categories" below: the bar is high.
3. Run `npm run check`. It builds, validates and tests. Fix anything it reports.
4. Commit the data change **and** the regenerated output together.

### Entry schema

```jsonc
{
  "id": "kebab-case-id",              // becomes /errors/<id>.html, unique, [a-z0-9-]
  "title": "The literal error text",  // what a person pastes into a search engine
  "category": "Kubernetes",           // must have a guide in data/categories.json
  "explanation": "What the message actually means, and why it happens.",
  "fix_snippet": "commands or config, \n-separated",
  "fix_snippet_windows": "optional; renders a Linux/Windows tab pair",
  "sources": ["https://…"],           // HTTPS only, primary docs, not blog posts
  "dateAdded": "2026-09-08"           // today; drives the New badge and the RSS feed
}
```

### House style, which the validator partly enforces

- **No em or en dashes anywhere.** Use a comma, colon, full stop or brackets. The
  validator fails the build on `–` and `—` in both data files. This is the loudest tell
  that copy was machine-written and the site is meant to read as hand-maintained.
- **Titles are the error text**, not a description of it. Someone should be able to paste
  the message from their terminal and match it. Keep them under about 80 characters or
  the validator warns that search results will truncate them; shorten by dropping the
  tail of a long message, never by paraphrasing the recognisable part.
- **Explanations say what the message means and why it happens**, in 40 to 600
  characters, two or three sentences. Say the non-obvious thing: which of two systems is
  actually at fault, why the same command works elsewhere, what makes it appear
  intermittently. Do not restate the title.
- **Fix snippets are terminal-ready.** Comment lines explain the steps, commands are real
  and safe to read before running. Include the diagnostic command that tells you which
  cause you have, not just the fix for one of them. Roughly 8 to 20 lines.
- **Sources are primary documentation**: the vendor, the RFC, the man page, the project's
  own docs. Not Stack Overflow, not a blog, not an AI-generated tutorial site. One or two
  links.
- British spelling in prose, since the rest of the site uses it.

### Choosing what to add

Useful entries are messages people actually paste into a search engine: exact,
recognisable, and produced by widely used software. Prefer:

- Errors from current versions of popular tooling, especially ones a major version bump
  introduced (a renamed API parameter, a removed stdlib module, a new default).
- Errors that are commonly misdiagnosed, where the message points at the wrong layer.
- Gaps in categories that are thin relative to how much the technology is used.

Avoid near-duplicates of existing entries. Check first:

```bash
node -e "const e=require('./data/errors.json');
  console.log(e.filter(x=>/timeout/i.test(x.title)).map(x=>x.id+' | '+x.title).join('\n'))"
```

The validator rejects duplicate ids and duplicate titles outright, but it cannot see that
two differently worded titles describe the same failure. That judgement is yours.

## New categories

Only when there is genuinely nowhere to put an entry, and when the new category will hold
enough errors to justify a hub page: roughly eight or more. A category is not a tag, it
is an authored guide to debugging a class of error, and a thin one makes the site worse.

Prefer an existing category. Deno and Bun errors live under JavaScript; Kafka under
MessageQueue; Flutter under Dart or Mobile. gRPC earned its own category because the
status codes form a fixed vocabulary with no home in Network, the same way HTTP status
codes and ICMP types do.

A guide needs `title`, `tagline`, `intro`, `howToDebug` (five or six steps, three
minimum) and `tools`. The `intro` and `howToDebug` entries may contain `<strong>`,
`<code>` and `<em>`; escape `&` as `&amp;`. Write the guide as an experienced engineer
explaining how to approach the class of problem, not as a summary of the entries below
it. Read two or three existing guides before writing one.

Category slugs are derived automatically (`C++` becomes `c-plus-plus`, `C#` becomes
`c-sharp`, `CI/CD` becomes `ci-cd`). The build fails on a slug collision.

## Keeping existing entries current

Vendors move their documentation constantly, so links rot faster than the content does:

```bash
npm run check:sources                          # every source URL
npm run check:sources -- --since 2026-09-01    # only recently added entries
```

Only 404 and 410 are real failures. A 403 or 429 is a vendor blocking automated clients
(dev.mysql.com, gnu.org and platform.openai.com all do this) and the page is usually
fine. When a link is dead, find where that page moved and update it; do not delete the
source or swap in a blog post. This check needs network access and is deliberately not
part of `npm run check`.

Also worth doing when asked to refresh the site: correcting entries whose advice has gone
stale because the tool changed, rather than only adding new ones.

## Commands

```bash
npm install                  # jsdom, for the tests
npm run check                # build + validate + test. Run before every commit.
npm run build                # regenerate pages, dataset, sitemap, feed
npm run validate             # data integrity, links, titles, canonicals, JSON-LD
npm test                     # DOM tests against the app and generated pages
npm run check:sources        # link rot in data/errors.json (network)
npm run og                   # regenerate og-image.png (Python + Pillow)
python3 -m http.server 8000  # preview
```

## What the build generates

Everything below is output. Editing any of it by hand will be overwritten by the next
build and will make the diff unreviewable.

| Path | What it is |
| --- | --- |
| `errors/<id>.html` | One page per error: explanation, fix, category guide, related entries, sources |
| `categories/<slug>.html` | One hub per category |
| `categories.html`, `all-errors.html` | Directory and A-Z index |
| `embedded-data.js` | The dataset the search app loads |
| `sitemap.xml`, `feed.xml` | Crawl and subscription surfaces |
| Counts in `index.html`, `manifest.json`, `README.md` | Rewritten in place from the dataset |

Those last three are hand-written files that quote the dataset size in prose. The build
rewrites the numbers and the validator proves none was missed, both driven by
`scripts/counts.mjs`. If you reword the surrounding copy, update the matching rule there
or the build will fail rather than leave a stale figure behind.

`index.html` is hand-written apart from those counts. It contains the search app.

## Things that will fail the build

- A duplicate id or title, an unsafe id, a non-HTTPS source.
- A category with no authored guide, or a guide missing a required field.
- An em or en dash in either data file.
- A broken internal link, a duplicate `<title>` or canonical, a missing `<h1>`,
  invalid JSON-LD.
- A count rule in `scripts/counts.mjs` that no longer matches its file.
- `embedded-data.js` out of step with `data/errors.json`, meaning you forgot to build.

## Committing

Commit the data change and the regenerated output in one commit. A build run on a
different day also rewrites the "Last updated" line in every footer and the `lastmod`
dates in the sitemap; that noise is expected and belongs in the same commit.
