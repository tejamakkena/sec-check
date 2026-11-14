#!/usr/bin/env node
// Builds news.json from the sources in news/feeds.js. The GitHub Pages
// workflow runs this on every deploy and on a schedule; run it locally to
// preview news.html.
//
//   node news/fetch.js [--out news.json] [--previous <url or file>]
//
// --previous seeds the merge with the last published news.json, so stories
// survive when a source is briefly down.

import { readFileSync, writeFileSync } from 'node:fs';
import { SOURCES, CATEGORIES, parseFeed, parseKev, mergeItems } from './feeds.js';

const USER_AGENT = 'sec-check-news/1.0 (+https://github.com/tejamakkena/sec-check)';
const TIMEOUT_MS = 20000;

function parseArgs(argv) {
  const opts = { out: 'news.json', previous: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--out') opts.out = argv[++i];
    else if (argv[i] === '--previous') opts.previous = argv[++i];
    else throw new Error(`Unknown argument: ${argv[i]}`);
  }
  return opts;
}

async function get(url) {
  const res = await fetch(url, {
    headers: { 'user-agent': USER_AGENT, accept: 'application/rss+xml, application/atom+xml, application/xml, application/json, text/xml' },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}

async function loadPrevious(location) {
  if (!location) return [];
  try {
    const text = /^https?:\/\//.test(location) ? await get(location) : readFileSync(location, 'utf8');
    const items = JSON.parse(text).items;
    return Array.isArray(items) ? items.filter(i => i && typeof i === 'object') : [];
  } catch (err) {
    console.warn(`previous news.json not loaded (${err.message}); starting fresh`);
    return [];
  }
}

const opts = parseArgs(process.argv.slice(2));
const now = Date.now();
const previous = await loadPrevious(opts.previous);

const results = await Promise.all(SOURCES.map(async source => {
  try {
    const body = await get(source.feed);
    const items = source.format === 'kev' ? parseKev(JSON.parse(body), source, now) : parseFeed(body, source, now);
    console.log(`ok    ${source.id}: ${items.length} items`);
    return { source, items, ok: true };
  } catch (err) {
    console.warn(`fail  ${source.id}: ${err.message}`);
    return { source, items: [], ok: false };
  }
}));

const items = mergeItems(results.flatMap(r => r.items), previous, now);
const news = {
  generated: new Date(now).toISOString(),
  categories: CATEGORIES.map(({ id, label }) => ({ id, label })),
  sources: results.map(({ source, ok }) => ({
    id: source.id, name: source.name, site: source.site, ok,
    count: items.filter(i => i.source === source.id).length,
  })),
  items,
};
writeFileSync(opts.out, `${JSON.stringify(news, null, 1)}\n`);

const working = results.filter(r => r.ok).length;
console.log(`wrote ${opts.out}: ${items.length} items, ${working}/${SOURCES.length} sources reachable`);
if (working === 0) process.exit(1);
