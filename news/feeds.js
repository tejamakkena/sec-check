// Security news: sources, feed parsing and merging.
//
// Pure functions only. news/fetch.js does the network part and writes
// news.json; news.html renders it. Every item links to the original story on
// the source's own site. We keep only the headline, date and the short
// excerpt the source publishes in its feed.

export const MAX_AGE_DAYS = 30;
export const MAX_PER_SOURCE = 40;
export const MAX_ITEMS = 400;
const EXCERPT_CHARS = 220;

export const SOURCES = [
  { id: 'cisa-kev', name: 'CISA: Known Exploited Vulnerabilities', site: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', feed: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', format: 'kev' },
  { id: 'ncsc', name: 'NCSC (UK)', site: 'https://www.ncsc.gov.uk/', feed: 'https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml' },
  { id: 'bleepingcomputer', name: 'BleepingComputer', site: 'https://www.bleepingcomputer.com/', feed: 'https://www.bleepingcomputer.com/feed/' },
  { id: 'thehackernews', name: 'The Hacker News', site: 'https://thehackernews.com/', feed: 'https://feeds.feedburner.com/TheHackersNews' },
  { id: 'securityweek', name: 'SecurityWeek', site: 'https://www.securityweek.com/', feed: 'https://www.securityweek.com/feed/' },
  { id: 'therecord', name: 'The Record', site: 'https://therecord.media/', feed: 'https://therecord.media/feed' },
  { id: 'darkreading', name: 'Dark Reading', site: 'https://www.darkreading.com/', feed: 'https://www.darkreading.com/rss.xml' },
  { id: 'krebs', name: 'Krebs on Security', site: 'https://krebsonsecurity.com/', feed: 'https://krebsonsecurity.com/feed/' },
  { id: 'schneier', name: 'Schneier on Security', site: 'https://www.schneier.com/', feed: 'https://www.schneier.com/feed/atom/', skip: /^Friday Squid Blogging/i },
  { id: 'troyhunt', name: 'Troy Hunt', site: 'https://www.troyhunt.com/', feed: 'https://feeds.feedburner.com/TroyHunt' },
  { id: 'malwarebytes', name: 'Malwarebytes Labs', site: 'https://www.malwarebytes.com/blog', feed: 'https://www.malwarebytes.com/blog/feed/index.xml' },
  { id: 'welivesecurity', name: 'WeLiveSecurity (ESET)', site: 'https://www.welivesecurity.com/', feed: 'https://www.welivesecurity.com/en/rss/feed/' },
  { id: 'unit42', name: 'Unit 42 (Palo Alto Networks)', site: 'https://unit42.paloaltonetworks.com/', feed: 'https://unit42.paloaltonetworks.com/feed/' },
];

// Keyword tags, matched against the headline and excerpt. An item can have
// several; the page filters on them.
export const CATEGORIES = [
  { id: 'exploited', label: 'Actively exploited', re: /actively exploit|exploited in the wild|zero[- ]day|0-day|under attack/i },
  { id: 'breach', label: 'Breaches & leaks', re: /breach|\bleak(?:s|ed)?\b|stolen data|exposed data|hacked|compromised/i },
  { id: 'ransomware', label: 'Ransomware', re: /ransomware|extortion/i },
  { id: 'malware', label: 'Malware', re: /malware|trojan|infostealer|stealer|botnet|backdoor|spyware|\brat\b|implant/i },
  { id: 'scams', label: 'Scams & phishing', re: /phish|scam|fraud|smishing|vishing|social engineering|deepfake|sextortion/i },
  { id: 'ai', label: 'AI & supply chain', re: /\bai\b|artificial intelligence|\bllms?\b|chatgpt|prompt injection|supply[- ]chain|\bnpm\b|pypi|malicious package/i },
  { id: 'vulnerability', label: 'Vulnerabilities & patches', re: /\bcve-\d{4}-\d+|vulnerab|patch|security update|flaw|exploit/i },
];

// ── Text helpers ─────────────────────────────────────────────────────────

const NAMED_ENTITIES = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', ndash: '–', mdash: '—',
  lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”', hellip: '…', bull: '•', copy: '©', reg: '®', trade: '™',
};

function decodeEntities(text) {
  return text.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (match, code) => {
    if (code[0] === '#') {
      const n = code[1].toLowerCase() === 'x' ? parseInt(code.slice(2), 16) : parseInt(code.slice(1), 10);
      return n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : match;
    }
    return NAMED_ENTITIES[code.toLowerCase()] ?? match;
  });
}

/** Feed text (maybe CDATA, entity-encoded HTML) to plain text. */
export function cleanText(raw) {
  if (!raw) return '';
  const unwrapped = raw.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1');
  // Decode first so entity-encoded markup (&lt;p&gt;) is stripped too.
  const stripped = decodeEntities(unwrapped).replace(/<[^>]*>/g, ' ');
  return decodeEntities(stripped).replace(/\s+/g, ' ').trim();
}

function excerpt(raw) {
  // Drop the WordPress feed footer: "The post <title> appeared first on <site>."
  const footer = raw.lastIndexOf('The post ');
  const text = footer !== -1 && raw.includes(' appeared first on ', footer) ? raw.slice(0, footer).trimEnd() : raw;
  if (text.length <= EXCERPT_CHARS) return text;
  const cut = text.slice(0, EXCERPT_CHARS);
  return `${cut.slice(0, cut.lastIndexOf(' ') > 0 ? cut.lastIndexOf(' ') : EXCERPT_CHARS)}…`;
}

/** Only absolute http(s) links ever reach the page. */
export function safeUrl(raw) {
  try {
    const url = new URL(cleanText(raw));
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : null;
  } catch {
    return null;
  }
}

function toIso(raw, now) {
  const time = Date.parse(cleanText(raw));
  if (Number.isNaN(time)) return null;
  return new Date(Math.min(time, now)).toISOString(); // no items from the future
}

export function tagsFor(text) {
  return CATEGORIES.filter(c => c.re.test(text)).map(c => c.id);
}

// ── Parsing ──────────────────────────────────────────────────────────────

function tagText(block, name) {
  const match = new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, 'i').exec(block);
  return match ? match[1] : '';
}

function atomLink(block) {
  for (const [tag] of block.matchAll(/<link\b[^>]*>/gi)) {
    const rel = /\brel\s*=\s*["']([^"']*)["']/i.exec(tag)?.[1] || 'alternate';
    const href = /\bhref\s*=\s*["']([^"']*)["']/i.exec(tag)?.[1];
    if (rel === 'alternate' && href) return href;
  }
  return '';
}

function makeItem(source, { title, url, published, summary }, extraTags = []) {
  const cleanTitle = cleanText(title);
  const link = safeUrl(url);
  if (!cleanTitle || !link || !published || source.skip?.test(cleanTitle)) return null;
  const cleanSummary = excerpt(cleanText(summary));
  const tags = [...new Set([...extraTags, ...tagsFor(`${cleanTitle} ${cleanSummary}`)])];
  return { title: cleanTitle, url: link, source: source.id, published, summary: cleanSummary, tags };
}

/** Parse an RSS 2.0 or Atom document into news items. */
export function parseFeed(xml, source, now = Date.now()) {
  const items = [];
  for (const [, block] of xml.matchAll(/<item\b[^>]*>([\s\S]*?)<\/item>/gi)) {
    let url = tagText(block, 'link');
    if (!cleanText(url)) url = tagText(block, 'guid');
    items.push(makeItem(source, {
      title: tagText(block, 'title'),
      url,
      published: toIso(tagText(block, 'pubDate') || tagText(block, 'dc:date'), now),
      summary: tagText(block, 'description'),
    }));
  }
  for (const [, block] of xml.matchAll(/<entry\b[^>]*>([\s\S]*?)<\/entry>/gi)) {
    items.push(makeItem(source, {
      title: tagText(block, 'title'),
      url: atomLink(block),
      published: toIso(tagText(block, 'published') || tagText(block, 'updated'), now),
      summary: tagText(block, 'summary') || tagText(block, 'content'),
    }));
  }
  return items.filter(Boolean);
}

/** Parse CISA's Known Exploited Vulnerabilities JSON into news items. */
export function parseKev(json, source, now = Date.now()) {
  const cutoff = now - MAX_AGE_DAYS * 86400000;
  return (json.vulnerabilities || [])
    .filter(v => /^CVE-\d{4}-\d+$/.test(v.cveID || '') && Date.parse(v.dateAdded) >= cutoff)
    .map(v => makeItem(source, {
      title: `${v.cveID}: ${v.vulnerabilityName || `${v.vendorProject} ${v.product}`}`,
      url: `${source.site}?search_api_fulltext=${encodeURIComponent(v.cveID)}`,
      published: toIso(v.dateAdded, now),
      summary: v.shortDescription || '',
    }, ['exploited', 'vulnerability', ...(v.knownRansomwareCampaignUse === 'Known' ? ['ransomware'] : [])]))
    .filter(Boolean);
}

// ── Merging ──────────────────────────────────────────────────────────────

function urlKey(url) {
  const u = new URL(url);
  for (const key of [...u.searchParams.keys()]) if (/^utm_|^(fbclid|gclid|ref)$/.test(key)) u.searchParams.delete(key);
  u.hash = '';
  return `${u.host.replace(/^www\./, '')}${u.pathname.replace(/\/$/, '')}${u.search}`.toLowerCase();
}

const titleKey = title => title.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();

/**
 * Combine freshly fetched items with the previous news.json items: fresh
 * copies win, duplicates (same link or same headline) collapse to the
 * earliest report, old items age out, and no source can crowd out the rest.
 */
export function mergeItems(fresh, previous = [], now = Date.now()) {
  const cutoff = now - MAX_AGE_DAYS * 86400000;
  const sources = new Map(SOURCES.map(s => [s.id, s]));
  const byUrl = new Map();
  for (const item of [...previous, ...fresh]) {
    const source = sources.get(item.source);
    if (!source || !safeUrl(item.url) || !(Date.parse(item.published) >= cutoff)) continue;
    if (typeof item.title !== 'string' || source.skip?.test(item.title)) continue;
    byUrl.set(urlKey(item.url), item);
  }
  const sorted = [...byUrl.values()].sort((a, b) => a.published.localeCompare(b.published));
  const seenTitles = new Set();
  const perSource = new Map();
  const kept = [];
  for (const item of sorted) {
    const key = titleKey(item.title);
    if (seenTitles.has(key)) continue;
    seenTitles.add(key);
    kept.push(item);
  }
  kept.reverse(); // newest first
  return kept.filter(item => {
    const n = (perSource.get(item.source) || 0) + 1;
    perSource.set(item.source, n);
    return n <= MAX_PER_SOURCE;
  }).slice(0, MAX_ITEMS);
}
