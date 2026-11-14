import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SOURCES, MAX_PER_SOURCE, cleanText, safeUrl, tagsFor, parseFeed, parseKev, mergeItems } from '../feeds.js';

const NOW = Date.parse('2026-11-14T12:00:00Z');
const source = id => SOURCES.find(s => s.id === id);
const daysAgo = n => new Date(NOW - n * 86400000).toISOString();

const RSS = `<?xml version="1.0"?><rss version="2.0"><channel>
  <title>Feed title is not an item</title>
  <item>
    <title><![CDATA[Ransomware gang leaks data &amp; demands &#8216;payment&#8217;]]></title>
    <link>https://example.com/story-one?utm_source=rss&amp;id=7</link>
    <pubDate>Fri, 13 Nov 2026 21:32:00 GMT</pubDate>
    <description>&lt;p&gt;A &lt;b&gt;phishing&lt;/b&gt; wave&lt;/p&gt; hit users.</description>
    <media:title>ignored</media:title>
  </item>
  <item>
    <title>No link falls back to the permalink guid</title>
    <link></link>
    <guid isPermaLink="true">https://example.com/two</guid>
    <dc:date>2026-11-12T08:00:00Z</dc:date>
    <description><![CDATA[<p>${'word '.repeat(80)}</p>]]></description>
  </item>
  <item><title>Unsafe link is dropped</title><link>javascript:alert(1)</link><pubDate>Fri, 13 Nov 2026 10:00:00 GMT</pubDate></item>
  <item><title>Bad date is dropped</title><link>https://example.com/x</link><pubDate>someday</pubDate></item>
  <item><title>Future date is clamped</title><link>https://example.com/future</link><pubDate>Mon, 01 Jan 2035 00:00:00 GMT</pubDate></item>
</channel></rss>`;

const ATOM = `<feed xmlns="http://www.w3.org/2005/Atom">
  <link rel="alternate" href="https://www.schneier.com/" />
  <entry>
    <title type="html"><![CDATA[New Zero-Day in VPN Appliances]]></title>
    <link rel="replies" href="https://www.schneier.com/comments" />
    <link rel="alternate" type="text/html" href="https://www.schneier.com/blog/zero-day.html" />
    <updated>2026-11-13T22:00:49Z</updated>
    <published>2026-11-13T22:00:46Z</published>
    <summary type="html">Attackers are &lt;em&gt;actively exploiting&lt;/em&gt; it.</summary>
  </entry>
  <entry>
    <title>Friday Squid Blogging: Squid</title>
    <link href="https://www.schneier.com/blog/squid.html" />
    <updated>2026-11-13T20:00:00Z</updated>
  </entry>
</feed>`;

test('cleanText unwraps CDATA, strips encoded markup and decodes entities', () => {
  assert.equal(cleanText('<![CDATA[<p>Hi &amp; bye</p>]]>'), 'Hi & bye');
  assert.equal(cleanText('&lt;p&gt;It&#x2019;s &quot;fine&quot;&lt;/p&gt;'), 'It’s "fine"');
  assert.equal(cleanText('&bogus; &#0;'), '&bogus; &#0;');
});

test('safeUrl allows only absolute http(s) links', () => {
  assert.equal(safeUrl('https://example.com/a'), 'https://example.com/a');
  assert.equal(safeUrl(' <![CDATA[http://example.com]]> '), 'http://example.com/');
  for (const bad of ['javascript:alert(1)', 'data:text/html,x', '/relative', '', 'not a url']) assert.equal(safeUrl(bad), null);
});

test('parses RSS items', () => {
  const items = parseFeed(RSS, source('therecord'), NOW);
  assert.deepEqual(items.map(i => i.title), [
    'Ransomware gang leaks data & demands ‘payment’',
    'No link falls back to the permalink guid',
    'Future date is clamped',
  ]);
  const [first, second, future] = items;
  assert.equal(first.url, 'https://example.com/story-one?utm_source=rss&id=7');
  assert.equal(first.published, '2026-11-13T21:32:00.000Z');
  assert.equal(first.summary, 'A phishing wave hit users.');
  assert.deepEqual(first.tags, ['breach', 'ransomware', 'scams']);
  assert.equal(second.url, 'https://example.com/two');
  assert.ok(second.summary.length <= 221 && second.summary.endsWith('…'));
  assert.equal(future.published, new Date(NOW).toISOString());
});

test('parses Atom entries, picks the alternate link, and applies source skips', () => {
  const items = parseFeed(ATOM, source('schneier'), NOW);
  assert.equal(items.length, 1);
  assert.equal(items[0].url, 'https://www.schneier.com/blog/zero-day.html');
  assert.equal(items[0].published, '2026-11-13T22:00:46.000Z');
  assert.equal(items[0].summary, 'Attackers are actively exploiting it.');
  const wp = parseFeed('<item><title>T</title><link>https://example.com/t</link><pubDate>Fri, 13 Nov 2026 10:00:00 GMT</pubDate><description>Real text. The post T appeared first on SecurityWeek.</description></item>', source('securityweek'), NOW);
  assert.equal(wp[0].summary, 'Real text.');
  assert.deepEqual(items[0].tags, ['exploited', 'vulnerability']);
});

test('parses recent CISA KEV entries and links to the catalog', () => {
  const kev = {
    vulnerabilities: [
      { cveID: 'CVE-2026-1234', vendorProject: 'Acme', product: 'VPN', vulnerabilityName: 'Acme VPN Auth Bypass', dateAdded: '2026-11-13', shortDescription: 'Lets attackers in.', knownRansomwareCampaignUse: 'Known' },
      { cveID: 'CVE-2020-0001', vulnerabilityName: 'Old', dateAdded: '2020-01-01' },
      { cveID: '<script>', vulnerabilityName: 'Bad id', dateAdded: '2026-11-13' },
    ],
  };
  const items = parseKev(kev, source('cisa-kev'), NOW);
  assert.equal(items.length, 1);
  assert.equal(items[0].title, 'CVE-2026-1234: Acme VPN Auth Bypass');
  assert.equal(items[0].url, 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2026-1234');
  assert.deepEqual(items[0].tags, ['exploited', 'vulnerability', 'ransomware']);
});

test('tags cover the main story types', () => {
  assert.deepEqual(tagsFor('Retailer leaks customer records'), ['breach']);
  assert.deepEqual(tagsFor('Malicious npm package drops infostealer'), ['malware', 'ai']);
  assert.deepEqual(tagsFor('Microsoft patches CVE-2026-1111'), ['vulnerability']);
  assert.deepEqual(tagsFor('Company hires new CISO'), []);
});

test('merge keeps the newest copy, collapses duplicates and ages items out', () => {
  const item = (over) => ({ title: 'Story', url: 'https://example.com/a', source: 'therecord', published: daysAgo(1), summary: '', tags: [], ...over });
  const previous = [
    item({ summary: 'old copy' }),
    item({ title: 'Too old', url: 'https://example.com/old', published: daysAgo(31) }),
    item({ title: 'Unknown source', url: 'https://example.com/u', source: 'nope' }),
    item({ title: 'Bad link', url: 'javascript:alert(1)' }),
    item({ title: 'Friday Squid Blogging: kept from an older run', url: 'https://www.schneier.com/squid', source: 'schneier' }),
  ];
  const fresh = [
    item({ summary: 'new copy', url: 'https://www.example.com/a/?utm_source=rss#top' }),
    item({ title: 'Story!', url: 'https://other.com/b', source: 'bleepingcomputer', published: daysAgo(0.5) }),
    item({ title: 'Newest', url: 'https://example.com/c', published: daysAgo(0) }),
  ];
  const merged = mergeItems(fresh, previous, NOW);
  assert.deepEqual(merged.map(i => [i.title, i.summary]), [['Newest', ''], ['Story', 'new copy']]);
});

test('merge caps each source so one feed cannot crowd out the rest', () => {
  const many = Array.from({ length: MAX_PER_SOURCE + 10 }, (_, n) => ({
    title: `Story ${n}`, url: `https://example.com/${n}`, source: 'thehackernews', published: daysAgo(n / 100), summary: '', tags: [],
  }));
  const merged = mergeItems(many, [], NOW);
  assert.equal(merged.length, MAX_PER_SOURCE);
  assert.equal(merged[0].title, 'Story 0');
});
