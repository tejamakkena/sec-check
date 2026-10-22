import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readGitIndex } from '../git-index.js';

const utf8 = s => new TextEncoder().encode(s);

function header(version, count) {
  const h = new DataView(new ArrayBuffer(12));
  h.setUint32(0, 0x44495243);
  h.setUint32(4, version);
  h.setUint32(8, count);
  return new Uint8Array(h.buffer);
}

// 62 bytes of stat data, object id and flags; only the flags matter here.
function fixed(nameLength, extended) {
  const f = new DataView(new ArrayBuffer(extended ? 64 : 62));
  f.setUint16(60, Math.min(nameLength, 0xfff) | (extended ? 0x4000 : 0));
  return new Uint8Array(f.buffer);
}

const join = parts => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};

function indexV2(version, entries) {
  const parts = [header(version, entries.length)];
  for (const { path, extended } of entries) {
    const name = utf8(path);
    const body = join([fixed(name.length, extended), name]);
    parts.push(body, new Uint8Array(8 - (body.length % 8))); // 1 to 8 NULs
  }
  return join(parts);
}

function indexV4(entries) {
  const parts = [header(4, entries.length)];
  let previous = new Uint8Array(0);
  for (const path of entries) {
    const name = utf8(path);
    let common = 0;
    while (common < previous.length && previous[common] === name[common]) common++;
    const strip = previous.length - common;
    assert.ok(strip < 128, 'test helper only writes one-byte varints');
    parts.push(fixed(name.length, false), Uint8Array.of(strip), name.subarray(common), Uint8Array.of(0));
    previous = name;
  }
  return join(parts);
}

const PATHS = ['.env', 'src/App.tsx', 'src/ünïcode.ts', 'supabase/migrations/20250101000000_init.sql', 'web/.env.local'];

test('reads version 2 and 3 indexes, including extended entries', () => {
  assert.deepEqual([...readGitIndex(indexV2(2, PATHS.map(path => ({ path }))))], PATHS);
  const v3 = indexV2(3, PATHS.map((path, i) => ({ path, extended: i % 2 === 1 })));
  assert.deepEqual([...readGitIndex(v3)], PATHS);
});

test('reads prefix-compressed version 4 indexes', () => {
  assert.deepEqual([...readGitIndex(indexV4(PATHS))], PATHS);
});

test('rejects files that are not a supported git index', () => {
  assert.throws(() => readGitIndex(utf8('not an index at all')), /not a git index/);
  assert.throws(() => readGitIndex(header(5, 0)), /unsupported/);
  assert.throws(() => readGitIndex(indexV2(2, [{ path: 'a' }]).subarray(0, 40)));
});
