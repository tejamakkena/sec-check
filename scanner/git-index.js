// Minimal reader for git's index file (.git/index), versions 2 to 4. Returns
// the set of tracked paths. Format: git's Documentation/gitformat-index.txt.
//
// sec-check reads the index itself rather than running git, because git
// honours the scanned repository's own config (core.fsmonitor and friends),
// which would let an untrusted project run commands during a scan.

const SIGNATURE = 0x44495243; // "DIRC"
const ENTRY_FIXED_BYTES = 62;
const EXTENDED_FLAG = 0x4000;

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

/** @param {Uint8Array} bytes contents of .git/index */
export function readGitIndex(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint32(0) !== SIGNATURE) throw new Error('not a git index');
  const version = view.getUint32(4);
  if (version < 2 || version > 4) throw new Error(`unsupported git index version ${version}`);
  const count = view.getUint32(8);
  const decoder = new TextDecoder();
  const paths = new Set();
  let offset = 12;
  let previous = new Uint8Array(0);

  for (let i = 0; i < count; i++) {
    const start = offset;
    const flags = view.getUint16(offset + ENTRY_FIXED_BYTES - 2);
    offset += ENTRY_FIXED_BYTES;
    if (version >= 3 && flags & EXTENDED_FLAG) offset += 2;

    let name;
    if (version === 4) {
      // Prefix-compressed: a varint count of bytes to drop from the previous
      // path, then the NUL-terminated suffix. No padding.
      let c = bytes[offset++];
      let strip = c & 0x7f;
      while (c & 0x80) {
        c = bytes[offset++];
        strip = ((strip + 1) << 7) + (c & 0x7f);
      }
      const end = bytes.indexOf(0, offset);
      name = concat(previous.subarray(0, previous.length - strip), bytes.subarray(offset, end));
      offset = end + 1;
    } else {
      // NUL-terminated and padded with 1 to 8 NULs to a multiple of 8 bytes.
      const end = bytes.indexOf(0, offset);
      name = bytes.subarray(offset, end);
      offset = start + ((end - start + 8) & ~7);
    }
    if (offset > bytes.length) throw new Error('truncated git index');
    paths.add(decoder.decode(name));
    previous = name;
  }
  return paths;
}
