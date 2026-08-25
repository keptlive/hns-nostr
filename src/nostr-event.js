/*
 * Nostr event integrity — the NATIVE layer of the two-layer trust model
 * (LAW L3). HNS/DNSSEC proves the readable mapping name -> pubkey; THIS proves
 * the canonical object: the event was really signed by that pubkey.
 *
 * An event id is sha256 of the canonical serialization
 *   [0, pubkey, created_at, kind, tags, content]
 * (NIP-01), and the signature is BIP-340 schnorr over that id by the x-only
 * pubkey. A resolver that skipped this would be trusting a relay's word for a
 * profile — exactly the failure this package exists to prevent.
 */

import { schnorr } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha2.js'

const HEX64 = /^[0-9a-f]{64}$/
const HEX128 = /^[0-9a-f]{128}$/

function hexToBytes (hex) {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16)
  return out
}

function bytesToHex (bytes) {
  let hex = ''
  for (const b of bytes) hex += b.toString(16).padStart(2, '0')
  return hex
}

/**
 * Canonical NIP-01 serialization used for the id. JSON.stringify already
 * emits the exact escaping NIP-01 mandates for the common cases; content with
 * control characters is handled by JSON.stringify's \uXXXX escapes.
 */
export function serializeEvent (event) {
  return JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags || [],
    event.content || ''
  ])
}

/** Recompute the event id from its fields. */
export function computeEventId (event) {
  const serialized = new TextEncoder().encode(serializeEvent(event))
  return bytesToHex(sha256(serialized))
}

/**
 * Full structural + cryptographic check of a Nostr event.
 * @returns {{ok:boolean, reason?:string}}
 */
/**
 * Sign an unsigned event in place-ish, returning the complete NIP-01 object.
 *
 * Deliberately produces an ORDINARY event: no HNS kind, no HNS-only tag, no
 * modified id rule. A Handshake name improves how an identity is DISCOVERED
 * and PROVEN; it must never change the bytes, or our users' posts stop being
 * readable on relays that have never heard of Handshake — which is the whole
 * point of the exercise.
 */
export function signEvent (unsigned, secretKey) {
  const key = typeof secretKey === 'string' ? hexToBytes(secretKey) : secretKey
  if (!(key instanceof Uint8Array) || key.length !== 32) {
    throw new Error('secret key must be 32 bytes')
  }
  const event = {
    pubkey: bytesToHex(schnorr.getPublicKey(key)),
    created_at: Math.floor(unsigned.created_at ?? Date.now() / 1000),
    kind: unsigned.kind,
    tags: unsigned.tags || [],
    content: unsigned.content == null ? '' : String(unsigned.content)
  }
  if (!Number.isInteger(event.kind)) throw new Error('kind must be an integer')
  event.id = computeEventId(event)
  event.sig = bytesToHex(schnorr.sign(hexToBytes(event.id), key))
  return event
}

/**
 * The thread root a reply to `parent` belongs under, per NIP-10.
 *
 * Naive version: "the parent's root-marked tag, else the parent itself". That
 * is wrong against half the network, and wrong in the way that hurts — the
 * reply detaches and renders as a new top-level note in everyone else's
 * client:
 *
 *   * A client replying DIRECTLY to a root is told to emit only a `root`
 *     marker. Several emit only a `reply` marker instead, so a parent with a
 *     `reply` tag and no `root` tag is a real and common shape; its `reply`
 *     target IS the thread root. (Snort carries an explicit comment about
 *     this; welshman re-marks the inherited tag as `root` for the same
 *     reason.)
 *   * NDK copies the parent's `e` tags verbatim and appends its own, so an
 *     event can carry TWO `reply` markers. The last one is the true parent;
 *     taking the first resolves to the grandparent.
 *   * Pre-marker events are positional: one `e` tag IS the reply target,
 *     while two or more begin with the root.
 *   * NIP-01's generic `e` shape puts the AUTHOR at index 3, where NIP-10
 *     puts the marker. A 64-hex value there is a pubkey, never a marker.
 */
export function threadRoot (parent) {
  const es = (parent.tags || []).filter((t) => Array.isArray(t) && t[0] === 'e' && HEX64.test(t[1] || ''))
  if (!es.length) return parent.id
  // Index 3 is the marker only when it is not a pubkey.
  const markerOf = (t) => (HEX64.test(t[3] || '') ? '' : String(t[3] || ''))
  const marked = es.filter((t) => ['root', 'reply', 'mention'].includes(markerOf(t)))
  if (marked.length) {
    const last = (marker) => {
      for (let i = marked.length - 1; i >= 0; i--) if (markerOf(marked[i]) === marker) return marked[i][1]
      return null
    }
    // A `reply` with no `root` means the parent was itself a direct reply to
    // the root, and that reply target is the root of this thread.
    return last('root') || last('reply') || parent.id
  }
  // Positional: one tag is the reply target; several begin with the root.
  return es.length === 1 ? es[0][1] : es[0][1]
}

/**
 * A reply, per NIP-10 marked tags.
 *
 * `root` and `reply` markers rather than the deprecated positional form: the
 * positional rules are ambiguous once a thread is more than two deep, and
 * ambiguity here shows up as replies rendering under the wrong parent in
 * other people's clients.
 *
 * A DIRECT reply to a root carries ONE `e` tag, marked `root` — the spec is
 * explicit, and emitting a second tag marked `reply` pointing at the same
 * event is a duplicate that some parsers resolve to the wrong parent.
 *
 * The 5th element is the referenced event's AUTHOR. It is what lets a client
 * that cannot resolve our relay hint go and look for the event on that
 * author's own write relays — the outbox model — so a thread survives our
 * relay being unreachable to a stranger.
 */
export function replyTags (parent, { rootId, rootRelay } = {}) {
  const relay = rootRelay || ''
  const tags = []
  const root = rootId || threadRoot(parent)
  // The root's author, when we can tell: it is the parent's own author for a
  // direct reply, and otherwise whatever the parent recorded for the root.
  const rootAuthor = root === parent.id
    ? parent.pubkey
    : (parent.tags || []).find((t) => t[0] === 'e' && t[1] === root && HEX64.test(t[4] || ''))?.[4] || ''
  tags.push(['e', root, relay, 'root', rootAuthor])
  if (root !== parent.id) tags.push(['e', parent.id, relay, 'reply', parent.pubkey])
  // Mention the author so their client surfaces the reply even if it never
  // sees our relay: `p` tags are how notifications travel between servers.
  // NIP-10: carry the parent's `p` tags forward as well, so everyone already
  // in the conversation stays in it.
  const people = new Set([parent.pubkey])
  for (const t of parent.tags || []) if (t[0] === 'p' && HEX64.test(t[1] || '')) people.add(t[1])
  for (const p of people) tags.push(['p', p])
  return tags
}

export function verifyEvent (event) {
  if (!event || typeof event !== 'object') return { ok: false, reason: 'not an object' }
  if (typeof event.pubkey !== 'string' || !HEX64.test(event.pubkey)) {
    return { ok: false, reason: 'bad pubkey' }
  }
  if (typeof event.id !== 'string' || !HEX64.test(event.id)) {
    return { ok: false, reason: 'bad id' }
  }
  if (typeof event.sig !== 'string' || !HEX128.test(event.sig)) {
    return { ok: false, reason: 'bad sig' }
  }
  if (typeof event.created_at !== 'number' || !Number.isInteger(event.created_at)) {
    return { ok: false, reason: 'bad created_at' }
  }
  if (typeof event.kind !== 'number' || !Number.isInteger(event.kind)) {
    return { ok: false, reason: 'bad kind' }
  }
  if (!Array.isArray(event.tags)) return { ok: false, reason: 'bad tags' }

  const computedId = computeEventId(event)
  if (computedId !== event.id) return { ok: false, reason: 'id mismatch' }

  try {
    const ok = schnorr.verify(hexToBytes(event.sig), hexToBytes(event.id), hexToBytes(event.pubkey))
    return ok ? { ok: true } : { ok: false, reason: 'signature invalid' }
  } catch (err) {
    return { ok: false, reason: `signature error: ${err.message || err}` }
  }
}

/** Parse a kind:0 metadata event's JSON content, or null. */
export function parseProfileContent (event) {
  try {
    const obj = JSON.parse(event.content || '{}')
    return (obj && typeof obj === 'object') ? obj : null
  } catch {
    return null
  }
}

/** NIP-65 kind:10002 -> relay list from `r` tags. */
export function parseRelayList (event) {
  const relays = []
  for (const tag of event.tags || []) {
    if (!Array.isArray(tag) || tag[0] !== 'r' || typeof tag[1] !== 'string') continue
    const url = tag[1]
    const marker = tag[2] // 'read' | 'write' | undefined (both)
    relays.push({ url, read: marker !== 'write', write: marker !== 'read' })
  }
  return relays
}
