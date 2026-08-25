/*
 * Test fixtures & mocks. Events are REAL BIP-340 schnorr signatures (so the
 * resolver's own verifyEvent must pass them); the HNS backend, relay pool, and
 * NIP-05 http are mocked so no chain node, socket, or network is touched.
 */

import { schnorr } from '@noble/curves/secp256k1'
import { computeEventId } from '../src/nostr-event.js'

export function bytesToHex (bytes) {
  let hex = ''
  for (const b of bytes) hex += b.toString(16).padStart(2, '0')
  return hex
}

export function hexToBytes (hex) {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16)
  return out
}

export function makeKeypair () {
  const sk = schnorr.utils.randomPrivateKey()
  const pubkey = bytesToHex(schnorr.getPublicKey(sk))
  return { sk, pubkey }
}

/** A properly-signed Nostr event. */
export function signEvent (kp, { kind, content = '', tags = [], created_at } = {}) {
  const ev = {
    pubkey: kp.pubkey,
    created_at: created_at ?? Math.floor(Date.now() / 1000),
    kind,
    tags,
    content
  }
  ev.id = computeEventId(ev)
  ev.sig = bytesToHex(schnorr.sign(hexToBytes(ev.id), kp.sk))
  return ev
}

export function profileEvent (kp, meta, opts = {}) {
  return signEvent(kp, { kind: 0, content: JSON.stringify(meta), ...opts })
}

export function relayListEvent (kp, urls, opts = {}) {
  const tags = urls.map((u) => ['r', u])
  return signEvent(kp, { kind: 10002, content: '', tags, ...opts })
}

/** Build a _nostr TXT string (may be passed as one or several strings). */
export function nostrTxt ({ pubkey, epoch = 0, relays = ['wss://relay.hns.one'], receipt, extra } = {}) {
  let s = `v=nostr1;pubkey=${pubkey};epoch=${epoch}`
  for (const r of relays) s += `;relay=${r}`
  if (receipt) s += `;receipt=${receipt}`
  if (extra) s += `;${extra}`
  return s
}

/**
 * Mock HNS backend. `names` maps a full HNS name to a verify() result:
 *   { found, txt:[...], proofs:{hns,dnssec}, treeState }
 */
export function mockHns (names = {}) {
  return {
    async verify (name) {
      const n = String(name).toLowerCase().replace(/\.$/, '')
      const tld = n.split('.').pop()
      if (names[n]) return { tld, treeState: 't-mock', ...names[n] }
      return { found: false, txt: [], proofs: { hns: false, dnssec: false }, treeState: 't-mock', tld, reason: 'not found' }
    },
    async treeState () { return 't-mock' }
  }
}

/** Mock relay pool over an in-memory event list. */
export function mockRelays (events = []) {
  const match = (filter, e) =>
    (!filter.authors || filter.authors.includes(e.pubkey)) &&
    (!filter.kinds || filter.kinds.includes(e.kind))
  return {
    events,
    async fetchEvents (filter, relays) { return events.filter((e) => match(filter, e)) },
    async fetchLatest (filter, relays) {
      const m = events.filter((e) => match(filter, e))
      if (!m.length) return null
      m.sort((a, b) => b.created_at - a.created_at)
      return m[0]
    }
  }
}

/**
 * Mock NIP-05 http fetch. `responses` maps "local@domain" -> json body, or the
 * string 'DOWN' to simulate an endpoint that throws (network failure), or
 * 'REDIRECT' to simulate a redirect (rejected by redirect:'error').
 */
export function mockNip05Http (responses = {}) {
  return async (url, opts) => {
    const u = new URL(url)
    const name = u.searchParams.get('name')
    const key = `${name}@${u.hostname}`
    const r = responses[key]
    if (r === 'DOWN') throw new Error('simulated network failure')
    if (r === 'REDIRECT') throw new Error('simulated redirect (redirect:error)')
    if (r === undefined) return { ok: false, status: 404, async json () { return {} } }
    return { ok: true, status: 200, async json () { return r } }
  }
}
