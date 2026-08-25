/*
 * NIP-05 verification (DESIGN §4, §6 "for alice@hns.one").
 *
 *   GET https://<domain>/.well-known/nostr.json?name=<local>
 *   { "names": { "<local>": "<64-hex>" },
 *     "relays": { "<64-hex>": ["wss://relay.hns.one", ...] } }
 *
 * Rules enforced here (from the spec):
 *   - lowercase hex keys, never npub
 *   - the endpoint MUST NOT redirect (redirect: 'error' — a redirect is an
 *     attempt to move the authority elsewhere and is refused)
 *   - CORS is a server concern; irrelevant to a server-side fetch
 *
 * This module NEVER decides HNS control. It only answers "does <local>@<domain>
 * map to this key" — the upgrade to an HNS-native binding happens only if a
 * SEPARATE HNS proof succeeds (resolver.js), honoring the DESIGN §6 invariant.
 */

const HEX64 = /^[0-9a-f]{64}$/

/**
 * @returns {Promise<{ok:boolean, reason?:string, pubkey?:string, relays?:string[]}>}
 */
export async function verifyNip05 (local, domain, { fetchImpl, timeout = 6000 } = {}) {
  const doFetch = fetchImpl || ((...a) => globalThis.fetch(...a))
  const name = String(local).toLowerCase()
  const url = `https://${domain}/.well-known/nostr.json?name=${encodeURIComponent(name)}`
  let res
  try {
    res = await doFetch(url, {
      // NEVER follow a redirect on the NIP-05 endpoint (spec + DESIGN §6 step 3).
      redirect: 'error',
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(timeout)
    })
  } catch (err) {
    return { ok: false, reason: `NIP-05 fetch failed: ${err.message || err}` }
  }
  if (!res.ok) return { ok: false, reason: `NIP-05 HTTP ${res.status}` }

  let json
  try {
    json = await res.json()
  } catch (err) {
    return { ok: false, reason: `NIP-05 bad JSON: ${err.message || err}` }
  }
  const names = json && json.names
  if (!names || typeof names !== 'object') {
    return { ok: false, reason: 'NIP-05 missing names map' }
  }
  const pubkey = names[name]
  if (typeof pubkey !== 'string' || !HEX64.test(pubkey.toLowerCase())) {
    return { ok: false, reason: `NIP-05 has no lowercase-hex key for "${name}"` }
  }
  const pk = pubkey.toLowerCase()
  const relays = []
  const relayMap = json.relays
  if (relayMap && typeof relayMap === 'object' && Array.isArray(relayMap[pk])) {
    for (const r of relayMap[pk]) {
      if (typeof r === 'string' && /^wss?:\/\//i.test(r)) relays.push(r.replace(/\/$/, ''))
    }
  }
  return { ok: true, pubkey: pk, relays }
}
