/*
 * The HNS-native `_nostr` record (DESIGN §2) — a Wildroot/HNS convention,
 * NOT an existing NIP:
 *
 *   _nostr.alice.exist TXT
 *   "v=nostr1;pubkey=<64-hex>;epoch=7;relay=wss://social.hns.one"
 *
 * Extra relay URLs go in additional TXT strings (their own `relay=...`, or a
 * bare wss URL). A single logical record MAY be split across several TXT
 * strings by the authoritative server; we merge every string of `_nostr.<name>`.
 *
 * Managed-SLD (DESIGN §2 caveat, INF-4): a `receipt=` field references the
 * owner-signed assignment attestation. When present the name is treated as
 * managed and the resolver requires the reciprocal kind:0 (mutual binding) as
 * the only complete state — DNSSEC alone only proves HNS.ONE *published* the
 * record, not that the SLD customer approved it.
 */

const HEX64 = /^[0-9a-f]{64}$/

/**
 * Parse the merged TXT strings of `_nostr.<name>`.
 * @param {string[]} txtStrings
 * @returns {{ok:boolean, reason?:string, version?:string, pubkey?:string,
 *   epoch?:number, relays?:string[], receipt?:string, managed?:boolean,
 *   assignedBy?:string}}
 */
export function parseNostrRecord (txtStrings) {
  if (!Array.isArray(txtStrings) || !txtStrings.length) {
    return { ok: false, reason: 'no _nostr TXT record' }
  }

  let version = null
  let pubkey = null
  let epoch = null
  let receipt = null
  let assignedBy = null
  const relays = []

  // Fields may be spread across several TXT strings; each string is a set of
  // `;`-separated key=value pairs (plus bare wss:// relay URLs).
  for (const raw of txtStrings) {
    const str = String(raw).trim()
    if (!str) continue
    for (const partRaw of str.split(';')) {
      const part = partRaw.trim()
      if (!part) continue
      const eq = part.indexOf('=')
      if (eq === -1) {
        // A bare token: accept a relay URL, ignore anything else.
        if (/^wss?:\/\//i.test(part)) relays.push(part)
        continue
      }
      const key = part.slice(0, eq).trim().toLowerCase()
      const value = part.slice(eq + 1).trim()
      switch (key) {
        case 'v': version = value; break
        case 'pubkey': pubkey = value.toLowerCase(); break
        case 'epoch': epoch = value; break
        case 'relay': if (value) relays.push(value); break
        case 'receipt': receipt = value; break
        case 'assignedby': assignedBy = value.toLowerCase(); break
        default: break // forward-compat: ignore unknown fields
      }
    }
  }

  if (version !== 'nostr1') {
    return { ok: false, reason: `unsupported record version ${version || '(none)'}` }
  }
  if (!pubkey || !HEX64.test(pubkey)) {
    return { ok: false, reason: 'missing or malformed pubkey (need 64-hex, lowercase)' }
  }
  const epochCheck = validateEpoch(epoch)
  if (!epochCheck.ok) return { ok: false, reason: epochCheck.reason }

  // De-dupe relays, keep only ws(s) URLs, preserve order.
  const seen = new Set()
  const cleanRelays = []
  for (const r of relays) {
    if (!/^wss?:\/\//i.test(r)) continue
    const u = r.replace(/\/$/, '')
    if (seen.has(u)) continue
    seen.add(u)
    cleanRelays.push(u)
  }

  return {
    ok: true,
    version,
    pubkey,
    epoch: epochCheck.epoch,
    relays: cleanRelays,
    receipt,
    assignedBy,
    managed: !!receipt
  }
}

/**
 * Ownership-epoch validation (DESIGN §6 step 4, §9; LAW L4). The epoch must be
 * a non-negative integer. It keys the resolver cache and drives the historical
 * vs current distinction on transfer.
 * @param {string|number} epoch
 * @param {object} [opts]
 * @param {number} [opts.expected]  a known-current epoch (from a registry /
 *   panel). When supplied it MUST match, else the binding is stale.
 */
export function validateEpoch (epoch, { expected } = {}) {
  if (epoch === null || epoch === undefined || epoch === '') {
    return { ok: false, reason: 'record has no epoch' }
  }
  const n = Number(epoch)
  if (!Number.isInteger(n) || n < 0) {
    return { ok: false, reason: `epoch must be a non-negative integer, got ${epoch}` }
  }
  if (expected !== undefined && expected !== null && n !== Number(expected)) {
    return { ok: false, reason: `epoch ${n} does not match expected ${expected}`, epoch: n, stale: true }
  }
  return { ok: true, epoch: n }
}
