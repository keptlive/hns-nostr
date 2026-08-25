/*
 * The HNS -> Nostr resolver (DESIGN §5, §6). This is the embeddable centerpiece
 * Wildroot calls (BR-7) and the CLI/service wraps (RES-1). It is DEPENDENCY-
 * INJECTED — an `hns` backend (real SPV chain proof via browser/src/hns, or a
 * mock), a `relays` pool, and a NIP-05 `http` fetch — so the same object runs
 * embedded in the browser, as a service, or under unit tests with fixtures.
 *
 * Two-layer trust (LAW L3), enforced end to end:
 *   HNS/DNSSEC  proves the readable mapping   name  -> pubkey  (proofs.hns/.dnssec)
 *   Nostr sig   proves the canonical object   pubkey -> name   (proofs.nostrAcknowledgement)
 *
 * The two DESIGN §6 invariants are load-bearing and tested:
 *   (1) NIP-05 failure MUST NOT invalidate a valid HNS-native binding.
 *   (2) A valid alice@hns.one MUST NEVER be reported as HNS control
 *       (proofs.hns stays false unless the HNS proof itself succeeds).
 */

import { classifyInput } from './input.js'
import { parseNostrRecord, validateEpoch } from './record.js'
import { parseProfileContent, parseRelayList } from './nostr-event.js'
import { verifyNip05 } from './nip05.js'
import { encodeNpub, encodeNprofile } from './nip19.js'
import { ResolverCache } from './cache.js'

const BINDING = {
  MUTUAL: 'mutual',            // HNS/DNSSEC record and signed kind:0 agree (complete)
  HNS_CONTROL: 'hns-control',  // valid HNS/DNSSEC record, no matching kind:0 (yet)
  NIP05: 'nip05-compatible',   // only alice@hns.one resolves to the key
  NONE: 'none'
}

function normName (s) {
  return String(s || '').toLowerCase().replace(/\.$/, '').trim()
}

export class NostrResolver {
  constructor ({
    hns,
    relays,
    http,
    nip05Domains = ['hns.one'],
    // social.hns.one is our canonical relay: `<label>.hns.one` is the proxy
    // address for the Handshake name `<label>`, and `social` is an ICANN root
    // name — never claimable or auctionable — so it is ours by construction and
    // never expires. Public relays follow so resolution still works if it is
    // briefly down. NEVER default to a bare Handshake label we don't own — the
    // old `wss://relay.hns.one` was a stranger's on-chain name.
    defaultRelays = ['wss://social.hns.one', 'wss://relay.damus.io', 'wss://nos.lol'],
    cache,
    epochOracle
  } = {}) {
    if (!hns || typeof hns.verify !== 'function') {
      throw new Error('NostrResolver requires an `hns` backend with verify(name)')
    }
    this.hns = hns
    this.relays = relays
    this.http = http
    this.nip05Domains = nip05Domains
    this.defaultRelays = defaultRelays
    this.cache = cache || new ResolverCache()
    // Optional: (hnsName) => expected current epoch (e.g. from a registry).
    this.epochOracle = epochOracle
  }

  async resolve (input) {
    const cls = classifyInput(input, { nip05Domains: this.nip05Domains })
    switch (cls.form) {
      case 'npub':
      case 'nprofile':
        return this._resolveByPubkey(cls.pubkeyHex, {
          relayHints: cls.relays || [], input, form: cls.form
        })
      case 'hns':
        return this._resolveHnsNative(cls.hnsName, { input, displayName: cls.displayName })
      case 'nip05':
        return this._resolveNip05(cls.local, cls.domain, { input })
      default:
        throw new Error(`unhandled input form ${cls.form}`)
    }
  }

  // ---- HNS-native path (alice.exist / _@alice.exist) — DESIGN §6 ------------

  async _resolveHnsNative (hnsName, { input } = {}) {
    hnsName = normName(hnsName)
    const warnings = []
    // Steps 1-4: SPV root proof + delegation + DNSSEC + read _nostr TXT.
    const hv = await this.hns.verify(hnsName)
    if (!hv.found) {
      const err = new Error(`no HNS-native Nostr identity for ${hnsName}: ${hv.reason || 'not found'}`)
      err.code = hv.dnssecFail ? 'DNSSEC_FAIL' : 'NO_RECORD'
      err.hns = hv
      throw err
    }
    const rec = parseNostrRecord(hv.txt)
    if (!rec.ok) {
      const err = new Error(`malformed _nostr record for ${hnsName}: ${rec.reason}`)
      err.code = 'BAD_RECORD'
      throw err
    }
    // Step 4 cont.: ownership-epoch validation (LAW L4).
    const expected = this.epochOracle ? await this.epochOracle(hnsName) : undefined
    const epochCheck = validateEpoch(rec.epoch, { expected })
    if (!epochCheck.ok && epochCheck.stale) {
      warnings.push(`ownership epoch ${rec.epoch} is stale (expected ${expected}); binding shown as historical`)
    }

    // Cache check keyed by name + epoch + verified tree state (DESIGN §9).
    const cached = this.cache.get(hnsName, rec.epoch, hv.treeState)
    if (cached) return cached

    const proofs = { hns: !!hv.proofs.hns, dnssec: !!hv.proofs.dnssec, nostrAcknowledgement: false, nip05: false }
    if (!proofs.hns) warnings.push('HNS chain proof unavailable (SPV node not synced) — mapping read but not chain-verified')

    // Steps 5-6: hex pubkey + relay hints, then fetch the latest signed kind:0.
    const relayHints = this._relaySet(rec.relays)
    const profile = await this._fetchProfile(rec.pubkey, relayHints)
    let nip05Claim = null
    if (profile) {
      const content = parseProfileContent(profile.event) || {}
      // Step 7: confirm the signed profile's `hns` claim == this name.
      if (normName(content.hns) === hnsName) {
        proofs.nostrAcknowledgement = true
      } else if (content.hns) {
        warnings.push(`kind:0 hns claim "${content.hns}" does not match ${hnsName}`)
      } else {
        warnings.push('kind:0 profile does not carry an hns claim (no reciprocal binding)')
      }
      if (typeof content.nip05 === 'string') nip05Claim = content.nip05
    } else {
      warnings.push('no signed kind:0 profile found on the queried relays')
    }

    // Step 8: OPTIONAL NIP-05 cross-check. INVARIANT (1): its failure must not
    // invalidate the HNS binding — it only sets proofs.nip05.
    let nip05Str = null
    const nip05Target = this._nip05Target(nip05Claim, hnsName)
    if (nip05Target) {
      nip05Str = `${nip05Target.local}@${nip05Target.domain}`
      const n = await verifyNip05(nip05Target.local, nip05Target.domain, { fetchImpl: this.http })
      if (n.ok && n.pubkey === rec.pubkey) {
        proofs.nip05 = true
      } else if (n.ok) {
        warnings.push(`NIP-05 ${nip05Str} resolves to a different key — not counted`)
      } else {
        warnings.push(`NIP-05 cross-check skipped/failed: ${n.reason}`)
      }
    }

    // Step 9: NIP-65 relay list.
    const nip65 = await this._fetchRelayList(rec.pubkey, relayHints)
    const relays = this._mergeRelays(rec.relays, nip65, profile)

    const binding = this._binding(proofs)
    const managed = !!rec.managed
    if (managed && binding !== BINDING.MUTUAL) {
      warnings.push('managed SLD: only a confirmed mutual binding (owner-signed kind:0) is complete — DNSSEC alone proves publication, not the owner\'s approval')
    }
    const complete = binding === BINDING.MUTUAL || (!managed && binding === BINDING.HNS_CONTROL)

    const result = this._build({
      pubkeyHex: rec.pubkey,
      hnsName,
      nip05: proofs.nip05 ? nip05Str : (nip05Str || null),
      relays,
      epoch: rec.epoch,
      proofs,
      binding,
      managed,
      complete,
      historical: !!(epochCheck.stale),
      warnings,
      resolutionPath: 'hns-native',
      input
    })
    if (!result.historical) this.cache.set(hnsName, rec.epoch, hv.treeState, result)
    return result
  }

  // ---- NIP-05 path (alice@hns.one) — DESIGN §6 ------------------------------

  async _resolveNip05 (local, domain, { input } = {}) {
    const warnings = []
    // Steps 1-4: fetch NIP-05 endpoint over ICANN https, no redirects.
    const n = await verifyNip05(local, domain, { fetchImpl: this.http })
    if (!n.ok) {
      const err = new Error(`NIP-05 ${local}@${domain} did not resolve: ${n.reason}`)
      err.code = 'NIP05_FAIL'
      throw err
    }
    const pubkey = n.pubkey
    const proofs = { hns: false, dnssec: false, nostrAcknowledgement: false, nip05: true }
    const nip05Str = `${local}@${domain}`

    // Step 5-6: fetch kind:0 and confirm it claims the same nip05.
    const relayHints = this._relaySet(n.relays)
    const profile = await this._fetchProfile(pubkey, relayHints)
    let hnsClaim = null
    if (profile) {
      const content = parseProfileContent(profile.event) || {}
      if (typeof content.nip05 === 'string' &&
          content.nip05.toLowerCase() === nip05Str.toLowerCase()) {
        proofs.nostrAcknowledgement = true
      } else if (content.nip05) {
        warnings.push(`kind:0 nip05 claim "${content.nip05}" does not match ${nip05Str}`)
      }
      if (typeof content.hns === 'string') hnsClaim = normName(content.hns)
    } else {
      warnings.push('no signed kind:0 profile found on the queried relays')
    }

    // Step 7: upgrade to the HNS-native binding ONLY if a SEPARATE HNS proof
    // succeeds. INVARIANT (2): proofs.hns stays false unless it does.
    let hnsName = null
    let epoch = null
    let binding = BINDING.NIP05
    let managed = false
    let treeState = null
    let historical = false
    if (hnsClaim) {
      const upgrade = await this._verifyHnsBinding(hnsClaim, pubkey)
      if (upgrade.verified) {
        proofs.hns = upgrade.proofs.hns
        proofs.dnssec = upgrade.proofs.dnssec
        hnsName = hnsClaim
        epoch = upgrade.epoch
        managed = upgrade.managed
        treeState = upgrade.treeState
        // The kind:0 that claimed the nip05 also carries the hns claim; if the
        // HNS record binds this key, that IS the reciprocal acknowledgement.
        if (proofs.hns) {
          proofs.nostrAcknowledgement = true
          binding = BINDING.MUTUAL
        }
      } else {
        warnings.push(`kind:0 claims hns "${hnsClaim}" but the HNS record does not bind this key (${upgrade.reason}) — NOT upgraded to HNS control`)
      }
    }

    const nip65 = await this._fetchRelayList(pubkey, relayHints)
    const relays = this._mergeRelays(n.relays, nip65, profile)
    const complete = binding === BINDING.MUTUAL

    const result = this._build({
      pubkeyHex: pubkey,
      hnsName,
      nip05: nip05Str,
      relays,
      epoch,
      proofs,
      binding,
      managed,
      complete,
      historical,
      warnings,
      resolutionPath: 'nip05',
      input
    })
    if (hnsName && epoch !== null && !historical) this.cache.set(hnsName, epoch, treeState, result)
    return result
  }

  // ---- Cryptographic-id path (npub / nprofile) ------------------------------

  async _resolveByPubkey (pubkeyHex, { relayHints = [], input, form } = {}) {
    const warnings = []
    const proofs = { hns: false, dnssec: false, nostrAcknowledgement: false, nip05: false }
    const hints = this._relaySet(relayHints)
    const profile = await this._fetchProfile(pubkeyHex, hints)
    let hnsClaim = null
    let nip05Claim = null
    if (profile) {
      const content = parseProfileContent(profile.event) || {}
      if (typeof content.hns === 'string') hnsClaim = normName(content.hns)
      if (typeof content.nip05 === 'string') nip05Claim = content.nip05
    } else {
      warnings.push('no signed kind:0 profile found on the queried relays')
    }

    let hnsName = null
    let epoch = null
    let managed = false
    let treeState = null
    let binding = BINDING.NONE
    // The profile's hns claim is only honored if the HNS record actually binds
    // this key (two-layer, LAW L3): pubkey -> name from the sig, name -> pubkey
    // from the chain. Both or neither.
    if (hnsClaim) {
      const b = await this._verifyHnsBinding(hnsClaim, pubkeyHex)
      if (b.verified) {
        proofs.hns = b.proofs.hns
        proofs.dnssec = b.proofs.dnssec
        proofs.nostrAcknowledgement = true
        hnsName = hnsClaim
        epoch = b.epoch
        managed = b.managed
        treeState = b.treeState
        binding = proofs.hns ? BINDING.MUTUAL : BINDING.NONE
      } else {
        warnings.push(`kind:0 claims hns "${hnsClaim}" but the HNS record does not bind this key (${b.reason})`)
      }
    }

    // NIP-05 cross-check from the profile's own nip05 claim, if any.
    let nip05Str = null
    const target = this._nip05Target(nip05Claim, hnsName)
    if (target) {
      nip05Str = `${target.local}@${target.domain}`
      const n = await verifyNip05(target.local, target.domain, { fetchImpl: this.http })
      if (n.ok && n.pubkey === pubkeyHex) {
        proofs.nip05 = true
        if (binding === BINDING.NONE) binding = BINDING.NIP05
      } else if (n.ok) {
        warnings.push(`NIP-05 ${nip05Str} resolves to a different key — not counted`)
      }
    }

    const nip65 = await this._fetchRelayList(pubkeyHex, hints)
    const relays = this._mergeRelays(relayHints, nip65, profile)
    const complete = binding === BINDING.MUTUAL

    return this._build({
      pubkeyHex,
      hnsName,
      nip05: proofs.nip05 ? nip05Str : null,
      relays,
      epoch,
      proofs,
      binding,
      managed,
      complete,
      historical: false,
      warnings,
      resolutionPath: form,
      input
    })
  }

  // ---- Shared helpers -------------------------------------------------------

  /** Verify an HNS record binds a specific key (used by the upgrade paths). */
  async _verifyHnsBinding (hnsName, pubkeyHex) {
    hnsName = normName(hnsName)
    let hv
    try {
      hv = await this.hns.verify(hnsName)
    } catch (err) {
      return { verified: false, reason: `HNS verify error: ${err.message || err}`, proofs: { hns: false, dnssec: false } }
    }
    if (!hv.found) return { verified: false, reason: hv.reason || 'no _nostr record', proofs: { hns: false, dnssec: false } }
    const rec = parseNostrRecord(hv.txt)
    if (!rec.ok) return { verified: false, reason: rec.reason, proofs: { hns: false, dnssec: false } }
    if (rec.pubkey !== pubkeyHex) {
      return { verified: false, reason: 'HNS record binds a different key', proofs: { hns: false, dnssec: false } }
    }
    return {
      verified: true,
      proofs: { hns: !!hv.proofs.hns, dnssec: !!hv.proofs.dnssec },
      epoch: rec.epoch,
      managed: !!rec.managed,
      treeState: hv.treeState,
      relays: rec.relays
    }
  }

  async _fetchProfile (pubkeyHex, relays) {
    if (!this.relays || !relays.length) return null
    try {
      const ev = await this.relays.fetchLatest({ authors: [pubkeyHex], kinds: [0], limit: 5 }, relays)
      return ev ? { event: ev } : null
    } catch { return null }
  }

  async _fetchRelayList (pubkeyHex, relays) {
    if (!this.relays || !relays.length) return []
    try {
      const ev = await this.relays.fetchLatest({ authors: [pubkeyHex], kinds: [10002], limit: 2 }, relays)
      return ev ? parseRelayList(ev) : []
    } catch { return [] }
  }

  _relaySet (hints) {
    const out = []
    const seen = new Set()
    for (const r of [...(hints || []), ...this.defaultRelays]) {
      if (!/^wss?:\/\//i.test(r || '')) continue
      const u = r.replace(/\/$/, '')
      if (seen.has(u)) continue
      seen.add(u); out.push(u)
    }
    return out
  }

  _mergeRelays (recordRelays, nip65, profile) {
    const out = []
    const seen = new Set()
    const add = (u) => {
      if (typeof u !== 'string' || !/^wss?:\/\//i.test(u)) return
      const v = u.replace(/\/$/, '')
      if (seen.has(v)) return
      seen.add(v); out.push(v)
    }
    for (const r of recordRelays || []) add(r)
    for (const r of nip65 || []) add(r.url)
    return out
  }

  /** Derive the NIP-05 cross-check target from a kind:0 nip05 claim, or from
   * the hns name via the configured NIP-05 domain (alice.exist -> alice@hns.one). */
  _nip05Target (nip05Claim, hnsName) {
    if (typeof nip05Claim === 'string' && nip05Claim.includes('@')) {
      const at = nip05Claim.lastIndexOf('@')
      const local = nip05Claim.slice(0, at).toLowerCase()
      const domain = nip05Claim.slice(at + 1).toLowerCase().replace(/\.$/, '')
      if (local && domain) return { local, domain }
    }
    return null
  }

  _binding (proofs) {
    if (proofs.hns && proofs.nostrAcknowledgement) return BINDING.MUTUAL
    if (proofs.hns) return BINDING.HNS_CONTROL
    if (proofs.nip05) return BINDING.NIP05
    return BINDING.NONE
  }

  _build ({ pubkeyHex, hnsName, nip05, relays, epoch, proofs, binding, managed, complete, historical, warnings, resolutionPath, input }) {
    const npub = encodeNpub(pubkeyHex)
    const nprofile = encodeNprofile({ pubkeyHex, relays: relays.slice(0, 4) })
    return {
      pubkeyHex,
      npub,
      nprofile,
      hnsName: hnsName || null,
      nip05: nip05 || null,
      relays,
      epoch: epoch === undefined ? null : epoch,
      proofs: {
        hns: !!proofs.hns,
        dnssec: !!proofs.dnssec,
        nostrAcknowledgement: !!proofs.nostrAcknowledgement,
        nip05: !!proofs.nip05
      },
      binding,
      managed: !!managed,
      complete: !!complete,
      historical: !!historical,
      warnings: warnings || [],
      resolutionPath,
      input
    }
  }
}

export { BINDING }
