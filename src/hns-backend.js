/*
 * The default HNS backend — REUSES Wildroot's mature Handshake core
 * (browser/src/hns: spv.js, dns-query.js, dnssec.js) so this resolver does
 * REAL local SPV chain-proof verification and DNSSEC validation, never a
 * trusted remote lookup. This is the concrete implementation of the
 * `hns` dependency the core NostrResolver injects; tests substitute a mock
 * of the same tiny interface.
 *
 * verify(name) mirrors DESIGN §6 steps 1-4:
 *   1. local HNS SPV getResource(tld)     -> Urkel proof, verified locally
 *   2. verify root proof + delegation      -> NS/DS on-chain
 *   3. read _nostr.<name> TXT at the zone's authoritative nameserver
 *   4. DNSSEC-validate that TXT up to the on-chain DS anchor
 *
 * The browser core is imported dynamically so merely importing hns-nostr (or
 * embedding it with a caller-supplied backend / mock) never requires hsd or
 * the browser's native deps to be installed.
 */

import dns from 'node:dns/promises'
import path from 'node:path'
import os from 'node:os'
import { fileURLToPath } from 'node:url'

const DEFAULT_BROWSER_HNS = path.resolve(
  fileURLToPath(new URL('.', import.meta.url)), '..', '..', 'browser', 'src', 'hns')

function isPublicAddress (addr) {
  // Minimal SSRF guard mirroring browser/src/hns/safe-address.js intent: refuse
  // loopback / private / link-local so a hostile zone cannot aim us at an
  // internal service. IPv4 only (the ns glue path is v4).
  if (typeof addr !== 'string') return false
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(addr)
  if (!m) return false
  const [a, b] = [Number(m[1]), Number(m[2])]
  if (a === 10 || a === 127 || a === 0) return false
  if (a === 169 && b === 254) return false
  if (a === 172 && b >= 16 && b <= 31) return false
  if (a === 192 && b === 168) return false
  if (a >= 224) return false // multicast / reserved
  return true
}

export async function createHnsBackend (options = {}) {
  const hnsDir = options.browserHnsPath || DEFAULT_BROWSER_HNS
  const toUrl = (f) => new URL('file://' + path.join(hnsDir, f)).href
  const { SPVNode } = await import(toUrl('spv.js'))
  const { query, TYPES } = await import(toUrl('dns-query.js'))
  const { validateChain } = await import(toUrl('dnssec.js'))

  const spv = options.spv || new SPVNode(options.spvOptions || {})
  const started = options.spv ? Promise.resolve() : spv.start()
  const timeout = options.timeout || 5000
  // A caller may point the authoritative hop at a fixed nameserver (tests /
  // a known resolver); production discovers it from the chain's NS records.
  const authoritative = options.authoritative || null

  async function nsServerFor (records) {
    if (authoritative) return authoritative
    const nsRecords = records.filter((r) => r.type === 'NS')
    let lastErr = null
    for (const ns of nsRecords) {
      const nsHost = ns.ns.replace(/\.$/, '')
      let address
      try {
        const glue = records.find(
          (r) => r.type === 'GLUE4' && r.ns && r.ns.replace(/\.$/, '') === nsHost)
        address = glue ? glue.address : (await dns.lookup(nsHost, { family: 4 })).address
      } catch (err) { lastErr = err; continue }
      if (!isPublicAddress(address)) { lastErr = new Error(`ns ${address} not public`); continue }
      return { server: address, port: 53 }
    }
    if (lastErr) throw lastErr
    return null
  }

  async function treeState () {
    try {
      const info = await spv.info()
      if (info && (info.bestblockhash || typeof info.blocks === 'number')) {
        return info.bestblockhash || `h${info.blocks}`
      }
    } catch {}
    return null
  }

  return {
    /**
     * @param {string} name  the full HNS name (e.g. "alice.exist" or "14898")
     * @returns {Promise<{found:boolean, txt:string[],
     *   proofs:{hns:boolean, dnssec:boolean}, treeState:string|null,
     *   tld:string, reason?:string}>}
     */
    async verify (name) {
      await started
      const host = String(name || '').toLowerCase().replace(/\.$/, '')
      const labels = host.split('.')
      const tld = labels[labels.length - 1]
      const synced = await spv.isSynced().catch(() => false)
      const tstate = await treeState()

      const resource = await spv.getResource(tld).catch(() => null)
      if (!resource || !Array.isArray(resource.records) || !resource.records.length) {
        return {
          found: false,
          txt: [],
          proofs: { hns: false, dnssec: false },
          treeState: tstate,
          tld,
          reason: synced ? 'name unregistered / no chain records' : 'SPV node not synced'
        }
      }
      const records = resource.records
      // proofs.hns TRUE only when the SPV node is synced (so its Urkel proof is
      // against the real tip) AND it returned a proven resource for the TLD.
      const hnsProof = synced

      const dsRecords = records.filter((r) => r.type === 'DS').map((r) => ({
        keyTag: r.keyTag, algorithm: r.algorithm, digestType: r.digestType, digest: r.digest
      }))
      const dnssecZone = dsRecords.length > 0

      let server
      try {
        server = await nsServerFor(records)
      } catch (err) {
        return {
          found: false, txt: [], proofs: { hns: hnsProof, dnssec: false },
          treeState: tstate, tld, reason: `no reachable nameserver: ${err.message || err}`
        }
      }
      if (!server) {
        return {
          found: false, txt: [], proofs: { hns: hnsProof, dnssec: false },
          treeState: tstate, tld, reason: 'name has no NS delegation (no _nostr possible)'
        }
      }

      const recordName = `_nostr.${host}`
      const txtResp = await query(server.server, server.port, recordName, TYPES.TXT,
        { timeout, dnssec: dnssecZone }).catch(() => null)
      if (!txtResp) {
        return {
          found: false, txt: [], proofs: { hns: hnsProof, dnssec: false },
          treeState: tstate, tld, reason: 'nameserver did not answer for _nostr'
        }
      }
      const txtRecords = txtResp.answers.filter((r) => r.type === TYPES.TXT && r.txt)
      const txt = []
      for (const r of txtRecords) txt.push(r.txt.join(''))
      if (!txt.length) {
        return {
          found: false, txt: [], proofs: { hns: hnsProof, dnssec: false },
          treeState: tstate, tld, reason: 'no _nostr TXT record published'
        }
      }

      // DNSSEC-validate the TXT rrset up to the on-chain DS, exactly as the
      // browser validates a TLSA pin (resolver.js). No DS on-chain => the zone
      // is unsigned => dnssec proof is simply false (not a failure).
      let dnssecProof = false
      if (dnssecZone) {
        try {
          const rrsig = txtResp.answers.find(
            (r) => r.type === TYPES.RRSIG && r.typeCovered === TYPES.TXT)
          const dk = await query(server.server, server.port, tld, TYPES.DNSKEY,
            { timeout, dnssec: true })
          const dnskeys = dk.answers.filter((r) => r.type === TYPES.DNSKEY)
          const dnskeyRRSIG = dk.answers.find(
            (r) => r.type === TYPES.RRSIG && r.typeCovered === TYPES.DNSKEY)
          const result = rrsig && validateChain({
            dsRecords,
            dnskeys,
            dnskeyRRSIG,
            leafOwner: recordName,
            leafType: TYPES.TXT,
            leafRdatas: txtRecords.map((r) => r.rdataRaw),
            leafRRSIG: rrsig
          })
          if (result && result.ok) {
            dnssecProof = true
          } else {
            // The chain says this zone is signed but the _nostr record did not
            // validate: that is tampering (or a broken zone). Fail the DNSSEC
            // proof AND refuse to treat the record as found — a forged _nostr
            // must not resolve.
            return {
              found: false, txt, proofs: { hns: hnsProof, dnssec: false },
              treeState: tstate, tld,
              reason: `DNSSEC validation failed: ${(result && result.reason) || 'no RRSIG'}`,
              dnssecFail: true
            }
          }
        } catch (err) {
          return {
            found: false, txt, proofs: { hns: hnsProof, dnssec: false },
            treeState: tstate, tld,
            reason: `DNSSEC validation error: ${err.message || err}`, dnssecFail: true
          }
        }
      }

      return {
        found: true,
        txt,
        proofs: { hns: hnsProof, dnssec: dnssecProof },
        treeState: tstate,
        tld
      }
    },

    treeState,

    async close () {
      if (!options.spv) { try { await spv.stop() } catch {} }
    }
  }
}

export { DEFAULT_BROWSER_HNS }
