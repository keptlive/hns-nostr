/*
 * hns-nostr — public API.
 *
 * Embeddable (Wildroot / BR-7):
 *   import { NostrResolver } from 'hns-nostr'
 *   const r = new NostrResolver({ hns, relays, http })   // inject your core
 *   const proof = await r.resolve('alice.exist')
 *
 * Batteries-included (CLI / service / a standalone app):
 *   import { createResolver } from 'hns-nostr'
 *   const r = await createResolver()   // wires the real SPV+DNSSEC backend
 *                                      // (wildroot-web3-resolution) + a WebSocket relay pool
 *   const proof = await r.resolve('alice@hns.one')
 *   await r.close()
 *
 * The proof object shape is DESIGN §5:
 *   { pubkeyHex, npub, nprofile, hnsName, nip05, relays, epoch,
 *     proofs:{hns, dnssec, nostrAcknowledgement, nip05},
 *     binding, managed, complete, historical, warnings, resolutionPath, input }
 */

import { NostrResolver, BINDING } from './resolver.js'
import { RelayPool } from './relay-pool.js'
import { ResolverCache } from './cache.js'
import { createHnsBackend } from './hns-backend.js'
import { classifyInput } from './input.js'
import { parseNostrRecord, validateEpoch } from './record.js'
import { verifyEvent, computeEventId } from './nostr-event.js'
import { encodeNpub, decodeNpub, encodeNprofile, decodeNprofile } from './nip19.js'

/**
 * Batteries-included resolver: the real SPV chain-proof + DNSSEC HNS backend
 * (reusing wildroot-web3-resolution's modules) and a WebSocket relay pool.
 * @param {object} options
 * @param {object} [options.hns]           override the HNS backend
 * @param {object} [options.spvOptions]    passed to the browser SPVNode
 * @param {string} [options.hnsSrcPath]    directory holding spv.js, dns-query.js
 *                                         and dnssec.js (default:
 *                                         ../wildroot-web3-resolution/src)
 * @param {object} [options.relays]        override the relay pool
 * @param {string[]} [options.defaultRelays]
 * @param {string[]} [options.nip05Domains]
 * @param {number} [options.relayTimeout]
 */
export async function createResolver (options = {}) {
  const hns = options.hns || await createHnsBackend({
    spvOptions: options.spvOptions,
    hnsSrcPath: options.hnsSrcPath,
    browserHnsPath: options.browserHnsPath,
    timeout: options.hnsTimeout,
    authoritative: options.authoritative
  })
  const relays = options.relays || new RelayPool({ timeout: options.relayTimeout })
  const resolver = new NostrResolver({
    hns,
    relays,
    http: options.http,
    nip05Domains: options.nip05Domains,
    defaultRelays: options.defaultRelays,
    cache: options.cache || new ResolverCache(),
    epochOracle: options.epochOracle
  })
  // Expose close() so the caller can stop the spawned SPV node.
  resolver.close = async () => { if (hns.close) await hns.close() }
  return resolver
}

export {
  NostrResolver,
  BINDING,
  RelayPool,
  ResolverCache,
  createHnsBackend,
  classifyInput,
  parseNostrRecord,
  validateEpoch,
  verifyEvent,
  computeEventId,
  encodeNpub,
  decodeNpub,
  encodeNprofile,
  decodeNprofile
}
