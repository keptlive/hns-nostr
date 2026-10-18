/*
 * Input classification — the accepted identifier forms (DESIGN §5):
 *   alice.exist            HNS-native
 *   _@alice.exist          root NIP-05 form, shown as alice.exist -> HNS-native
 *   alice@hns.one          conventional NIP-05 (ICANN domain we own)
 *   _@alice.w3.hns.one     NIP-05 at a host under a configured NIP-05 domain
 *   npub1...               cryptographic id
 *   nprofile1...           portable profile (with relay hints)
 *   nostr:npub1... / nostr:nprofile1...   URI-wrapped
 *
 * The classifier never guesses a namespace it wasn't given: an `@` input over
 * a configured ICANN NIP-05 domain (or a host under one) takes the NIP-05
 * path, and any other `@` input is read as a Handshake name. Which namespace
 * an input belongs to decides which proof can back it, so the two never
 * silently cross over.
 */

import { decodeNpub, decodeNprofile } from './nip19.js'

const NPUB_RE = /^npub1[0-9a-z]+$/i
const NPROFILE_RE = /^nprofile1[0-9a-z]+$/i

/**
 * @param {string} raw
 * @param {object} opts
 * @param {string[]} opts.nip05Domains  domains resolved via the ICANN NIP-05
 *   path (default ['hns.one']). An `@`-input whose domain is one of these, or a
 *   host under one, is a NIP-05 identity; any other `@`-domain is treated as a
 *   Handshake name.
 * @returns {{form:'npub'|'nprofile'|'hns'|'nip05', ...}}
 */
export function classifyInput (raw, { nip05Domains = ['hns.one'] } = {}) {
  if (typeof raw !== 'string') throw new Error('input must be a string')
  let s = raw.trim()
  if (!s) throw new Error('empty input')

  // Strip the nostr: URI scheme (NIP-21). Only npub/nprofile are in scope here.
  if (/^nostr:/i.test(s)) s = s.slice('nostr:'.length)

  if (NPUB_RE.test(s)) {
    return { form: 'npub', pubkeyHex: decodeNpub(s.toLowerCase()), input: raw }
  }
  if (NPROFILE_RE.test(s)) {
    const { pubkeyHex, relays } = decodeNprofile(s.toLowerCase())
    return { form: 'nprofile', pubkeyHex, relays, input: raw }
  }

  if (s.includes('@')) {
    const at = s.lastIndexOf('@')
    const local = s.slice(0, at)
    const domain = s.slice(at + 1).toLowerCase().replace(/\.$/, '')
    if (!domain) throw new Error(`no domain in ${raw}`)

    // A configured NIP-05 domain covers the hosts under it: hns.one serves
    // each name's NIP-05 document at that name's own host, as
    // `_@<name>.hns.one`, so that host is an ICANN domain like any other.
    if (isNip05Domain(domain, nip05Domains)) {
      return { form: 'nip05', local: local.toLowerCase(), domain, input: raw }
    }

    // `_@name` over a Handshake name is the NIP-05 root form: display and
    // resolve as the bare HNS name `name` (DESIGN §1).
    if (local === '_') {
      return { form: 'hns', hnsName: domain, displayName: domain, rootForm: true, input: raw }
    }

    // An `@` over a Handshake name (not a configured NIP-05 domain): resolve
    // `_nostr.<local>.<domain>` HNS-natively — the generalization of the
    // `alice.exist` subdomain-identity convention to any label.
    return {
      form: 'hns',
      hnsName: `${local.toLowerCase()}.${domain}`,
      displayName: `${local.toLowerCase()}.${domain}`,
      input: raw
    }
  }

  // A bare dotted or single-label name -> HNS-native.
  const name = s.toLowerCase().replace(/\.$/, '')
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(name)) {
    throw new Error(`unrecognized identifier: ${raw}`)
  }
  return { form: 'hns', hnsName: name, displayName: name, input: raw }
}

/** True when `domain` is one of `nip05Domains` or a host under one. */
function isNip05Domain (domain, nip05Domains) {
  return nip05Domains.some((d) => {
    const base = String(d).toLowerCase().replace(/\.$/, '')
    return base && (domain === base || domain.endsWith('.' + base))
  })
}
