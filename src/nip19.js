/*
 * NIP-19 bech32 entities (npub, nprofile) — the shareable, human-visible
 * Nostr identifiers. Self-contained bech32 (BIP-173) + the NIP-19 TLV format
 * for `nprofile`, so the package carries no bech32 dependency.
 *
 * Nostr uses bech32 WITHOUT the 90-char length cap (an nprofile with several
 * relay hints exceeds it), so the cap is deliberately not enforced here — the
 * checksum still is.
 */

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]

function polymod (values) {
  let chk = 1
  for (const v of values) {
    const top = chk >> 25
    chk = ((chk & 0x1ffffff) << 5) ^ v
    for (let i = 0; i < 5; i++) {
      if ((top >> i) & 1) chk ^= GENERATOR[i]
    }
  }
  return chk
}

function hrpExpand (hrp) {
  const out = []
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5)
  out.push(0)
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31)
  return out
}

function verifyChecksum (hrp, data) {
  return polymod(hrpExpand(hrp).concat(data)) === 1
}

function createChecksum (hrp, data) {
  const values = hrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0])
  const mod = polymod(values) ^ 1
  const out = []
  for (let i = 0; i < 6; i++) out.push((mod >> (5 * (5 - i))) & 31)
  return out
}

export function bech32Encode (hrp, data) {
  const combined = data.concat(createChecksum(hrp, data))
  let out = hrp + '1'
  for (const d of combined) out += CHARSET.charAt(d)
  return out
}

export function bech32Decode (str) {
  if (str.length < 8) throw new Error('bech32 string too short')
  const lower = str.toLowerCase()
  const upper = str.toUpperCase()
  if (str !== lower && str !== upper) throw new Error('bech32 mixed case')
  const s = lower
  const pos = s.lastIndexOf('1')
  if (pos < 1 || pos + 7 > s.length) throw new Error('bech32 missing separator')
  const hrp = s.slice(0, pos)
  const data = []
  for (let i = pos + 1; i < s.length; i++) {
    const d = CHARSET.indexOf(s.charAt(i))
    if (d === -1) throw new Error('bech32 invalid character')
    data.push(d)
  }
  if (!verifyChecksum(hrp, data)) throw new Error('bech32 bad checksum')
  return { hrp, data: data.slice(0, data.length - 6) }
}

/** Regroup bits (e.g. 8->5 for encode, 5->8 for decode). */
export function convertBits (data, from, to, pad) {
  let acc = 0
  let bits = 0
  const out = []
  const maxv = (1 << to) - 1
  for (const value of data) {
    if (value < 0 || value >> from !== 0) throw new Error('convertBits: bad value')
    acc = (acc << from) | value
    bits += from
    while (bits >= to) {
      bits -= to
      out.push((acc >> bits) & maxv)
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxv)
  } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
    throw new Error('convertBits: invalid padding')
  }
  return out
}

function bytesToHex (bytes) {
  let hex = ''
  for (const b of bytes) hex += b.toString(16).padStart(2, '0')
  return hex
}

function hexToBytes (hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0) throw new Error('bad hex')
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.substr(i * 2, 2), 16)
    if (Number.isNaN(byte)) throw new Error('bad hex')
    out[i] = byte
  }
  return out
}

/** 32-byte x-only pubkey hex -> npub1... */
export function encodeNpub (pubkeyHex) {
  const bytes = hexToBytes(pubkeyHex)
  if (bytes.length !== 32) throw new Error('npub needs a 32-byte pubkey')
  return bech32Encode('npub', convertBits(Array.from(bytes), 8, 5, true))
}

/** npub1... -> 64-char hex */
export function decodeNpub (npub) {
  const { hrp, data } = bech32Decode(npub)
  if (hrp !== 'npub') throw new Error('not an npub')
  const bytes = convertBits(data, 5, 8, false)
  if (bytes.length !== 32) throw new Error('npub payload not 32 bytes')
  return bytesToHex(bytes)
}

// NIP-19 TLV types.
const TLV_SPECIAL = 0
const TLV_RELAY = 1

/** { pubkeyHex, relays[] } -> nprofile1... */
export function encodeNprofile ({ pubkeyHex, relays = [] }) {
  const pk = hexToBytes(pubkeyHex)
  if (pk.length !== 32) throw new Error('nprofile needs a 32-byte pubkey')
  const tlv = []
  const pushTLV = (type, valueBytes) => {
    if (valueBytes.length > 255) throw new Error('TLV value too long')
    tlv.push(type, valueBytes.length, ...valueBytes)
  }
  pushTLV(TLV_SPECIAL, Array.from(pk))
  for (const relay of relays) {
    pushTLV(TLV_RELAY, Array.from(new TextEncoder().encode(relay)))
  }
  return bech32Encode('nprofile', convertBits(tlv, 8, 5, true))
}

/** nprofile1... -> { pubkeyHex, relays[] } */
export function decodeNprofile (nprofile) {
  const { hrp, data } = bech32Decode(nprofile)
  if (hrp !== 'nprofile') throw new Error('not an nprofile')
  const bytes = convertBits(data, 5, 8, false)
  let i = 0
  let pubkeyHex = null
  const relays = []
  while (i < bytes.length) {
    const type = bytes[i++]
    const len = bytes[i++]
    const value = bytes.slice(i, i + len)
    i += len
    if (type === TLV_SPECIAL) {
      if (value.length !== 32) throw new Error('nprofile special TLV not 32 bytes')
      pubkeyHex = bytesToHex(value)
    } else if (type === TLV_RELAY) {
      relays.push(new TextDecoder().decode(new Uint8Array(value)))
    }
  }
  if (!pubkeyHex) throw new Error('nprofile missing pubkey')
  return { pubkeyHex, relays }
}
