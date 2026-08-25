import { test } from 'node:test'
import assert from 'node:assert/strict'
import { encodeNpub, decodeNpub, encodeNprofile, decodeNprofile } from '../src/nip19.js'

// A known NIP-19 test vector (from the NIP-19 spec).
const HEX = '3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d'
const NPUB = 'npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6'

test('npub encodes to the known vector and round-trips', () => {
  assert.equal(encodeNpub(HEX), NPUB)
  assert.equal(decodeNpub(NPUB), HEX)
})

test('npub rejects a non-32-byte key', () => {
  assert.throws(() => encodeNpub('abcd'))
})

test('nprofile round-trips pubkey + relays (no length cap)', () => {
  const relays = ['wss://relay.hns.one', 'wss://relay.damus.io', 'wss://nos.lol']
  const np = encodeNprofile({ pubkeyHex: HEX, relays })
  assert.ok(np.startsWith('nprofile1'))
  const back = decodeNprofile(np)
  assert.equal(back.pubkeyHex, HEX)
  assert.deepEqual(back.relays, relays)
})

test('nprofile with no relays still carries the pubkey', () => {
  const np = encodeNprofile({ pubkeyHex: HEX })
  assert.equal(decodeNprofile(np).pubkeyHex, HEX)
})

test('a corrupted bech32 checksum is rejected', () => {
  const bad = NPUB.slice(0, -1) + (NPUB.endsWith('6') ? '7' : '6')
  assert.throws(() => decodeNpub(bad))
})
