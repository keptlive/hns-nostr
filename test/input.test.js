import { test } from 'node:test'
import assert from 'node:assert/strict'
import { classifyInput } from '../src/input.js'
import { encodeNpub, encodeNprofile } from '../src/nip19.js'

const HEX = '3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d'

test('bare HNS name -> hns form', () => {
  assert.deepEqual(classifyInput('alice.exist').form, 'hns')
  assert.equal(classifyInput('alice.exist').hnsName, 'alice.exist')
})

test('bare TLD (any Handshake TLD) -> hns form', () => {
  const c = classifyInput('14898')
  assert.equal(c.form, 'hns')
  assert.equal(c.hnsName, '14898')
})

test('_@alice.exist -> hns-native, displayed as alice.exist', () => {
  const c = classifyInput('_@alice.exist')
  assert.equal(c.form, 'hns')
  assert.equal(c.hnsName, 'alice.exist')
  assert.equal(c.rootForm, true)
})

test('alice@hns.one -> nip05 form (ICANN domain we own)', () => {
  const c = classifyInput('alice@hns.one')
  assert.equal(c.form, 'nip05')
  assert.equal(c.local, 'alice')
  assert.equal(c.domain, 'hns.one')
})

test('_@<name>.hns.one -> nip05 at that host (under a NIP-05 domain)', () => {
  for (const addr of ['_@hnsone.14898.hns.one', '_@matt.w3.hns.one']) {
    const c = classifyInput(addr)
    assert.equal(c.form, 'nip05')
    assert.equal(c.local, '_')
    assert.equal(c.domain, addr.slice(2))
  }
})

test('_@ a NIP-05 domain itself -> nip05', () => {
  const c = classifyInput('_@hns.one')
  assert.equal(c.form, 'nip05')
  assert.equal(c.domain, 'hns.one')
})

test('local@host under a NIP-05 domain -> nip05', () => {
  const c = classifyInput('Bob@Shop.HNS.one.')
  assert.equal(c.form, 'nip05')
  assert.equal(c.local, 'bob')
  assert.equal(c.domain, 'shop.hns.one')
})

test('a domain that only ends in the same letters is not under it', () => {
  const c = classifyInput('_@nothns.one')
  assert.equal(c.form, 'hns')
  assert.equal(c.hnsName, 'nothns.one')
})

test('nip05Domains replaces the default and also covers subdomains', () => {
  const custom = { nip05Domains: ['example.com'] }
  assert.equal(classifyInput('_@alice.example.com', custom).form, 'nip05')
  assert.equal(classifyInput('alice@example.com', custom).form, 'nip05')
  const c = classifyInput('_@alice.hns.one', custom)
  assert.equal(c.form, 'hns')
  assert.equal(c.hnsName, 'alice.hns.one')
  assert.equal(classifyInput('_@alice.example.com').form, 'hns')
})

test('local@handshake-name (non-underscore) -> hns-native subdomain identity', () => {
  const c = classifyInput('bob@shop.exist')
  assert.equal(c.form, 'hns')
  assert.equal(c.hnsName, 'bob.shop.exist')
})

test('npub -> npub form with decoded pubkey', () => {
  const c = classifyInput(encodeNpub(HEX))
  assert.equal(c.form, 'npub')
  assert.equal(c.pubkeyHex, HEX)
})

test('nprofile -> nprofile form with pubkey + relays', () => {
  const c = classifyInput(encodeNprofile({ pubkeyHex: HEX, relays: ['wss://r.example'] }))
  assert.equal(c.form, 'nprofile')
  assert.equal(c.pubkeyHex, HEX)
  assert.deepEqual(c.relays, ['wss://r.example'])
})

test('nostr: URI prefix is stripped', () => {
  const c = classifyInput('nostr:' + encodeNpub(HEX))
  assert.equal(c.form, 'npub')
  assert.equal(c.pubkeyHex, HEX)
})

test('garbage input throws', () => {
  assert.throws(() => classifyInput('  '))
  assert.throws(() => classifyInput('not a name!!'))
})
