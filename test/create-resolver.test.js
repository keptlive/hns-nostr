import { test, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { createResolver } from '../src/index.js'
import { encodeNpub } from '../src/nip19.js'
import { makeKeypair, profileEvent, nostrTxt, mockRelays, mockNip05Http } from './helpers.js'

// createResolver() with the default backend, pointed at stand-in Handshake
// modules so the test can count SPV nodes without hsd or a network.
const FAKE_DIR = fileURLToPath(new URL('./fixtures/fake-hns', import.meta.url))
const fakeUrl = (f) => new URL('file://' + path.join(FAKE_DIR, f)).href
const { SPVNode, zone } = await import(fakeUrl('spv.js'))
const { answers } = await import(fakeUrl('dns-query.js'))

beforeEach(() => {
  SPVNode.reset()
  answers.txt = {}
})

test('resolving an npub never starts an SPV node', async () => {
  const kp = makeKeypair()
  const resolver = await createResolver({
    hnsSrcPath: FAKE_DIR,
    relays: mockRelays([profileEvent(kp, { name: 'Key only' })]),
    http: mockNip05Http({})
  })
  const p = await resolver.resolve(encodeNpub(kp.pubkey))
  assert.equal(p.pubkeyHex, kp.pubkey)
  await resolver.close()
  assert.equal(SPVNode.instances.length, 0)
})

test('resolving a NIP-05 address under hns.one never starts an SPV node', async () => {
  const kp = makeKeypair()
  const resolver = await createResolver({
    hnsSrcPath: FAKE_DIR,
    relays: mockRelays([profileEvent(kp, { nip05: '_@site.w3.hns.one' })]),
    http: mockNip05Http({ '_@site.w3.hns.one': { names: { _: kp.pubkey } } })
  })
  const p = await resolver.resolve('_@site.w3.hns.one')
  assert.equal(p.proofs.nip05, true)
  await resolver.close()
  assert.equal(SPVNode.instances.length, 0)
})

test('resolving a Handshake name starts one node, and close() stops it', async () => {
  const kp = makeKeypair()
  zone.records.exist = [{ type: 'NS', ns: 'ns1.exist.' }]
  answers.txt['_nostr.alice.exist'] = [nostrTxt({ pubkey: kp.pubkey, epoch: 3 })]
  const resolver = await createResolver({
    hnsSrcPath: FAKE_DIR,
    authoritative: { server: '192.0.2.1', port: 53 },
    relays: mockRelays([profileEvent(kp, { hns: 'alice.exist' })]),
    http: mockNip05Http({})
  })
  assert.equal(SPVNode.instances.length, 0)
  const p = await resolver.resolve('alice.exist')
  assert.equal(p.pubkeyHex, kp.pubkey)
  assert.equal(p.binding, 'mutual')
  assert.equal(SPVNode.instances.length, 1)
  assert.equal(SPVNode.instances[0].starts, 1)
  await resolver.close()
  assert.equal(SPVNode.instances[0].stops, 1)
})
