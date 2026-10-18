import { test } from 'node:test'
import assert from 'node:assert/strict'

import { NostrResolver, BINDING } from '../src/resolver.js'
import { encodeNpub, encodeNprofile } from '../src/nip19.js'
import {
  makeKeypair, profileEvent, relayListEvent, nostrTxt,
  mockHns, mockRelays, mockNip05Http
} from './helpers.js'

// A full, healthy alice.exist identity: HNS record + reciprocal kind:0 + NIP-05.
function aliceWorld ({ nip05 = 'ok', epoch = 7 } = {}) {
  const alice = makeKeypair()
  const hns = mockHns({
    'alice.exist': {
      found: true,
      txt: [nostrTxt({ pubkey: alice.pubkey, epoch, relays: ['wss://relay.hns.one'] })],
      proofs: { hns: true, dnssec: true }
    }
  })
  const relays = mockRelays([
    profileEvent(alice, { name: 'Alice', hns: 'alice.exist', nip05: 'alice@hns.one' }),
    relayListEvent(alice, ['wss://relay.hns.one', 'wss://nos.lol'])
  ])
  const http = mockNip05Http({
    'alice@hns.one': nip05 === 'DOWN'
      ? 'DOWN'
      : { names: { alice: alice.pubkey }, relays: { [alice.pubkey]: ['wss://relay.hns.one'] } }
  })
  return { alice, resolver: new NostrResolver({ hns, relays, http }) }
}

test('alice.exist resolves to a complete mutual binding with all proofs', async () => {
  const { alice, resolver } = aliceWorld()
  const p = await resolver.resolve('alice.exist')
  assert.equal(p.pubkeyHex, alice.pubkey)
  assert.equal(p.hnsName, 'alice.exist')
  assert.equal(p.nip05, 'alice@hns.one')
  assert.equal(p.epoch, 7)
  assert.equal(p.npub, encodeNpub(alice.pubkey))
  assert.ok(p.nprofile.startsWith('nprofile1'))
  assert.deepEqual(p.proofs, { hns: true, dnssec: true, nostrAcknowledgement: true, nip05: true })
  assert.equal(p.binding, BINDING.MUTUAL)
  assert.equal(p.complete, true)
  assert.ok(p.relays.includes('wss://relay.hns.one'))
  assert.ok(p.relays.includes('wss://nos.lol')) // merged from NIP-65
})

test('_@alice.exist resolves identically (root NIP-05 form)', async () => {
  const { alice, resolver } = aliceWorld()
  const p = await resolver.resolve('_@alice.exist')
  assert.equal(p.pubkeyHex, alice.pubkey)
  assert.equal(p.hnsName, 'alice.exist')
  assert.equal(p.proofs.hns, true)
})

test('alice@hns.one resolves via NIP-05 AND upgrades to HNS control (mutual)', async () => {
  const { alice, resolver } = aliceWorld()
  const p = await resolver.resolve('alice@hns.one')
  assert.equal(p.resolutionPath, 'nip05')
  assert.equal(p.pubkeyHex, alice.pubkey)
  assert.equal(p.proofs.nip05, true)
  // The kind:0 claims hns=alice.exist and the HNS record binds this key -> upgrade.
  assert.equal(p.proofs.hns, true)
  assert.equal(p.proofs.dnssec, true)
  assert.equal(p.hnsName, 'alice.exist')
  assert.equal(p.binding, BINDING.MUTUAL)
})

test('npub / nprofile / nostr: forms all resolve to the same identity', async () => {
  for (const mk of [
    (a) => encodeNpub(a.pubkey),
    (a) => encodeNprofile({ pubkeyHex: a.pubkey, relays: ['wss://relay.hns.one'] }),
    (a) => 'nostr:' + encodeNpub(a.pubkey)
  ]) {
    const { alice, resolver } = aliceWorld()
    const p = await resolver.resolve(mk(alice))
    assert.equal(p.pubkeyHex, alice.pubkey)
    assert.equal(p.hnsName, 'alice.exist') // via verified kind:0 hns claim
    assert.equal(p.proofs.hns, true)
    assert.equal(p.proofs.nostrAcknowledgement, true)
    assert.equal(p.binding, BINDING.MUTUAL)
  }
})

test('_@<name>.hns.one resolves over NIP-05 at that host, with no Handshake lookup', async () => {
  const site = makeKeypair()
  const hnsCalls = []
  const hns = { async verify (name) { hnsCalls.push(name); throw new Error('no Handshake lookup expected') } }
  const resolver = new NostrResolver({
    hns,
    relays: mockRelays([profileEvent(site, { name: 'Site', nip05: '_@site.w3.hns.one' })]),
    http: mockNip05Http({
      '_@site.w3.hns.one': { names: { _: site.pubkey }, relays: { [site.pubkey]: ['wss://site.w3.hns.one'] } }
    })
  })
  const p = await resolver.resolve('_@site.w3.hns.one')
  assert.equal(p.resolutionPath, 'nip05')
  assert.equal(p.pubkeyHex, site.pubkey)
  assert.equal(p.nip05, '_@site.w3.hns.one')
  assert.equal(p.proofs.nip05, true)
  assert.equal(p.proofs.nostrAcknowledgement, true)
  assert.equal(p.proofs.hns, false)
  assert.equal(p.binding, BINDING.NIP05)
  assert.ok(p.relays.includes('wss://site.w3.hns.one'))
  assert.deepEqual(hnsCalls, [])
})

// ---- INVARIANT (1): NIP-05 failure must NOT invalidate an HNS binding -------

test('INVARIANT 1: with NIP-05 down, a valid HNS binding still resolves', async () => {
  const { alice, resolver } = aliceWorld({ nip05: 'DOWN' })
  const p = await resolver.resolve('alice.exist')
  assert.equal(p.proofs.hns, true)
  assert.equal(p.proofs.dnssec, true)
  assert.equal(p.proofs.nostrAcknowledgement, true)
  assert.equal(p.proofs.nip05, false) // the only casualty
  assert.equal(p.binding, BINDING.MUTUAL)
  assert.equal(p.complete, true)
  assert.equal(p.pubkeyHex, alice.pubkey)
  assert.ok(p.warnings.some((w) => /NIP-05/.test(w)))
})

// ---- INVARIANT (2): a valid alice@hns.one is NEVER reported as HNS control ---

test('INVARIANT 2: a NIP-05-only key never claims HNS control', async () => {
  const bob = makeKeypair()
  // NO HNS record for bob anywhere; kind:0 carries only a nip05 claim.
  const resolver = new NostrResolver({
    hns: mockHns({}),
    relays: mockRelays([profileEvent(bob, { name: 'Bob', nip05: 'bob@hns.one' })]),
    http: mockNip05Http({ 'bob@hns.one': { names: { bob: bob.pubkey } } })
  })
  const p = await resolver.resolve('bob@hns.one')
  assert.equal(p.proofs.hns, false) // <-- the invariant
  assert.equal(p.proofs.dnssec, false)
  assert.equal(p.hnsName, null)
  assert.equal(p.nip05, 'bob@hns.one')
  assert.equal(p.binding, BINDING.NIP05)
  assert.equal(p.complete, false)
})

test('INVARIANT 2: a kind:0 that claims an hns name binding a DIFFERENT key is not upgraded', async () => {
  const bob = makeKeypair()
  const someoneElse = makeKeypair()
  const resolver = new NostrResolver({
    // eve.exist exists but binds someoneElse, not bob.
    hns: mockHns({
      'eve.exist': {
        found: true,
        txt: [nostrTxt({ pubkey: someoneElse.pubkey, epoch: 1 })],
        proofs: { hns: true, dnssec: true }
      }
    }),
    relays: mockRelays([profileEvent(bob, { nip05: 'bob@hns.one', hns: 'eve.exist' })]),
    http: mockNip05Http({ 'bob@hns.one': { names: { bob: bob.pubkey } } })
  })
  const p = await resolver.resolve('bob@hns.one')
  assert.equal(p.proofs.hns, false)
  assert.equal(p.hnsName, null)
  assert.ok(p.warnings.some((w) => /does not bind this key/.test(w)))
})

// ---- Managed SLD: mutual binding is the only complete state -----------------

test('managed SLD with reciprocal kind:0 is a complete mutual binding', async () => {
  const carol = makeKeypair()
  const resolver = new NostrResolver({
    hns: mockHns({
      'carol.exist': {
        found: true,
        txt: [nostrTxt({ pubkey: carol.pubkey, epoch: 2, receipt: 'assign-receipt-xyz' })],
        proofs: { hns: true, dnssec: true }
      }
    }),
    relays: mockRelays([profileEvent(carol, { hns: 'carol.exist', nip05: 'carol@hns.one' })]),
    http: mockNip05Http({})
  })
  const p = await resolver.resolve('carol.exist')
  assert.equal(p.managed, true)
  assert.equal(p.binding, BINDING.MUTUAL)
  assert.equal(p.complete, true)
})

test('managed SLD WITHOUT the owner kind:0 is HNS-control but NOT complete', async () => {
  const carol = makeKeypair()
  const resolver = new NostrResolver({
    hns: mockHns({
      'carol.exist': {
        found: true,
        txt: [nostrTxt({ pubkey: carol.pubkey, epoch: 2, receipt: 'assign-receipt-xyz' })],
        proofs: { hns: true, dnssec: true }
      }
    }),
    relays: mockRelays([]), // no kind:0 acknowledgement
    http: mockNip05Http({})
  })
  const p = await resolver.resolve('carol.exist')
  assert.equal(p.managed, true)
  assert.equal(p.proofs.hns, true)
  assert.equal(p.proofs.nostrAcknowledgement, false)
  assert.equal(p.binding, BINDING.HNS_CONTROL)
  assert.equal(p.complete, false)
  assert.ok(p.warnings.some((w) => /managed SLD/.test(w)))
})

// ---- Works for ANY Handshake TLD, not just .exist ---------------------------

test('resolves a bare-TLD identity (14898) — any Handshake TLD works', async () => {
  const dev = makeKeypair()
  const resolver = new NostrResolver({
    hns: mockHns({
      14898: {
        found: true,
        txt: [nostrTxt({ pubkey: dev.pubkey, epoch: 0 })],
        proofs: { hns: true, dnssec: true }
      }
    }),
    relays: mockRelays([profileEvent(dev, { hns: '14898' })]),
    http: mockNip05Http({})
  })
  const p = await resolver.resolve('14898')
  assert.equal(p.pubkeyHex, dev.pubkey)
  assert.equal(p.hnsName, '14898')
  assert.equal(p.binding, BINDING.MUTUAL)
})

// ---- Epoch / historical (DESIGN §9) -----------------------------------------

test('a stale ownership epoch is shown historical, never current', async () => {
  const { resolver } = aliceWorld({ epoch: 7 })
  // The registry says the current epoch is 8, but the record still reads 7.
  resolver.epochOracle = () => 8
  const p = await resolver.resolve('alice.exist')
  assert.equal(p.historical, true)
  assert.ok(p.warnings.some((w) => /stale/.test(w)))
})

test('DNSSEC failure from the backend is a hard error, not a silent downgrade', async () => {
  const resolver = new NostrResolver({
    hns: mockHns({
      'tamper.exist': {
        found: false, txt: ['whatever'], proofs: { hns: true, dnssec: false },
        dnssecFail: true, reason: 'TLSA RRSIG missing'
      }
    }),
    relays: mockRelays([]),
    http: mockNip05Http({})
  })
  await assert.rejects(() => resolver.resolve('tamper.exist'), /no HNS-native Nostr identity/)
})

test('HNS proof unavailable (SPV not synced) reads the mapping but flags it unverified', async () => {
  const dev = makeKeypair()
  const resolver = new NostrResolver({
    hns: mockHns({
      'slow.exist': {
        found: true,
        txt: [nostrTxt({ pubkey: dev.pubkey, epoch: 0 })],
        proofs: { hns: false, dnssec: false } // node not synced
      }
    }),
    relays: mockRelays([profileEvent(dev, { hns: 'slow.exist' })]),
    http: mockNip05Http({})
  })
  const p = await resolver.resolve('slow.exist')
  assert.equal(p.proofs.hns, false)
  assert.equal(p.binding, BINDING.NONE) // no chain proof -> not HNS control
  assert.ok(p.warnings.some((w) => /not chain-verified|not synced|unavailable/.test(w)))
})
