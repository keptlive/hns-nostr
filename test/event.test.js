import { test } from 'node:test'
import assert from 'node:assert/strict'
import { verifyEvent, parseProfileContent, parseRelayList } from '../src/nostr-event.js'
import { makeKeypair, signEvent, profileEvent, relayListEvent } from './helpers.js'

test('a genuinely signed event verifies', () => {
  const kp = makeKeypair()
  const ev = signEvent(kp, { kind: 1, content: 'hello handshake' })
  assert.equal(verifyEvent(ev).ok, true)
})

test('a tampered content is rejected (id mismatch)', () => {
  const kp = makeKeypair()
  const ev = signEvent(kp, { kind: 1, content: 'hello' })
  ev.content = 'goodbye'
  const r = verifyEvent(ev)
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'id mismatch')
})

test('a swapped signature is rejected', () => {
  const a = makeKeypair()
  const b = makeKeypair()
  const evA = signEvent(a, { kind: 1, content: 'x' })
  const evB = signEvent(b, { kind: 1, content: 'x', created_at: evA.created_at })
  // Claim A's pubkey but keep B's signature/id -> invalid.
  const forged = { ...evB, pubkey: a.pubkey, id: evA.id }
  assert.equal(verifyEvent(forged).ok, false)
})

test('profile content parses; relay list reads r tags', () => {
  const kp = makeKeypair()
  const p = profileEvent(kp, { name: 'alice.exist', hns: 'alice.exist', nip05: 'alice@hns.one' })
  assert.equal(parseProfileContent(p).hns, 'alice.exist')
  const rl = relayListEvent(kp, ['wss://relay.hns.one', 'wss://nos.lol'])
  assert.deepEqual(parseRelayList(rl).map((r) => r.url), ['wss://relay.hns.one', 'wss://nos.lol'])
})
