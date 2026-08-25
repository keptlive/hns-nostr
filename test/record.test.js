import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseNostrRecord, validateEpoch } from '../src/record.js'

const PK = 'a'.repeat(64)

test('parses a well-formed v=nostr1 record', () => {
  const r = parseNostrRecord([`v=nostr1;pubkey=${PK};epoch=7;relay=wss://relay.hns.one`])
  assert.equal(r.ok, true)
  assert.equal(r.pubkey, PK)
  assert.equal(r.epoch, 7)
  assert.deepEqual(r.relays, ['wss://relay.hns.one'])
  assert.equal(r.managed, false)
})

test('merges multiple TXT strings and multiple relays', () => {
  const r = parseNostrRecord([
    `v=nostr1;pubkey=${PK};epoch=0`,
    'relay=wss://relay.hns.one;relay=wss://nos.lol'
  ])
  assert.equal(r.ok, true)
  assert.deepEqual(r.relays, ['wss://relay.hns.one', 'wss://nos.lol'])
})

test('rejects wrong version', () => {
  assert.equal(parseNostrRecord([`v=nostr2;pubkey=${PK};epoch=1`]).ok, false)
})

test('rejects a malformed pubkey', () => {
  assert.equal(parseNostrRecord(['v=nostr1;pubkey=xyz;epoch=1']).ok, false)
})

test('rejects a missing epoch', () => {
  assert.equal(parseNostrRecord([`v=nostr1;pubkey=${PK}`]).ok, false)
})

test('a receipt field marks the name managed', () => {
  const r = parseNostrRecord([`v=nostr1;pubkey=${PK};epoch=3;receipt=abc123;assignedby=${'b'.repeat(64)}`])
  assert.equal(r.ok, true)
  assert.equal(r.managed, true)
  assert.equal(r.receipt, 'abc123')
})

test('epoch validation: integers only, optional expected match', () => {
  assert.equal(validateEpoch('5').ok, true)
  assert.equal(validateEpoch('-1').ok, false)
  assert.equal(validateEpoch('x').ok, false)
  const stale = validateEpoch('4', { expected: 5 })
  assert.equal(stale.ok, false)
  assert.equal(stale.stale, true)
  assert.equal(validateEpoch('5', { expected: 5 }).ok, true)
})
