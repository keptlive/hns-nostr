import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ResolverCache } from '../src/cache.js'

test('cache keys on name + epoch + tree state', () => {
  const c = new ResolverCache()
  c.set('alice.exist', 7, 'tree-A', { pubkeyHex: 'aa' })
  assert.equal(c.get('alice.exist', 7, 'tree-A').pubkeyHex, 'aa')
  // Different epoch or different tree state => miss (safe on transfer).
  assert.equal(c.get('alice.exist', 8, 'tree-A'), null)
  assert.equal(c.get('alice.exist', 7, 'tree-B'), null)
})

test('an entry cached under an older epoch is reported historical', () => {
  const c = new ResolverCache()
  c.set('alice.exist', 7, 'tree-A', { pubkeyHex: 'old' })
  // New owner resolves at epoch 8 -> latestEpoch advances.
  c.set('alice.exist', 8, 'tree-B', { pubkeyHex: 'new' })
  assert.equal(c.get('alice.exist', 8, 'tree-B').historical, false)
  assert.equal(c.get('alice.exist', 7, 'tree-A').historical, true) // stale key, never current
})

test('noteEpoch marks older entries historical without a fresh resolve', () => {
  const c = new ResolverCache()
  c.set('bob.exist', 3, 'tree-X', { pubkeyHex: 'bob' })
  c.noteEpoch('bob.exist', 4)
  assert.equal(c.get('bob.exist', 3, 'tree-X').historical, true)
})

test('expired entries are evicted', () => {
  const c = new ResolverCache({ ttl: -1 })
  c.set('x.exist', 1, 't', { pubkeyHex: 'x' })
  assert.equal(c.get('x.exist', 1, 't'), null)
})
