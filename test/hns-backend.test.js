import { test, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { createHnsBackend } from '../src/hns-backend.js'

// The backend imports these by the same file URL, so the test and the backend
// share one instance of each fake module.
const FAKE_DIR = fileURLToPath(new URL('./fixtures/fake-hns', import.meta.url))
const fakeUrl = (f) => new URL('file://' + path.join(FAKE_DIR, f)).href
const { SPVNode, zone } = await import(fakeUrl('spv.js'))
const { answers } = await import(fakeUrl('dns-query.js'))

const PUBKEY = 'a'.repeat(64)
const AUTH = { server: '192.0.2.1', port: 53 }

beforeEach(() => {
  SPVNode.reset()
  answers.txt = {}
})

test('creating the backend neither loads nor starts an SPV node', async () => {
  const hns = await createHnsBackend({ hnsSrcPath: FAKE_DIR })
  assert.equal(SPVNode.instances.length, 0)
  await hns.close()
  assert.equal(SPVNode.instances.length, 0)
})

test('the first lookup starts the node, and later lookups reuse it', async () => {
  zone.records.exist = [{ type: 'NS', ns: 'ns1.exist.' }]
  answers.txt['_nostr.alice.exist'] = [`v=nostr1;pubkey=${PUBKEY};epoch=1`]
  const hns = await createHnsBackend({ hnsSrcPath: FAKE_DIR, authoritative: AUTH })

  const r = await hns.verify('alice.exist')
  assert.equal(r.found, true)
  assert.deepEqual(r.txt, [`v=nostr1;pubkey=${PUBKEY};epoch=1`])
  assert.equal(r.proofs.hns, true)
  assert.equal(SPVNode.instances.length, 1)
  assert.equal(SPVNode.instances[0].starts, 1)

  await hns.verify('alice.exist')
  assert.equal(SPVNode.instances.length, 1)
  assert.equal(SPVNode.instances[0].starts, 1)

  await hns.close()
  assert.equal(SPVNode.instances[0].stops, 1)
})

test('concurrent first lookups start a single node', async () => {
  const hns = await createHnsBackend({ hnsSrcPath: FAKE_DIR })
  await Promise.all([hns.verify('a.exist'), hns.verify('b.exist'), hns.treeState()])
  assert.equal(SPVNode.instances.length, 1)
  assert.equal(SPVNode.instances[0].starts, 1)
  await hns.close()
})

test('a caller-supplied node is used as is: never started or stopped', async () => {
  const own = new SPVNode({})
  SPVNode.instances.length = 0
  const hns = await createHnsBackend({ hnsSrcPath: FAKE_DIR, spv: own })
  const r = await hns.verify('missing.exist')
  assert.equal(r.found, false)
  await hns.close()
  assert.equal(own.starts, 0)
  assert.equal(own.stops, 0)
  assert.equal(SPVNode.instances.length, 0)
})

test('a missing module directory fails the lookup, not the constructor', async () => {
  const hns = await createHnsBackend({ hnsSrcPath: path.join(FAKE_DIR, 'does-not-exist') })
  await assert.rejects(hns.verify('alice.exist'))
  await hns.close()
})
