#!/usr/bin/env node
/*
 * hns-nostr — CLI for the standalone HNS -> Nostr resolver (RES-1).
 *
 *   hns-nostr resolve alice.exist
 *   hns-nostr resolve alice@hns.one --json
 *   hns-nostr resolve npub1... --relay wss://relay.hns.one
 *   hns-nostr encode <64-hex>                 # -> npub / nprofile
 *   hns-nostr classify <input>                # show how an input is parsed
 *
 * `resolve` stands up the REAL SPV chain-proof + DNSSEC backend (reusing
 * wildroot-web3-resolution's modules) and a WebSocket relay pool. `encode` /
 * `classify` are offline and need no node.
 */

import { createResolver, classifyInput, encodeNpub, encodeNprofile } from '../src/index.js'

function parseArgs (argv) {
  const args = { _: [], relay: [], json: false }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--json') args.json = true
    else if (a === '--relay') args.relay.push(argv[++i])
    else if (a === '--nip05-domain') args.nip05Domain = argv[++i]
    else if (a === '--timeout') args.timeout = Number(argv[++i])
    else if (a === '--spv-url') args.spvUrl = argv[++i]
    else if (a.startsWith('--')) { /* ignore unknown flags */ }
    else args._.push(a)
  }
  return args
}

function printProof (p, json) {
  if (json) { console.log(JSON.stringify(p, null, 2)); return }
  const y = (b) => (b ? 'yes' : 'no ')
  console.log(`  identity     ${p.hnsName || p.nip05 || p.npub}`)
  console.log(`  pubkey       ${p.pubkeyHex}`)
  console.log(`  npub         ${p.npub}`)
  console.log(`  nprofile     ${p.nprofile}`)
  if (p.hnsName) console.log(`  hnsName      ${p.hnsName}`)
  if (p.nip05) console.log(`  nip05        ${p.nip05}`)
  console.log(`  epoch        ${p.epoch === null ? '(n/a)' : p.epoch}`)
  console.log(`  relays       ${p.relays.join(', ') || '(none)'}`)
  console.log(`  binding      ${p.binding}${p.complete ? ' (complete)' : ''}${p.historical ? ' (HISTORICAL)' : ''}${p.managed ? ' [managed SLD]' : ''}`)
  console.log('  proofs       ' +
    `hns=${y(p.proofs.hns)} dnssec=${y(p.proofs.dnssec)} ` +
    `nostrAck=${y(p.proofs.nostrAcknowledgement)} nip05=${y(p.proofs.nip05)}`)
  console.log(`  path         ${p.resolutionPath}`)
  for (const w of p.warnings) console.log(`  ! ${w}`)
}

async function main () {
  const args = parseArgs(process.argv.slice(2))
  const cmd = args._[0]
  const target = args._[1]

  if (!cmd || cmd === 'help' || cmd === '--help') {
    console.log('usage: hns-nostr <resolve|encode|classify> <input> [--json] [--relay wss://...]')
    process.exit(cmd ? 0 : 1)
  }

  if (cmd === 'classify') {
    if (!target) { console.error('classify needs an input'); process.exit(1) }
    console.log(JSON.stringify(classifyInput(target, {
      nip05Domains: args.nip05Domain ? [args.nip05Domain] : undefined
    }), null, 2))
    return
  }

  if (cmd === 'encode') {
    if (!target || !/^[0-9a-f]{64}$/i.test(target)) {
      console.error('encode needs a 64-char hex pubkey'); process.exit(1)
    }
    const hex = target.toLowerCase()
    console.log('npub     ', encodeNpub(hex))
    console.log('nprofile ', encodeNprofile({ pubkeyHex: hex, relays: args.relay }))
    return
  }

  if (cmd === 'resolve') {
    if (!target) { console.error('resolve needs an input'); process.exit(1) }
    const resolver = await createResolver({
      defaultRelays: args.relay.length ? args.relay : undefined,
      nip05Domains: args.nip05Domain ? [args.nip05Domain] : undefined,
      relayTimeout: args.timeout,
      spvOptions: args.spvUrl ? { url: args.spvUrl } : undefined
    })
    try {
      const proof = await resolver.resolve(target)
      printProof(proof, args.json)
    } catch (err) {
      if (args.json) console.log(JSON.stringify({ error: err.message, code: err.code || null }, null, 2))
      else console.error(`resolve failed: ${err.message}`)
      process.exitCode = 2
    } finally {
      await resolver.close()
    }
    return
  }

  console.error(`unknown command: ${cmd}`)
  process.exit(1)
}

main().catch((err) => { console.error(err); process.exit(1) })
