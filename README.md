# hns-nostr — standalone HNS → Nostr resolver

The open-source resolver at the center of the Nostr work (RES-1). It turns any
of the six Nostr/HNS identity forms into a **proof object**, doing REAL local
Handshake SPV chain-proof verification and DNSSEC validation (not a trusted
remote lookup) for the HNS half, and BIP-340 Nostr signature verification for
the native half. It works for **any Handshake TLD** — a registry owner who
publishes a `_nostr` record gets Nostr identity resolution for free.

Authoritative spec: [`DESIGN.md`](./DESIGN.md). This README documents the code.

## Two-layer trust (LAW L3)

```
HNS / DNSSEC   proves the readable mapping   name  → pubkey    proofs.hns / proofs.dnssec
Nostr sig      proves the canonical object   pubkey → name     proofs.nostrAcknowledgement
```

Both must pass for a *complete* (mutual) binding. The native Nostr key and its
`npub`/`nprofile` always stay canonical and visible.

## Install / run

```
npm install                 # @noble/curves + @noble/hashes only
npm test                    # 42 unit tests, fully mocked (no chain node, no sockets)

node bin/hns-nostr.js resolve alice.exist
node bin/hns-nostr.js resolve alice@hns.one --json
node bin/hns-nostr.js resolve npub1… --relay wss://relay.hns.one
node bin/hns-nostr.js classify _@alice.exist     # offline: show how an input parses
node bin/hns-nostr.js encode <64-hex>            # offline: → npub / nprofile
```

## Embeddable API (what Wildroot calls — BR-7)

The resolver is **dependency-injected**, so the same object runs embedded in the
browser, as a service, or under tests. Inject three collaborators:

```js
import { NostrResolver } from 'hns-nostr'

const resolver = new NostrResolver({
  hns,             // HNS backend:  verify(name) → { found, txt[], proofs{hns,dnssec}, treeState, tld }
  relays,          // relay pool:   fetchLatest(filter, relays[]) / fetchEvents(filter, relays[])
  http,            // fetch impl for NIP-05 (default: global fetch)
  nip05Domains,    // ICANN NIP-05 domains we own (default ['hns.one'])
  defaultRelays,   // relay hints to always include (default ['wss://social.hns.one', 'wss://relay.damus.io', 'wss://nos.lol'])
  cache,           // ResolverCache (default: a fresh one)
  epochOracle      // optional (hnsName) → expected current epoch, for staleness
})

const proof = await resolver.resolve('alice.exist')
```

`resolve()` accepts every DESIGN §5 input form:
`alice.exist`, `_@alice.exist`, `alice@hns.one`, `npub1…`, `nprofile1…`,
`nostr:npub1…`.

### Batteries-included factory (CLI / service / standalone)

```js
import { createResolver } from 'hns-nostr'
const resolver = await createResolver()      // wires the REAL SPV+DNSSEC backend
const proof = await resolver.resolve('alice@hns.one')
await resolver.close()                        // stops the spawned SPV node
```

`createResolver()` builds the default backend from **Wildroot's HNS core**
(`../browser/src/hns`: `spv.js` for the SPV Urkel proof, `dns-query.js` for the
authoritative hop, `dnssec.js` for chain-anchored DNSSEC validation) and a
`WebSocket` relay pool. Point it elsewhere with `browserHnsPath`, or inject your
own `hns` / `relays`.

### Proof object (DESIGN §5)

```jsonc
{
  "pubkeyHex": "…",
  "npub": "npub1…",
  "nprofile": "nprofile1…",
  "hnsName": "alice.exist",          // null unless an HNS proof actually succeeded
  "nip05": "alice@hns.one",          // conventional NIP-05 identity, or null
  "relays": ["wss://relay.hns.one"], // record hints ∪ NIP-65 kind:10002
  "epoch": 7,                        // ownership epoch (LAW L4)
  "proofs": { "hns": true, "dnssec": true, "nostrAcknowledgement": true, "nip05": true },
  "binding": "mutual",               // mutual | hns-control | nip05-compatible | none
  "managed": false,                  // HNS.ONE-managed SLD (needs a mutual binding to be complete)
  "complete": true,
  "historical": false,               // a stale-epoch key is historical, never current
  "warnings": [],
  "resolutionPath": "hns-native"     // hns-native | nip05 | npub | nprofile
}
```

### The three binding states (DESIGN §3)

| binding | meaning |
|---|---|
| `hns-control` | valid HNS/DNSSEC record — the name controls the key |
| `mutual` | HNS record **and** a signed `kind:0` with a matching `hns` claim agree — the only *complete* binding |
| `nip05-compatible` | `alice@hns.one` also resolves to the same key |

### Invariants (DESIGN §6, enforced + tested)

1. **A NIP-05 failure never invalidates a valid HNS-native binding.** With
   `alice@hns.one` down, `alice.exist` still resolves; only `proofs.nip05`
   drops to `false`.
2. **A valid `alice@hns.one` is never reported as HNS control.** `proofs.hns`
   stays `false` unless a *separate* HNS proof for the key succeeds — an upgrade
   that only happens when the profile's `hns` claim resolves to an HNS record
   that binds this exact key.

### Managed SLDs (DESIGN §2 caveat)

A `_nostr` record with a `receipt=` field is treated as a managed SLD. DNSSEC
then only proves HNS.ONE *published* the record, so the customer's signed
`kind:0` acknowledgement (the mutual binding) is required — `complete` is
`false` until it is present.

## Module map

| File | Role |
|---|---|
| `src/resolver.js` | the orchestrator — DESIGN §6 order + invariants + binding states |
| `src/hns-backend.js` | default backend, **reuses `browser/src/hns`** for SPV + DNSSEC |
| `src/relay-pool.js` | NIP-01 WebSocket transport; verifies every event before returning it |
| `src/nip05.js` | NIP-05 fetch (no redirects) + verification |
| `src/nostr-event.js` | event id (NIP-01) + BIP-340 schnorr signature check |
| `src/record.js` | `_nostr` TXT parse + ownership-epoch validation |
| `src/nip19.js` | self-contained bech32 + `npub`/`nprofile` |
| `src/cache.js` | cache keyed by name + epoch + verified HNS tree state (DESIGN §9) |
| `src/input.js` | input classification for the six accepted forms |
| `bin/hns-nostr.js` | CLI |

## What's implemented vs stubbed

- **Implemented:** all six input forms; the full §6 resolver order for both the
  HNS-native and NIP-05 paths; real SPV + DNSSEC verification via the reused
  browser core; real Nostr signature verification; the three binding states;
  both invariants; managed-SLD detection with the mutual-binding requirement;
  epoch validation + §9 cache keying with historical marking; NIP-65 relay
  discovery; CLI + embeddable library.
- **Partial / pending a frozen spec:** the managed-SLD **assignment-receipt
  signature** is detected (`receipt=`) and gates completeness on the mutual
  binding, but full cryptographic verification of the receipt payload waits on
  INF-4 freezing its exact format. `epochOracle` is an injection point for a
  live current-epoch source (registry/panel); on its own the resolver validates
  the epoch is a well-formed integer and uses it for cache keying.
