# hns-nostr

A resolver that maps a Handshake name, a NIP-05 address, an `npub` or an
`nprofile` to a Nostr public key, and reports what was proven: the Handshake
side by a local SPV chain proof and DNSSEC validation, the Nostr side by
checking event signatures. Library and command line. The design is in
[`DESIGN.md`](DESIGN.md).

## Requirements

Node.js 20 or later. Resolving Handshake names with the default backend also
needs a checkout of
[wildroot-web3-resolution](https://github.com/keptlive/wildroot-web3-resolution)
next to this one, with its dependencies installed. It supplies the SPV node
(hsd in SPV mode), the DNS client and the DNSSEC validator. The offline
commands, and the library with your own `hns` backend, do not need it.

```sh
git clone https://github.com/keptlive/wildroot-web3-resolution
git clone https://github.com/keptlive/hns-nostr
(cd wildroot-web3-resolution && npm ci)
cd hns-nostr && npm ci && npm test
```

Pass `hnsSrcPath` to `createResolver()` to load those modules from elsewhere.
With `--spv-url`, the resolver uses an hsd SPV node you already run; otherwise
it uses one on the default port or starts one.

## Command line

```sh
node bin/hns-nostr.js classify _@alice.exist     # offline: how an input is parsed
node bin/hns-nostr.js encode <64-hex-pubkey>     # offline: npub and nprofile
node bin/hns-nostr.js resolve <handshake-name>   # the name must publish a _nostr record
node bin/hns-nostr.js resolve npub1zec3ndwmv7dapve77p2wlu7vkehymec8xynrr8c63tlkzw4cwl0sujpjmn --json
```

Options: `--json`, `--relay wss://...` (repeatable; replaces the default
relays), `--nip05-domain <domain>`, `--timeout <ms>`, `--spv-url <url>`.

The `npub` above is the hns.one project identity. Its profile claims the
NIP-05 address `_@hnsone.14898.hns.one`, which the resolver checks.

A Handshake name binds a key with a TXT record:

```
_nostr.alice.exist TXT "v=nostr1;pubkey=<64-hex>;epoch=7;relay=wss://social.hns.one"
```

## Library

```js
import { createResolver } from 'hns-nostr'

const resolver = await createResolver()
const proof = await resolver.resolve('npub1...')
await resolver.close()   // stops the SPV node if it started one
```

To embed it without the default backend, construct `NostrResolver` with an
`hns` object (`verify(name)`), a relay pool and an optional `fetch`; see
`src/resolver.js` and the mocks in `test/helpers.js`.

`resolve()` returns the key (`pubkeyHex`, `npub`, `nprofile`), the relays,
the ownership `epoch`, `proofs` (`hns`, `dnssec`, `nostrAcknowledgement`,
`nip05`), `warnings`, and a `binding`:

| binding | meaning |
|---|---|
| `hns-control` | a valid `_nostr` record binds the key |
| `mutual` | that record and the key's signed `kind:0` profile name each other; the only complete binding |
| `nip05-compatible` | a NIP-05 address resolves to the key; this never counts as Handshake control |

## NIP-05 addresses on hns.one

hns.one serves NIP-05 at each name's own host, with the local part `_`, so
the address for `hnsone.14898` is `_@hnsone.14898.hns.one`. An address goes through
NIP-05 when its domain is a configured NIP-05 domain or a host under one, and
the default is `hns.one`:

```sh
node bin/hns-nostr.js resolve _@hnsone.14898.hns.one
```

The result is a `nip05-compatible` binding, with the key's signed profile
confirming the address. Any other `_@` input is the root form of a Handshake
name: `_@alice.exist` resolves as `alice.exist`. `--nip05-domain` (or
`nip05Domains`) replaces the default list.

## Not implemented

- The signature on a managed-name assignment receipt (`receipt=`) is not
  verified. Its presence marks the name as managed, and a managed name is
  complete only with a mutual binding.
- `epochOracle` is an injection point for a live epoch source. Without one,
  the epoch is checked for form and used as a cache key.

## License

MIT
