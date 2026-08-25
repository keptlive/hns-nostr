# HNS ↔ Nostr resolver & dual-publication — design

> **STATUS NOTE, 2026-08-21.** This document is the ORIGINAL design. Where it
> differs from what shipped, `~/hns/NOSTR-STATUS.md` wins.
>
> The one difference that will bite you: this file uses `alice@hns.one`
> throughout as the "conventional NIP-05" form (§1, §3, §4, §6, §8). **That
> endpoint does not exist.** `hns.one/.well-known/nostr.json` is not served,
> and the gateway answers only the `_` local part at the name's own host. The
> shipped identity is `_@alice.<tld>.hns.one`, which ordinary clients display
> as the bare `alice.<tld>.hns.one`.
>
> Copying §3's example `kind:0` verbatim produces a profile whose `nip05`
> fails verification silently in every client. Use `_@<name>.hns.one`.

Source: Matt's spec, 2026-08-18. This is the reference every Nostr task reads.
The decision is NOT "put a Nostr key in HNS." It is: **ship an open, HNS-aware
Nostr resolver, while dual-publishing everything through conventional Nostr
standards so users stay compatible with existing clients.** The legacy identity
path is NIP-05; NIP-04 DMs and old relay-list formats are separate legacy cases
handled differently.

Guiding rule: HNS-aware resolution only *improves* identity, proof, relay
discovery, and key-change/recovery handling. It never changes Nostr event
encoding or signatures. Do not create an isolated "HNS Nostr network."

## 1. Two equivalent identity routes (for user "alice")

| Route | Identifier | Who resolves it |
|---|---|---|
| HNS-native | `alice.exist` | HNS-aware clients (Wildroot) |
| Root NIP-05 form | `_@alice.exist`, shown as `alice.exist` | HNS-aware NIP-05 clients |
| Conventional NIP-05 | `alice@hns.one` | every ordinary Nostr client |
| Cryptographic id | `npub1…` | every Nostr client |
| Portable profile | `nprofile1…` | Nostr clients (with relay hints) |

NIP-05 allows `_@domain` to display as just `domain`, so `_@alice.exist` shows
as `alice.exist`; ordinary clients simply lack HNS resolution.

## 2. HNS-native record (a Wildroot/HNS convention, NOT an existing NIP)

```
_nostr.alice.exist TXT
"v=nostr1;pubkey=<64-hex>;epoch=7;relay=wss://relay.hns.one"
```
Extra relay URLs go in additional TXT strings. The resolver MUST verify, in
order: (1) the Handshake root result via embedded SPV; (2) the `.exist`
delegation; (3) the DNSSEC chain for `alice.exist`; (4) the `_nostr.alice.exist`
record; (5) the current ownership epoch; (6) the Nostr key's signed profile
claim (§3).

**Managed-SLD caveat (security-critical):** for HNS.ONE-managed SLDs the result
must contain or reference the **owner-signed assignment receipt + epoch** —
otherwise DNSSEC only proves HNS.ONE *published* the record, not that the SLD
customer approved it. The customer's `kind:0` acknowledgement (§3, the mutual
binding) is what supplies that approval; treat "mutual binding confirmed" as the
only complete state for managed names.

## 3. Reciprocal Nostr publication (two-way binding)

The Nostr key acknowledges the HNS name via an ordinary signed `kind:0`:
```json
{"name":"alice.exist","display_name":"Alice","nip05":"alice@hns.one",
 "hns":"alice.exist","website":"https://hns.one/alice"}
```
`nip05` is standard; the extra `hns` field is ignored by ordinary clients,
recognized by HNS-aware ones. Binding:
```
HNS/DNSSEC:      alice.exist  → pubkey
Nostr signature: pubkey       → alice.exist
```
Three states the resolver distinguishes:
- **HNS control confirmed** — valid HNS/DNSSEC record.
- **Mutual binding confirmed** — HNS record and signed `kind:0` agree (the only
  *complete* binding).
- **NIP-05 compatible** — `alice@hns.one` also resolves to the same key.

## 4. Conventional NIP-05 publication (from the SAME identity record)

`GET https://hns.one/.well-known/nostr.json?name=alice`
```json
{"names":{"alice":"<64-hex-lowercase>"},
 "relays":{"<64-hex-lowercase>":["wss://relay.hns.one","wss://second-independent.example"]}}
```
Requirements (from the NIP-05 spec): lowercase hex keys (never npub); include
the `relays` map; `Access-Control-Allow-Origin: *`; **never redirect** the
endpoint; generate from the **same** identity record the HNS resolver uses —
never a separate hand-edited DB.

## 5. What Wildroot ships — THREE interoperable pieces (not just a browser feature)

1. **Embedded resolver** — a library in Wildroot accepting `alice.exist`,
   `_@alice.exist`, `alice@hns.one`, `npub1…`, `nprofile1…`, `nostr:npub1…` and
   returning:
   ```json
   {"pubkeyHex":"…","npub":"npub1…","nprofile":"nprofile1…",
    "hnsName":"alice.exist","nip05":"alice@hns.one","relays":["wss://relay.hns.one"],
    "epoch":7,
    "proofs":{"hns":true,"dnssec":true,"nostrAcknowledgement":true,"nip05":true}}
   ```
2. **Standalone open-source resolver** — the SAME resolver as a reusable package
   + CLI/service, working for **any Handshake TLD**, not only `.exist`. Strategic:
   other HNS registry owners publish `_nostr` records and instantly get Nostr
   identity resolution through Wildroot. This is the main HNS contribution.
3. **Proof service** — clearnet + onion endpoints (`https://proof.hns.one`,
   `http://<svc>.onion`) returning HNS/DNSSEC proof material. The local resolver
   VERIFIES this material; it is never blindly trusted.

## 6. Resolver order

**For `alice.exist`:** (1) local HNS SPV; (2) verify root proof + DNSSEC
delegation; (3) fetch `_nostr.alice.exist`; (4) validate ownership epoch;
(5) get hex pubkey + relay hints; (6) fetch latest signed `kind:0`; (7) confirm
its `hns` == `alice.exist`; (8) optionally verify `alice@hns.one` via NIP-05;
(9) fetch NIP-65 relay list; (10) build an `nprofile` with pubkey + relay hints.

**For `alice@hns.one`:** (1) resolve `hns.one` via the configured ICANN ODoH
path; (2) fetch the NIP-05 endpoint; (3) ignore redirects; (4) extract hex key +
relays; (5) fetch matching `kind:0`; (6) confirm it claims the same `nip05`;
(7) upgrade to `alice.exist` ONLY if the separate HNS proof succeeds.

**Invariants:** NIP-05 failure must NOT invalidate an otherwise valid HNS-native
binding. A valid `alice@hns.one` response must NEVER be represented as proof of
HNS control.

## 7. Dual publication to normal Nostr

Every post is an ordinary signed Nostr event, published to `wss://relay.hns.one`
+ the author's other NIP-65 write relays + mentioned recipients' read relays
when appropriate. Publish the author's `kind:10002` relay list to the same set
(NIP-65 recommends ~2–4 relays). HNS-aware resolution changes none of the event
encoding or signatures.

## 8. Compatibility publication matrix

| Info | Modern/native | Compatibility |
|---|---|---|
| Identity | `_nostr.alice.exist` | NIP-05 `alice@hns.one` |
| Profile | `kind:0` + `hns` claim | normal `kind:0` fields |
| Relay discovery | NIP-65 `kind:10002` | NIP-05 JSON `relays` map |
| Sharing | `alice.exist` | `npub`, `nprofile`, `alice@hns.one` |
| Posts | HNS.ONE relay | same event to public relays |
| Follows | normal NIP-02 `kind:3` | no proprietary format |
| Private msgs | NIP-17/44/59 | read legacy NIP-04 only |

**Old relay-list format:** MAY *read* older relay hints incl. relay URLs on
NIP-02 follow entries; do NOT write private relay config into `kind:3` content
(NIP-02 defines that content as unused).

**Old DMs:** *read* NIP-04 for compatibility, *send* NIP-17 by default. Never
publish a DM in both formats (duplicates + weakens NIP-17 gift-wrap metadata
protection). Legacy NIP-04 send requires an explicit warning and only when the
recipient can't receive NIP-17.

## 9. Transfers & caching (ties to LAW L4 epochs)

On `alice.exist` ownership change: increment the epoch; immediately remove the
HNS→Nostr binding; remove `alice` from the NIP-05 response; invalidate resolver
caches; require the new owner to bind their own key; never auto-point followers
to the new key; never transfer old notes/DMs/relay data. Cache key =
`HNS name + ownership epoch + verified HNS tree state`. A stale cached key may be
shown as *historical*, never as the current controller.

## Reference NIPs
NIP-05 (identity), NIP-65 (relay list `kind:10002`), NIP-02 (follows `kind:3`),
NIP-17/44/59 (private DMs), NIP-04 (legacy DMs, read-only).
