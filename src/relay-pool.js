/*
 * Relay transport — fetches signed events from Nostr relays over the standard
 * NIP-01 websocket protocol (REQ / EVENT / EOSE). Every event returned is
 * signature-verified (nostr-event.js) before it leaves this module, so a
 * lying relay can withhold but never forge — the Nostr half of the two-layer
 * trust model (resolver.js).
 *
 * The transport is injectable: the default uses the global WebSocket (Node
 * >=20). Tests pass a mock exposing the same fetchEvents(filters, relays)
 * shape and never open a socket.
 *
 * VERIFIED IN ELECTRON'S MAIN PROCESS (38.8.6 / Node 22.22, Linux and the
 * packaged Windows build): `globalThis.WebSocket` is present, is the WHATWG
 * one, and carries the onopen/onmessage/onerror/onclose + send/close surface
 * this file uses. Vendoring `ws` in here would add a dependency to fix a
 * problem that does not exist — and the import would resolve in a dev
 * checkout while being absent from the installed app, which is the exact
 * failure mode the header above exists to prevent.
 *
 * AN UNREACHABLE RELAY IS NOT AN ERROR HERE, AND THAT IS DELIBERATE.
 * `_fromOne` resolves to [] for a refused connection, a TLS failure, a DNS
 * failure and a timeout alike, so a total outage returns zero events rather
 * than throwing. Callers therefore CANNOT learn "the relays are down" from a
 * rejected promise — they must read `reached`/`attempted`/`relays` from the
 * *Detailed variants. A caller that reports a thrown exception as "could not
 * reach the relays" is guaranteed to be reporting something else entirely.
 */

import { verifyEvent } from './nostr-event.js'

/**
 * One canonical spelling per relay.
 *
 * `wss://nos.lol` and `wss://nos.lol/` are the same relay and used to become
 * two sockets to it — twice the handshakes, twice the signature checks, and a
 * "2 of 4 answered" that is really 1 of 2. The rules are nostr-tools'
 * (`normalizeURL` in utils.ts): default ports dropped, a bare path collapsed
 * to `/`, query parameters sorted, fragment discarded.
 */
export function normalizeRelayUrl (input) {
  const raw = String(input || '').trim()
  if (!/^wss?:\/\//i.test(raw)) return null
  let url
  try { url = new URL(raw) } catch { return null }
  if (!url.hostname) return null
  url.protocol = url.protocol.toLowerCase()
  url.hostname = url.hostname.toLowerCase()
  if ((url.protocol === 'wss:' && url.port === '443') ||
      (url.protocol === 'ws:' && url.port === '80')) url.port = ''
  if (url.pathname.endsWith('/')) url.pathname = url.pathname.replace(/\/+$/, '')
  url.searchParams.sort()
  url.hash = ''
  return url.toString()
}

/** The relay list, canonicalised and de-duplicated, dropping anything that is
 *  not a websocket URL at all. */
export function uniqueRelays (relays) {
  const out = []
  for (const r of relays || []) {
    const url = normalizeRelayUrl(r)
    if (url && !out.includes(url)) out.push(url)
  }
  return out
}

/**
 * Query a set of relays for events matching one filter, returning ALL verified
 * matches (caller picks newest). Resolves after EOSE from every relay or the
 * timeout — whichever comes first — and always resolves (a dead relay set
 * yields []).
 */
export class RelayPool {
  constructor ({ WebSocketImpl, timeout = 6000, maxEvents = 256 } = {}) {
    this.WebSocketImpl = WebSocketImpl || globalThis.WebSocket
    this.timeout = timeout
    this.maxEvents = maxEvents
  }

  /**
   * @param {object} filter  NIP-01 filter, e.g. {authors:[hex], kinds:[0], limit:5}
   * @param {string[]} relays  wss:// URLs
   * @returns {Promise<Array<object>>} verified events
   */
  async fetchEvents (filter, relays) {
    return (await this.fetchEventsDetailed(filter, relays)).events
  }

  /**
   * Like fetchEvents, but also says HOW MANY relays actually answered.
   *
   * The plain version reports "no events" identically whether the relays said
   * "nothing here" or never connected at all. For a read that is about to be
   * turned into a REPLACING write — a NIP-02 follow list, a NIP-65 relay list
   * — those two cases could not be more different: one means the user follows
   * nobody, the other means we have no idea who they follow. Publishing on
   * the second wipes the list, and the replaced event is unrecoverable.
   *
   * @returns {Promise<{events, reached: number, attempted: number}>}
   */
  async fetchEventsDetailed (filter, relays) {
    if (!this.WebSocketImpl) {
      throw new Error('no WebSocket implementation available — pass ' +
        '{WebSocketImpl} to RelayPool on a runtime with no global WebSocket')
    }
    const urls = uniqueRelays(relays)
    if (!urls.length) return { events: [], reached: 0, attempted: 0, relays: [] }
    // One set per QUERY, not per pool: the same note arrives from every relay
    // that holds it, and the schnorr check on each copy is the bulk of the
    // work in a feed load. Per-query keeps concurrent reads independent.
    const seen = new Set()
    const results = await Promise.all(urls.map(async (u) => {
      const list = await this._fromOne(u, filter, seen)
      // `_fromOne` resolves to [] both for "relay answered, nothing matched"
      // and for "relay never opened". It marks the difference on the array
      // when it can; absent the mark, a non-empty result proves it answered.
      return {
        relay: u,
        list,
        status: list.status || (list.reached ? 'eose' : 'failed'),
        reached: list.reached !== false && (list.reached === true || list.length > 0)
      }
    }))
    const byId = new Map()
    for (const { list } of results) {
      for (const ev of list) if (!byId.has(ev.id)) byId.set(ev.id, ev)
    }
    return {
      events: [...byId.values()],
      reached: results.filter((r) => r.reached).length,
      attempted: urls.length,
      // PER RELAY, not just a count. A UI that can only say "2 of 4" cannot
      // tell the user WHICH two, so it cannot tell them the one that is down
      // is the one their own name advertises — which is the difference
      // between "the network is flaky" and "nobody can reach you". `status`
      // separates "refused" from "too slow" from "wants AUTH", which are
      // three different things to do about it.
      relays: results.map((r) => ({
        relay: r.relay,
        reached: r.reached,
        status: r.status,
        // What this relay sent, duplicates included — see `delivered` in
        // `_fromOne`. `r.list.length` is post-dedup and would credit every
        // copy of a note to whichever relay happened to answer first.
        events: r.list.delivered ?? r.list.length
      }))
    }
  }

  /**
   * Newest verified event matching the filter across the relays, or null.
   */
  async fetchLatest (filter, relays) {
    return (await this.fetchLatestDetailed(filter, relays)).event
  }

  /** fetchLatest, plus how many relays answered. See fetchEventsDetailed. */
  async fetchLatestDetailed (filter, relays) {
    const detail = await this.fetchEventsDetailed(
      { ...filter, limit: filter.limit || 5 }, relays)
    const { events, reached, attempted } = detail
    events.sort((a, b) => b.created_at - a.created_at)
    return { event: events[0] || null, reached, attempted, relays: detail.relays || [] }
  }

  /**
   * Send one signed event to many relays.
   *
   * Publishing is fan-out, not a transaction: some relays accept, some reject
   * (rate limits, paid-relay policy, spam filters) and NONE of that makes the
   * event invalid. So this reports per-relay outcomes and never throws on a
   * partial result — the caller decides whether one acceptance is enough.
   *
   * Fan-out is also how a reply reaches someone whose client never reads our
   * relay: the same bytes go to their relays too, which is what makes a
   * conversation across servers work at all.
   *
   * @returns {Promise<Array<{relay, ok, message}>>} one entry per relay
   */
  async publish (event, relays) {
    if (!this.WebSocketImpl) {
      throw new Error('no WebSocket implementation available — pass ' +
        '{WebSocketImpl} to RelayPool on a runtime with no global WebSocket')
    }
    const check = verifyEvent(event)
    // Refuse locally rather than let every relay reject it: an unverifiable
    // event is a bug on our side, and "all relays said no" is a much harder
    // thing to debug than "we would not send this".
    if (!check.ok) throw new Error('refusing to publish an invalid event: ' + check.reason)
    const urls = uniqueRelays(relays)
    if (!urls.length) return []
    return Promise.all(urls.map((u) => this._publishOne(u, event)))
  }

  _publishOne (url, event) {
    return new Promise((resolve) => {
      let ws
      let done = false
      const finish = (ok, message) => {
        if (done) return
        done = true
        clearTimeout(timer)
        try { ws && ws.close() } catch {}
        resolve({ relay: url, ok, message })
      }
      const timer = setTimeout(() => finish(false, 'timeout'), this.timeout)
      try {
        ws = new this.WebSocketImpl(url)
      } catch (err) {
        return finish(false, String(err && err.message ? err.message : err))
      }
      ws.onerror = () => finish(false, 'connection failed')
      ws.onclose = () => finish(false, 'closed before OK')
      ws.onopen = () => {
        try { ws.send(JSON.stringify(['EVENT', event])) } catch (err) { finish(false, String(err)) }
      }
      ws.onmessage = (msg) => {
        let frame
        try { frame = JSON.parse(typeof msg.data === 'string' ? msg.data : '') } catch { return }
        if (!Array.isArray(frame)) return
        // NIP-01: ["OK", <id>, <true|false>, <message>]. Match on the id --
        // a relay may be handling other subscriptions on this socket.
        if (frame[0] === 'OK' && frame[1] === event.id) {
          finish(frame[2] === true, String(frame[3] || ''))
        } else if (frame[0] === 'NOTICE') {
          // Not an outcome on its own; relays send notices for all sorts of
          // reasons and some never send OK at all. Recorded, not resolved.
          this.lastNotice = String(frame[1] || '')
        }
      }
    })
  }

  _fromOne (url, filter, seen) {
    return new Promise((resolve) => {
      let ws
      const events = []
      // HOW THIS RELAY ENDED, not just whether anything arrived:
      //   'eose'    it answered and said that is everything
      //   'timeout' the socket opened but nothing finished it in time
      //   'failed'  it never opened at all (refused, DNS, TLS)
      //   'closed'  it hung up on us mid-subscription
      //   'auth'    it demands NIP-42 AUTH, which we do not speak yet
      // `reached` collapses those to a boolean for existing callers, but a
      // relay that is alive and merely SLOW must not be counted as
      // unreachable: that is the input to the guard that refuses to replace a
      // follow list, and mislabelling it there refuses legitimate writes.
      events.reached = false
      events.status = 'failed'
      // How many matching events THIS relay sent us, duplicates included.
      // `events` itself only holds the copies this query had not seen yet, so
      // it under-counts every relay but the first to deliver a given note —
      // and a relay that answered with nothing but duplicates would look
      // unreachable. `delivered` is what "did this relay have it" is read off.
      events.delivered = 0
      const subId = 'hns' + Math.random().toString(36).slice(2, 10)
      let done = false
      const finish = (status) => {
        if (done) return
        done = true
        if (status) events.status = status
        events.reached = events.status === 'eose' || events.delivered > 0
        clearTimeout(timer)
        try { ws && ws.close() } catch {}
        resolve(events)
      }
      const timer = setTimeout(() => finish(events.status === 'failed' ? 'failed' : 'timeout'), this.timeout)
      try {
        ws = new this.WebSocketImpl(url)
      } catch {
        clearTimeout(timer)
        events.status = 'failed'
        return resolve(events)
      }
      ws.onopen = () => {
        // The socket is up: from here a silence is slowness, not absence.
        events.status = 'timeout'
        try { ws.send(JSON.stringify(['REQ', subId, filter])) } catch { finish('failed') }
      }
      ws.onmessage = (msg) => {
        let data
        try { data = JSON.parse(typeof msg.data === 'string' ? msg.data : String(msg.data)) } catch { return }
        if (!Array.isArray(data)) return
        if (data[0] === 'EVENT' && data[1] === subId && data[2]) {
          const ev = data[2]
          // Dedup BEFORE verifying: the same note arrives from every relay
          // that has it, and a schnorr check per copy is the bulk of the work
          // in a feed load.
          if (seen && seen.has(ev.id)) {
            events.delivered++
          } else if (verifyEvent(ev).ok) {
            events.push(ev)
            events.delivered++
            if (seen) seen.add(ev.id)
          }
          // Cap on what the relay SENT, not on what survived dedup: a relay
          // replaying a page we already have would otherwise never reach the
          // cap and would stream until the timeout.
          if (events.delivered >= this.maxEvents) finish('eose')
        } else if (data[0] === 'EOSE' && data[1] === subId) {
          finish('eose')
        } else if (data[0] === 'CLOSED' && data[1] === subId) {
          // NIP-42: a relay that wants AUTH says so here. We do not speak it
          // yet, and saying "closed" would hide a fixable configuration
          // problem behind a generic outage.
          finish(/^auth-required/i.test(String(data[2] || '')) ? 'auth' : 'closed')
        }
      }
      ws.onerror = () => finish(events.status === 'timeout' ? 'timeout' : 'failed')
      ws.onclose = () => finish(events.status === 'timeout' ? 'closed' : 'failed')
    })
  }
}
