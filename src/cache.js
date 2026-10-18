/*
 * Resolver cache (DESIGN §9). Cache key =
 *   HNS name + ownership epoch + verified HNS tree state.
 *
 * The epoch and tree-state in the key are what make transfers safe: on an
 * ownership change the epoch increments (and the tree state moves), so the new
 * lookup MISSES the old entry — the new owner's binding is resolved fresh, and
 * a still-cached old-epoch key is offered only as `historical`, never as the
 * current controller. A caller that resolves the same name and gets a result
 * under a NEWER epoch marks the prior ones stale via note().
 */

export class ResolverCache {
  constructor ({ ttl = 5 * 60 * 1000, max = 1024 } = {}) {
    this.ttl = ttl
    this.max = max
    this.map = new Map() // key -> { value, at }
    this.latestEpoch = new Map() // hnsName -> highest epoch seen
  }

  static key (hnsName, epoch, treeState) {
    return `${hnsName}|${epoch}|${treeState || ''}`
  }

  get (hnsName, epoch, treeState) {
    const k = ResolverCache.key(hnsName, epoch, treeState)
    const hit = this.map.get(k)
    if (!hit) return null
    if (hit.at + this.ttl <= Date.now()) { this.map.delete(k); return null }
    // Refresh LRU position.
    this.map.delete(k)
    this.map.set(k, hit)
    // A key cached under an epoch older than the highest we have seen for this
    // name is historical, never the current controller (DESIGN §9).
    const latest = this.latestEpoch.get(hnsName)
    const historical = latest !== undefined && Number(epoch) < Number(latest)
    return { ...hit.value, historical }
  }

  set (hnsName, epoch, treeState, value) {
    const k = ResolverCache.key(hnsName, epoch, treeState)
    if (this.map.size >= this.max) {
      this.map.delete(this.map.keys().next().value) // evict oldest
    }
    this.map.set(k, { value, at: Date.now() })
    const prev = this.latestEpoch.get(hnsName)
    if (prev === undefined || Number(epoch) > Number(prev)) {
      this.latestEpoch.set(hnsName, Number(epoch))
    }
  }

  /** Note the current epoch for a name (e.g. from a registry) so older cached
   * entries are reported historical without needing a fresh resolve. */
  noteEpoch (hnsName, epoch) {
    const prev = this.latestEpoch.get(hnsName)
    if (prev === undefined || Number(epoch) > Number(prev)) {
      this.latestEpoch.set(hnsName, Number(epoch))
    }
  }

  clear () { this.map.clear(); this.latestEpoch.clear() }
}
