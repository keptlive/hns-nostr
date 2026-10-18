// Stand-in for wildroot-web3-resolution's spv.js. It records every node the
// backend creates, so a test can see whether and when one was started.

export const zone = { records: {} } // tld -> chain records returned by getResource

export class SPVNode {
  static instances = []

  static reset () {
    SPVNode.instances.length = 0
    zone.records = {}
  }

  constructor (options) {
    this.options = options
    this.starts = 0
    this.stops = 0
    SPVNode.instances.push(this)
  }

  async start () { this.starts++ }
  async stop () { this.stops++ }
  async isSynced () { return true }
  async info () { return { blocks: 100 } }
  async getResource (tld) {
    const records = zone.records[tld]
    return records ? { records } : null
  }
}
