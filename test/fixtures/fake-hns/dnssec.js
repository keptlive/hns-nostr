// Stand-in for wildroot-web3-resolution's dnssec.js. The fixtures publish no
// DS records, so the backend never reaches this.

export function validateChain () {
  return { ok: false, reason: 'not used by the fixtures' }
}
