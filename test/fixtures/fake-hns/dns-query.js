// Stand-in for wildroot-web3-resolution's dns-query.js: answers TXT queries
// from an in-memory table instead of the network.

export const TYPES = { TXT: 16, RRSIG: 46, DNSKEY: 48 }

export const answers = { txt: {} } // owner name -> array of TXT strings

export async function query (server, port, name, type) {
  const strings = type === TYPES.TXT ? answers.txt[name] : null
  return { answers: (strings || []).map((s) => ({ type: TYPES.TXT, txt: [s] })) }
}
