const sodium = require('sodium-native')
const bip39 = require('bip39')
const c = require('compact-encoding')
const assert = require('nanoassert')
const b4a = require('b4a')

const MASTER_CHAIN_CODE = b4a.from('ed25519 seed')
const HARDENED_OFFSET = 0x80000000

class ChainingKey {
  constructor () {
    this._buffer = b4a.alloc(64)

    this.chainKey = this._buffer.subarray(0, 32)
    this.chainCode = this._buffer.subarray(32)

    this.publicKey = b4a.alloc(32)
    this.secretKey = b4a.alloc(64)
  }

  static generateMnemonic () {
    return bip39.generateMnemonic()
  }

  static generateSeed (mnemonic) {
    return bip39.mnemonicToSeedSync(mnemonic)
  }

  static verify (signable, signature, publicKey) {
    return sodium.crypto_sign_verify_detached(signature, signable, publicKey)
  }

  static from ({ mnemonic, seed }) {
    assert(mnemonic || seed, 'No mnemonic or seed was passed.')

    if (mnemonic) seed = ChainingKey.generateSeed(mnemonic)

    const key = new ChainingKey()

    hmac(key._buffer, seed, MASTER_CHAIN_CODE)

    key._initialise()

    return key
  }

  clone () {
    const key = new ChainingKey()

    key.chainKey.set(this.chainKey)
    key.chainCode.set(this.chainCode)
    key._initialise()

    return key
  }

  get isKeychain () {
    return true
  }

  get (path) {
    const key = this.clone()
    key.derive(path)

    return key
  }

  derive (path) {
    for (const step of path) {
      const index = ensureHardened(step) // hardened indices are >= 2^31

      hmac(this._buffer, encodeDerivationData(this, index), this.chainCode)
      this._initialise()
    }
  }

  _initialise (seed) {
    sodium.crypto_sign_seed_keypair(this.publicKey, this.secretKey, this.chainKey)
  }
}

module.exports = ChainingKey

function hmac (output, data, key) {
  const innerPad = b4a.alloc(128, 0x36)
  const outerPad = b4a.alloc(128, 0x5c)

  bufferXor(innerPad, key)
  bufferXor(outerPad, key)

  const int = b4a.alloc(64)
  hash(b4a.concat([innerPad, data]), int)
  hash(b4a.concat([outerPad, int]), output)

  return output
}

function hash (data, output = b4a.alloc(64)) {
  sodium.crypto_hash_sha512(output, data)
  return output
}

function bufferXor (output, data) {
  assert(output.byteLength >= data.byteLength)

  for (let i = 0; i < data.byteLength; i++) {
    output[i] ^= data[i]
  }

  return output
}

function encodeDerivationData (key, step) {
  const state = { buffer: b4a.alloc(37), start: 0, end: 37 }

  c.uint8.encode(state, 0)
  c.fixed32.encode(state, key.chainKey)
  state.buffer.writeUInt32BE(step, state.start)

  state.buffer[33] |= 0x80

  return state.buffer
}

function ensureHardened (n) {
  if (n >= HARDENED_OFFSET) return n
  return n + HARDENED_OFFSET
}
