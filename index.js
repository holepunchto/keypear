const sodium = require('sodium-native')
const b4a = require('b4a')

const EMPTY = b4a.alloc(32)

class Keychain {
  constructor (home = Keychain.keyPair(), base = null, tweak = null) {
    this.home = toScalarKeyPair(fromKeyPair(home))
    this.base = base || this.home
    this.tweak = tweak
    this.head = tweak
      ? add(tweak, this.base, allocKeyPair(!!this.base.scalar))
      : this.base
  }

  get isKeychain () {
    return true
  }

  get publicKey () {
    return this.head.publicKey
  }

  get (name) {
    if (!name) return createSigner(this.head)

    const keyPair = allocKeyPair(!!this.base.scalar)
    add(this.base, this._getTweak(name), keyPair)

    return createSigner(keyPair)
  }

  sub (name) {
    const tweak = this._getTweak(name)
    if (this.tweak) add(tweak, this.tweak, tweak)

    return new Keychain(this.home, this.base, tweak)
  }

  checkout (keyPair) {
    return new Keychain(this.home, fromKeyPair(keyPair), null)
  }

  _getTweak (name) {
    if (typeof name === 'string') name = b4a.from(name)
    if (!b4a.isBuffer(name)) return name // keypair

    const cur = this.tweak ? this.tweak.publicKey : EMPTY
    return tweakKeyPair(toBuffer(name), cur)
  }

  static from (k) {
    if (Keychain.isKeychain(k)) { // future compat
      return k instanceof Keychain ? k : new Keychain(k.home, k.base, k.tweak)
    }
    return new Keychain(k)
  }

  static isKeychain (k) {
    return !!(k && k.isKeychain)
  }

  static seed () {
    const buf = b4a.alloc(32)
    sodium.randombytes_buf(buf)
    return buf
  }

  static keyPair (seed) {
    const buf = b4a.alloc(96)
    const publicKey = buf.subarray(0, 32)
    const secretKey = buf.subarray(32, 96)
    const scalar = secretKey.subarray(0, 32)

    if (seed) sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
    else sodium.crypto_sign_keypair(publicKey, secretKey)

    sodium.experimental_crypto_tweak_ed25519_sk_to_scalar(scalar, secretKey)

    return {
      publicKey,
      scalar
    }
  }
}

module.exports = Keychain

function add (a, b, out) {
  sodium.experimental_crypto_tweak_ed25519_publickey_add(out.publicKey, a.publicKey, b.publicKey)
  if (a.scalar && b.scalar) {
    sodium.experimental_crypto_tweak_ed25519_secretkey_add(out.scalar, a.scalar, b.scalar)
  }
  return out
}

function fromKeyPair (keyPair) {
  if (b4a.isBuffer(keyPair)) return { publicKey: keyPair, scalar: null }
  return toScalarKeyPair(keyPair)
}

function allocKeyPair (signer) {
  const buf = b4a.alloc(signer ? 64 : 32)
  return {
    publicKey: buf.subarray(0, 32),
    scalar: signer ? buf.subarray(32, 64) : null
  }
}

function toScalarKeyPair (keyPair) {
  if (!keyPair.secretKey) return keyPair

  const scalar = b4a.alloc(32)
  sodium.experimental_crypto_tweak_ed25519_sk_to_scalar(scalar, keyPair.secretKey)
  return { publicKey: keyPair.publicKey, scalar }
}

function tweakKeyPair (name, prev) {
  const keyPair = allocKeyPair(true)
  const seed = b4a.allocUnsafe(32)
  sodium.crypto_generichash_batch(seed, [prev, name])
  sodium.experimental_crypto_tweak_ed25519(keyPair.scalar, keyPair.publicKey, seed)
  return keyPair
}

function createSigner (kp) {
  if (kp.scalar) {
    return {
      publicKey: kp.publicKey,
      scalar: kp.scalar,
      sign (signable) {
        const sig = b4a.alloc(64)
        sodium.experimental_crypto_tweak_ed25519_sign_detached(sig, signable, kp.scalar)
        return sig
      },
      verify
    }
  }

  return {
    publicKey: kp.publicKey,
    scalar: null,
    sign: null,
    verify
  }

  function verify (signable, signature) {
    return sodium.crypto_sign_verify_detached(signature, signable, kp.publicKey)
  }
}

function toBuffer (buf) {
  return typeof buf === 'string' ? b4a.from(buf) : buf
}
