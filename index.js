const sodium = require('sodium-native')
const b4a = require('b4a')

class Hyperkeys {
  constructor (keyPair = Hyperkeys.keyPair(), tweak = null) {
    this.root = toScalarKeyPair(keyPair)
    this.tweak = tweak
    this.chain = tweak
      ? add(tweak, this.root, allocKeyPair(!!this.root.scalar))
      : this.root
  }

  get publicKey () {
    return this.chain.publicKey
  }

  createKeyPair (name) {
    if (!name) return createSigner(this.chain)

    const tweak = tweakKeyPair(toBuffer(name))
    const keyPair = allocKeyPair(!!this.root.scalar)

    add(this.chain, tweak, keyPair)

    return createSigner(keyPair)
  }

  sub (name) {
    const tweak = tweakKeyPair(toBuffer(name))
    if (this.tweak) add(tweak, this.tweak, tweak)
    return new Hyperkeys(this.root, tweak)
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

module.exports = Hyperkeys

function add (a, b, out) {
  sodium.experimental_crypto_tweak_ed25519_publickey_add(out.publicKey, a.publicKey, b.publicKey)
  if (a.scalar && b.scalar) {
    sodium.experimental_crypto_tweak_ed25519_secretkey_add(out.scalar, a.scalar, b.scalar)
  }
  return out
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

function tweakKeyPair (name) {
  const keyPair = allocKeyPair(true)
  sodium.experimental_crypto_tweak_ed25519(keyPair.scalar, keyPair.publicKey, name)
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
