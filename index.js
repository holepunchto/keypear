const storage = require('./storage')
const sodium = require('sodium-native')
const c = require('compact-encoding')
const b4a = require('b4a')

const attestable = {
  preencode (state, obj) {
    c.fixed32.preencode(state, obj.base)
    c.buffer.preencode(state, obj.metadata)
  },
  encode (state, obj) {
    c.fixed32.encode(state, obj.base)
    c.buffer.encode(state, obj.metadata)
  },
  decode (state) {
    const base = c.fixed32.decode(state)
    const metadata = c.buffer.decode(state)

    return {
      base,
      metadata
    }
  }
}

const attest = {
  preencode (state, obj) {
    c.fixed32.preencode(state, obj.base)
    c.buffer.preencode(state, obj.metadata)
    c.fixed64.preencode(state, obj.signature)
  },
  encode (state, obj) {
    c.fixed32.encode(state, obj.base)
    c.buffer.encode(state, obj.metadata)
    c.fixed64.encode(state, obj.signature)
  },
  decode (state) {
    const base = c.fixed32.decode(state)
    const metadata = c.buffer.decode(state)
    const signature = c.fixed64.decode(state)

    return {
      base,
      metadata,
      signature
    }
  }
}

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

    const keyPair = allocKeyPair(!!this.head.scalar)

    add(this.head, this._getTweak(name), keyPair)

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

    return tweakKeyPair(toBuffer(name), this.head.publicKey)
  }

  static getAttestable ({ base, metadata }) {
    if (base instanceof Keychain) {
      return Keychain.getAttestable({ base: base.head.publicKey, metadata })
    }
    return c.encode(attestable, { base, metadata })
  }

  static bindAttestation (keyPair, metadata, signature, root) {
    if (!keyPair.scalar) keyPair = toScalarKeyPair(keyPair)

    const base = keyPair.publicKey
    const attestable = Keychain.getAttestable({ base, metadata })

    if (root && !sodium.crypto_sign_verify_detached(signature, attestable, root)) {
      throw new Error('Attestation failed: signature verification failed.')
    }

    const attestation = c.encode(attest, { base, signature, metadata })
    const tweak = tweakKeyPair(attestation)

    return {
      keyPair: add(keyPair, tweak, allocKeyPair(!!keyPair.scalar)),
      attestation
    }
  }

  static verifyAttestation (publicKey, attestedData, root) {
    const { metadata, base, signature } = c.decode(attest, attestedData)
    const signData = c.encode(attestable, { metadata, base })

    const tweak = tweakKeyPair(attestedData)
    const check = add({ publicKey: base }, tweak, allocKeyPair(false))

    if (!Keychain.verify(signData, signature, root)) return false
    if (!b4a.equals(check.publicKey, publicKey)) return false

    return true
  }

  static async open (filename) {
    return new this(this.keyPair(await storage.open(filename)))
  }

  static openSync (filename) {
    return new this(this.keyPair(storage.openSync(filename)))
  }

  static from (k) {
    if (this.isKeychain(k)) { // future compat
      return k instanceof this ? k : new this(k.home, k.base, k.tweak)
    }
    return new this(k)
  }

  static verify (signable, signature, publicKey) {
    return sodium.crypto_sign_verify_detached(signature, signable, publicKey)
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

function tweakKeyPair (name, prev = b4a.alloc(0)) {
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
      writable: true,
      dh (publicKey) {
        const output = b4a.alloc(sodium.crypto_scalarmult_ed25519_BYTES)

        sodium.crypto_scalarmult_ed25519_noclamp(
          output,
          kp.scalar,
          publicKey
        )

        return output
      },
      sign (signable) {
        const sig = b4a.alloc(sodium.crypto_sign_BYTES)
        sodium.experimental_crypto_tweak_ed25519_sign_detached(sig, signable, kp.scalar)
        return sig
      },
      verify
    }
  }

  return {
    publicKey: kp.publicKey,
    scalar: null,
    writable: false,
    dh: null,
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
