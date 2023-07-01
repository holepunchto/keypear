const test = require('brittle')
const b4a = require('b4a')
const Keychain = require('../')

test('basic', function (t) {
  const root = new Keychain()
  const base = new Keychain()

  const signer = root.get()

  const metadata = b4a.from('some data to attest')
  const attestable = Keychain.getAttestable({ base, metadata })

  const signature = signer.sign(attestable)
  const { keyPair, attestation } = Keychain.bindAttestation(base, metadata, signature)

  t.ok(Keychain.verifyAttestation(keyPair.publicKey, attestation, signer.publicKey))
  t.exception(() => Keychain.bindAttestation(base, metadata.subarray(1), signature, signer.publicKey))

  t.end()
})
