const test = require('brittle')
const b4a = require('b4a')
const Keychain = require('../')

test('basic', function (t) {
  const keys = new Keychain()

  const signer = keys.get()

  t.ok(signer.publicKey)
  t.ok(signer.sign)
})

test('deterministic', function (t) {
  const keys = new Keychain(Keychain.keyPair(b4a.alloc(32)))

  const signer = keys.get()

  t.snapshot(signer.publicKey, 'signer has same public key')
  t.ok(signer.sign, 'signable')

  const publicKeys = new Keychain(keys.publicKey)
  const verifier = publicKeys.get()

  t.alike(verifier.publicKey, signer.publicKey, 'verifier has same public key')
  t.not(verifier.sign, 'signable')
})

test('deterministic subs', function (t) {
  const keys = new Keychain(Keychain.keyPair(b4a.alloc(32)))

  const signer = keys.get('test')

  t.snapshot(signer.publicKey, 'signer has same public key for test')

  const publicKeys = new Keychain(keys.publicKey)
  const verifier = publicKeys.get('test')

  t.alike(verifier.publicKey, signer.publicKey, 'verifier has same public key')
  t.not(verifier.sign, 'signable')

  const sub = publicKeys.sub('test')
  const main = sub.get()

  t.alike(main.publicKey, signer.publicKey, 'verifier has same public key')
})

test('sub with tweak', function (t) {
  const keys = new Keychain()

  const sub1 = keys.sub('foo').sub('bar')
  const sub2 = keys.sub(sub1.tweak)

  t.alike(sub1.publicKey, sub2.publicKey, 'same sub')
})
