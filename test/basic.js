const test = require('brittle')
const fs = require('fs')
const path = require('path')
const os = require('os')
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

test('dh', function (t) {
  const a = new Keychain()
  const b = new Keychain()

  const ak = a.get()
  const bk = b.get()

  const aSharedSecret = ak.dh(b.publicKey)
  const bSharedSecret = bk.dh(a.publicKey)

  t.alike(aSharedSecret, bSharedSecret)
})

test('local sub and remote checkout', function (t) {
  const a = new Keychain()
  const b = new Keychain()

  const sub = a.sub('a-sub')

  const k1 = sub.get()
  const k2 = sub.get('1')

  const checkout = b.checkout(k1.publicKey)

  const k3 = checkout.get()
  const k4 = checkout.get('1')

  t.alike(k1.publicKey, k3.publicKey)
  t.alike(k2.publicKey, k4.publicKey)
})

test('storage double open', async function (t) {
  const dir = createTmpDir(t)
  const filename = path.join(dir, 'primary-key')

  const open1 = Keychain.open(filename)
  const open2 = Keychain.open(filename)

  const keys1 = await open1
  const keys2 = await open2

  t.alike(keys1.home.publicKey, keys2.home.publicKey)
})

function createTmpDir (t) {
  const tmpdir = path.join(os.tmpdir(), 'localdrive-test-')
  const dir = fs.mkdtempSync(tmpdir)
  t.teardown(() => fs.promises.rm(dir, { recursive: true }))
  return dir
}
