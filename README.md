# hyperkeys

Keychain that derives deterministic Ed25519 keypairs for Hypercore

```
npm install hyperkeys
```

## Usage

``` js
const KeyChain = require('hyperkeys')

const keys = new KeyChain(KeyChain.keyPair())

console.log(keys.home) // keypair the chain is constructed with
console.log(keys.base) // keypair used for tweaks
console.log(keys.tweak) // the current tweak
console.log(keys.head) // base + tweak, used for getting keypairs

const k = keys.get() // returns a keypair instance for .head
const s = keys.get('foo') // .head + 'foo'

const sub = keys.sub('bar') // get a sub keychain based on .head + bar
const subsub = sub.sub('baz') // + baz

// to sign things

const sig = k.sign(message)
const publicKey = k.publicKey

// to move your keychain to a specific public key

const c = keys.checkout(publicKey) // sets c.base but c.home is the same as keys.home

// make a chain from a keychain or publickey or keypair

const k = KeyChain.from(publicKey)
```

## License

MIT
