# hyperkeys

Keychain that derives deterministic Ed25519 keypairs for Hypercore

```
npm install hyperkeys
```

## Usage

``` js
const Keychain = require('hyperkeys')

const keys = new Keychain()

const cur = keys.get() // returns the current keypair instance
const foo = keys.get('foo') // tweaks and returns a keypair instancoe for 'foo'

const sub = keys.sub('bar') // get a sub keychain tweaked by 'bar'
const subsub = sub.sub('baz') // sub the the sub chain

// to sign things

const sig = cur.sign(message)
const publicKey = cur.publicKey
```

## API

#### `keys = new Keychain(publicKeyOrKeyPair)`

Make a new Keychain instance.

```js
const keys = new Keychain() // generates a fresh keypair for you
const keys = new Keychain(publicKey) // generate a "readonly" keychain
const keys = new Keychain(keyPair) // generate a keychain from a keypair
```

#### `keys.home`

Points to the keypair that was used to construct the Keychain.

#### `keys.base`

Points to current checkout, or home if not checkout was made.

#### `keys.tweak`

Points to the current tweak used.

#### `keys.head`

The key pair of this chain, basically `base + tweak`.

#### `keys = Keychain.from(keyChainOrPublicKeyOrKeyPair)`

Same as above, except it will return the Keychain if passed to it.
Useful to avoid a peer dependency on the Keychain in your application, ie

```js
const Keychain = require('hyperkeys')

function myModule (keychain) {
  const keys = Keychain.from(keychain) // ensures the version of keys is the one you installed
}
```

#### `keyPairInstance = keys.get([nameOrKeyPair])`

Get a new KeyPair instance from the Keychain. Optionally you can provide a name or key pair to
tweak the keypair before returning it.

```js
const k = keys.get() // get a keypair instance from the current head
const k = keys.get('name') // tweak it with "name" first
const k = keys.get(keyPair) // tweak it with this keypair first
```

#### `keyPairInstance.sign(message)`

Sign a message (if you own the key pair).

#### `keyPairInstance.dh(otherPublicKey)`

Perform a Diffie-Hellman against another keypair (if you own this key pair).

#### `keyPairInstance.publicKey`

Get the public key of this instance.

#### `keychain = keys.sub(nameOrKeyPair)`

Make a new sub Keychain, tweaked from a name or key pair.

```js
const keychain = keys.sub('name') // tweak the current keychain
const keychain = keys.sub({ publicKey: ... }) // new "readonly" keychain
const keychain = keys.sub({ publicKey: ..., scalar: ... }) // same as above to "writable" as well
```

Note that the following keypairs are equivalent

```js
const k = keys.get('name')
const k = keys.sub('name').get()
```

All tweaks are "one way", meaning the actual tweak used is

```js
tweakSeed = blake2b([currentTweak ? currentTweak.publicKey : blank, tweakInput])
```

Ie, you need to know the previous tweak to get to it.

#### `keychain = keys.checkout(publicKeyOrKeyPair)`

Get a new Keychain, based on an "absolute" keypair or public key.
This preserves the "home" pointer, meaning you can get from a checkout to your home keychain by doing

```js
const c = keys.checkout(somePublicKey)
// go back to home
const h = c.checkout(c.home)
```

## License

MIT
