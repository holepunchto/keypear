# Attested Keys

This scheme outlines how a keypair `root` can generate a new key pair `deviceId` that may be used by a separate device/party as bearer based capability token.

Requirements:
1. `root` is not compromised if `deviceId` is compromised
2. `deviceId` should be uniquely linked to `root`

Desirable:
1. Revocability

## Key Generation

To generate a new key pair, first root generates metadata, this can be any data eg:
```
{
  DeviceID: "iPhone",
  User: "John Doe",
  App: "Holepunch",
  Expiry: "22/12/2022" 
}
```

Then `root` generates a new key pair, `seed`. `root` then creates a signature over:
```
{
  metadata,
  base: seed.publicKey
}
```

`root` computes `deviceId = tweak(seed, attestation)`, with `attestation` as:
```
{
  metadata,
  base,
  signature
}
```

## Handshake

Now when `deviceId` is presenting to a verifier, they first prove ownership of `deviceId` (eg. by performing a Noise handshake). Then they must provide `attestation` and `rootPublicKey` such that `verify` returns `true`:

```js
function verify (deviceId, attestation, root) {
  const { metadata, base, signature } = attestation
  const signData = { metadata, base }

  check = tweak(base, attestation)

  if (!crypto.verify(signature, signData, root)) return false
  if (!b4a.equal(check.publicKey, deviceId)) return false

  /* validate metadata */

  return true
}
```

## Rationale

### `root` key pair security

The only information `deviceId` gains from `root` key pair is a signature and a public key. Therefore, in the case that `deviceId` is compromised, all data on `root` is public anyway.

### `deviceId` uniquely bound

`attestation.signature` will only verify for `root`'s signature.

- `attestation` is uniquely bound to `root`

`attestation` commits to `base`, so there is only one public key will be provably valid for `attestation`, which is `pk = tweak(base, attestation)`. By definition, `deviceId = tweak(seed, attestation)` and so
```
deviceId.publicKey == tweak(seed.publicKey, attestation) == tweak(base, attestation) == pk
```
As a result:

- `attestation` is uniquely bound to `deviceId`

Together both points show that `(root, deviceId)` is the only valid tuple of key pairs for `attestation`.

If `(root, deviceId)` were valid for any other `message !== attestation`, this would imply that `blake2b(message) == blake2b(attestation)`, which breaks `blake2b` collision resistance. So finally:

- Assuming blake2b collision resistance, `(root, device)` is the only valid tuple of key pairs for a given `attestion`, meaning `attestation` uniquely binds `root` and `device`

### Revocability

Since `deviceId` is just a key pair, `root` can maintain a revocation list which services/peers may subscribe too.

If `deviceId` appears on any revocation list, then services may immediately reject the request.