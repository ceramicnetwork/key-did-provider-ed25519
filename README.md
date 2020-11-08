# ed25519 key did provider
This is a DID Provider which implements [EIP2844](https://eips.ethereum.org/EIPS/eip-2844) for `did:key:` using ed25519. It also supports decryption using x25519.

## Usage

```js
import { Ed25519Provider } from 'key-did-provider-secp256k1'
import { DID } from 'dids'

const seed = new Uint8Array(...) //  32 bytes with high entropy
const provider = new Ed25519Provider(seed)
const did = new DID({ provider })
await did.authenticate()

// log the DID
console.log(did.id)

// create JWS
const { jws, linkedBlock } = did.createDagJWS({ hello: 'world' })

// decrypt JWE
const jwe = ... // encrypted JWE
const decrypted = did.decryptDagJWE(jwe)
```

## License

Apache-2.0 OR MIT
