import { createJWS, decryptJWE, NaclSigner, x25519Decrypter, JWE } from 'did-jwt'
import {
  HandlerMethods,
  RequestHandler,
  RPCConnection,
  RPCError,
  RPCRequest,
  RPCResponse,
  createHandler,
} from 'rpc-utils'
import stringify from 'fast-json-stable-stringify'
import * as u8a from 'uint8arrays'
import { generateKeyPairFromSeed, convertSecretKeyToX25519 } from '@stablelib/ed25519'

const B64 = 'base64pad'

function toStableObject(obj: Record<string, any>): Record<string, any> {
  return JSON.parse(stringify(obj)) as Record<string, any>
}

export function encodeDID(publicKey: Uint8Array): string {
  const bytes = new Uint8Array(publicKey.length + 2)
  bytes[0] = 0xed // ed25519 multicodec
  // The multicodec is encoded as a varint so we need to add this.
  // See js-multicodec for a general implementation
  bytes[1] = 0x01
  bytes.set(publicKey, 2)
  return `did:key:z${u8a.toString(bytes, 'base58btc')}`
}

interface Context {
  did: string
  secretKey: Uint8Array
}

interface CreateJWSParams {
  payload: Record<string, any>
  protected?: Record<string, any>
  did: string
}

interface DecryptJWEParams {
  jwe: JWE
  did?: string
}

interface AuthParams {
  paths: Array<string>
}

const didMethods: HandlerMethods<Context> = {
  did_authenticate: ({ did }, params: AuthParams) => {
    return { did, paths: params.paths }
  },
  did_createJWS: async ({ did, secretKey }, params: CreateJWSParams) => {
    const requestDid = params.did.split('#')[0]
    if (requestDid !== did) throw new RPCError(4100, `Unknown DID: ${did}`)
    const pubkey = did.split(':')[2]
    const kid = `${did}#${pubkey}`
    const signer = NaclSigner(u8a.toString(secretKey, B64))
    const header = toStableObject(Object.assign(params.protected || {}, { kid, alg: 'EdDSA' }))
    const jws = await createJWS(toStableObject(params.payload), signer, header)
    return { jws }
  },
  did_decryptJWE: async ({ secretKey }, params: DecryptJWEParams) => {
    const decrypter = x25519Decrypter(convertSecretKeyToX25519(secretKey))
    try {
      const bytes = await decryptJWE(params.jwe, decrypter)
      return { cleartext: u8a.toString(bytes, B64) }
    } catch (e) {
      throw new RPCError(-32000, (e as Error).message)
    }
  },
}

export class Ed25519Provider implements RPCConnection {
  protected _handle: (msg: RPCRequest) => Promise<RPCResponse | null>

  constructor(seed: Uint8Array) {
    const { secretKey, publicKey } = generateKeyPairFromSeed(seed)
    const did = encodeDID(publicKey)
    const handler: RequestHandler = createHandler<Context>(didMethods)
    this._handle = (msg: RPCRequest) => {
      return handler({ did, secretKey }, msg)
    }
  }

  public get isDidProvider(): boolean {
    return true
  }

  public async send(msg: RPCRequest): Promise<RPCResponse | null> {
    return await this._handle(msg)
  }
}
