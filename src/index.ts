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

interface JWSSignature {
  protected: string
  signature: string
}

export interface GeneralJWS {
  payload: string
  signatures: Array<JWSSignature>
}

function toGeneralJWS(jws: string): GeneralJWS {
  const [protectedHeader, payload, signature] = jws.split('.')
  return {
    payload,
    signatures: [{ protected: protectedHeader, signature }],
  }
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
  nonce: string
  aud: string
  paths: Array<string>
}

const sign = async (
  payload: Record<string, any>,
  did: string,
  secretKey: Uint8Array,
  protectedHeader?: Record<string, any>
) => {
  const kid = `${did}#${did.split(':')[2]}`
  const signer = NaclSigner(u8a.toString(secretKey, B64))
  const header = toStableObject(Object.assign(protectedHeader || {}, { kid, alg: 'EdDSA' }))
  return createJWS(toStableObject(payload), signer, header)
}

const didMethods: HandlerMethods<Context> = {
  did_authenticate: async ({ did, secretKey }, params: AuthParams) => {
    const response = await sign(
      {
        did,
        aud: params.aud,
        nonce: params.nonce,
        paths: params.paths,
        exp: Math.floor(Date.now() / 1000) + 600, // expires 10 min from now
      },
      did,
      secretKey
    )
    return toGeneralJWS(response)
  },
  did_createJWS: async ({ did, secretKey }, params: CreateJWSParams) => {
    const requestDid = params.did.split('#')[0]
    if (requestDid !== did) throw new RPCError(4100, `Unknown DID: ${did}`)
    const jws = await sign(params.payload, did, secretKey, params.protected)
    return { jws: toGeneralJWS(jws) }
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
