// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { AKEFn, AKEKeyPair, OPRFFn } from './thecrypto.js'
import {
    Evaluation,
    EvaluationRequest,
    FinalizeData,
    OPRFClient,
    OPRFServer,
    Oprf,
    SuiteID,
    deriveKeyPair,
    getKeySizes
} from '@cloudflare/voprf-ts'
import { CredentialResponse, KE1 } from './messages.js'
import { encode_number, encode_vector_16, encode_vector_8, joinAll } from './util.js'

import { Config } from './config.js'

export type Ok<T> = { ok: true; value: T }
export type Err<E> = { ok: false; error: E }
export function Ok<T>(v: T): Ok<T> {
    return { ok: true, value: v }
}
export function Err<E>(e: E): Err<E> {
    return { ok: false, error: e }
}
export type Result<T, E> = Ok<T> | Err<E>
export function isErr<T, E>(res: Result<T, E>): res is Err<E> {
    return !res.ok
}
export function isOk<T, E>(res: Result<T, E>): res is Ok<T> {
    return res.ok
}

const te = new TextEncoder()
function encStr(s: string): readonly number[] {
    return Array.from(te.encode(s))
}
export const LABELS = {
    AuthKey: encStr('AuthKey'),
    ClientMAC: encStr('ClientMAC'),
    CredentialResponsePad: encStr('CredentialResponsePad'),
    ExportKey: encStr('ExportKey'),
    HandshakeSecret: encStr('HandshakeSecret'),
    MaskingKey: encStr('MaskingKey'),
    OPAQUE: encStr('OPAQUE-'),
    OPAQUE_DeriveDHKeyPair: encStr('OPAQUE-DeriveDiffieHellmanKeyPair'),
    OPAQUE_DeriveKeyPair: encStr('OPAQUE-DeriveKeyPair'),
    OprfKey: encStr('OprfKey'),
    PrivateKey: encStr('PrivateKey'),
    ServerMAC: encStr('ServerMAC'),
    SessionKey: encStr('SessionKey'),
    Version: encStr('OPAQUEv1-')
} as const

export class OPRFBaseMode implements OPRFFn {
    readonly Noe: number // Noe: The size of a serialized OPRF group element.

    readonly hash: string // hash: Name of the hash function used.

    readonly name: string // name: Name of the OPRF function.

    constructor(public readonly id: SuiteID) {
        const group = Oprf.getGroup(id)
        this.Noe = group.eltSize(true)
        this.hash = Oprf.getHash(id)
        this.name = group.id
    }

    async blind(input: Uint8Array): Promise<{ blind: Uint8Array; blindedElement: Uint8Array }> {
        const [finData, evalReq] = await new OPRFClient(this.id as SuiteID).blind([input])
        return {
            blind: finData.blinds[0].serialize(),
            blindedElement: evalReq.blinded[0].serialize()
        }
    }

    async evaluate(key: Uint8Array, blinded: Uint8Array): Promise<Uint8Array> {
        const server = new OPRFServer(this.id as SuiteID, key)
        const deserBlinded = server.gg.desElt(blinded)
        const evalReq = new EvaluationRequest([deserBlinded])
        const evaluations = await server.blindEvaluate(evalReq)
        return evaluations.evaluated[0].serialize()
    }

    async finalize(
        input: Uint8Array,
        blind: Uint8Array,
        evaluationBytes: Uint8Array
    ): Promise<Uint8Array> {
        const client = new OPRFClient(this.id as SuiteID)
        const deserEval = client.gg.desElt(evaluationBytes)
        const blindSc = client.gg.desScalar(blind)
        const finData = new FinalizeData([input], [blindSc], new EvaluationRequest([]))
        const evaluation = new Evaluation(client.mode, [deserEval])
        const outputs = await client.finalize(finData, evaluation)
        return outputs[0]
    }

    async deriveOPRFKey(seed: Uint8Array): Promise<Uint8Array> {
        const { privateKey } = await deriveKeyPair(
            Oprf.Mode.OPRF,
            this.id as SuiteID,
            seed,
            Uint8Array.from(LABELS.OPAQUE_DeriveKeyPair)
        )
        return privateKey
    }
}

function expandLabel(
    cfg: Config,
    secret: Uint8Array,
    label: Uint8Array,
    context: Uint8Array,
    length: number
): Promise<Uint8Array> {
    const customLabel = joinAll([
        encode_number(length, 16),
        encode_vector_8(joinAll([Uint8Array.from(LABELS.OPAQUE), label])),
        encode_vector_8(context)
    ])

    return cfg.kdf.expand(secret, customLabel, length)
}

function deriveSecret(
    cfg: Config,
    secret: Uint8Array,
    label: Uint8Array,
    transHash: Uint8Array
): Promise<Uint8Array> {
    return expandLabel(cfg, secret, label, transHash, cfg.kdf.Nx)
}

export function preambleBuild(
    client_identity: Uint8Array,
    ke1: KE1,
    server_identity: Uint8Array,
    credential_response: CredentialResponse,
    server_nonce: Uint8Array,
    server_public_keyshare: Uint8Array,
    context: Uint8Array
): Uint8Array {
    return joinAll([
        Uint8Array.from(LABELS.Version),
        encode_vector_16(context),
        encode_vector_16(client_identity),
        Uint8Array.from(ke1.serialize()),
        encode_vector_16(server_identity),
        Uint8Array.from(credential_response.serialize()),
        server_nonce,
        server_public_keyshare
    ])
}

type scalarElt = { sk: Uint8Array; pk: Uint8Array }
type scalarElt3 = [scalarElt, scalarElt, scalarElt]

export function tripleDH_IKM(cfg: Config, keys: scalarElt3): Uint8Array {
    const gg = Oprf.getGroup(cfg.oprf.id as SuiteID)
    const ikm = new Array<Uint8Array>(3)

    for (let i = 0; i < 3; i++) {
        const { sk, pk } = keys[i as number]
        const point = gg.desElt(pk)
        const scalar = gg.desScalar(sk)
        const p = point.mul(scalar)
        ikm[i as number] = p.serialize()
    }

    return joinAll(ikm)
}

export async function deriveKeys(
    cfg: Config,
    ikm: Uint8Array,
    preamble: Uint8Array
): Promise<{
    Km2: Uint8Array
    Km3: Uint8Array
    session_key: Uint8Array
}> {
    const nosalt = new Uint8Array(cfg.hash.Nh)
    const prk = await cfg.kdf.extract(nosalt, ikm)
    const h_preamble = await cfg.hash.sum(preamble)
    const handshake_secret = await deriveSecret(
        cfg,
        prk,
        Uint8Array.from(LABELS.HandshakeSecret),
        h_preamble
    )
    const session_key = await deriveSecret(cfg, prk, Uint8Array.from(LABELS.SessionKey), h_preamble)
    const no_transcript = new Uint8Array()
    const Km2 = await deriveSecret(
        cfg,
        handshake_secret,
        Uint8Array.from(LABELS.ServerMAC),
        no_transcript
    )
    const Km3 = await deriveSecret(
        cfg,
        handshake_secret,
        Uint8Array.from(LABELS.ClientMAC),
        no_transcript
    )

    return { Km2, Km3, session_key }
}

export class AKE3DH implements AKEFn {
    readonly Nsk: number

    readonly Npk: number

    private readonly suiteID: SuiteID

    constructor(oprfID: SuiteID) {
        this.suiteID = oprfID
        const { Npk, Nsk } = getKeySizes(this.suiteID)
        this.Npk = Npk
        this.Nsk = Nsk
    }

    async deriveDHKeyPair(seed: Uint8Array): Promise<AKEKeyPair> {
        const keypair = await deriveKeyPair(
            Oprf.Mode.OPRF,
            this.suiteID,
            seed,
            Uint8Array.from(LABELS.OPAQUE_DeriveDHKeyPair)
        )
        return { private_key: keypair.privateKey, public_key: keypair.publicKey }
    }

    // recoverPublicKey(private_key: Uint8Array): AKEKeyPair {
    //     const public_key = generatePublicKey(this.suiteID, private_key)
    //     return { private_key, public_key }
    // }

    // async generateAuthKeyPair(): Promise<AKEExportKeyPair> {
    //     const keypair = this.recoverPublicKey(await randomPrivateKey(this.suiteID))
    //     return {
    //         private_key: Array.from(keypair.private_key),
    //         public_key: Array.from(keypair.public_key)
    //     }
    // }
}
