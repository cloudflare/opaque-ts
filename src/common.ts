// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { AKEExportKeyPair, AKEFn, AKEKeyPair, OPRFFn } from './thecrypto.js'
import {
    Blind,
    Blinded,
    Evaluation,
    Group,
    OPRFClient,
    OPRFServer,
    Oprf,
    OprfID,
    SerializedElt,
    SerializedScalar,
    generatePublicKey,
    getKeySizes,
    randomPrivateKey
} from '@cloudflare/voprf-ts'
import { KE1, KE2 } from './messages.js'
import { encode_number, encode_vector_16, encode_vector_8, joinAll } from './util.js'

import { Config } from './config.js'

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
    OPAQUE_DeriveAuthKeyPair: encStr('OPAQUE-DeriveAuthKeyPair'),
    OPAQUE_DeriveKeyPair: encStr('OPAQUE-DeriveKeyPair'),
    OprfKey: encStr('OprfKey'),
    PrivateKey: encStr('PrivateKey'),
    RFC: encStr('RFCXXXX'),
    ServerMAC: encStr('ServerMAC'),
    SessionKey: encStr('SessionKey')
} as const

export class OPRFBaseMode implements OPRFFn {
    readonly Noe: number // Noe: The size of a serialized OPRF group element.

    readonly hash: string // hash: Name of the hash function used.

    readonly name: string // name: Name of the OPRF function.

    constructor(public readonly id: number) {
        const { blindedSize, hash } = Oprf.params(id)
        this.Noe = blindedSize
        this.hash = hash
        this.name = OprfID[id as number]
    }

    async blind(input: Uint8Array): Promise<{ blind: Uint8Array; blindedElement: Uint8Array }> {
        const res = await new OPRFClient(this.id).blind(input)
        return {
            blind: new Uint8Array(res.blind.buffer),
            blindedElement: new Uint8Array(res.blindedElement.buffer)
        }
    }

    async evaluate(key: Uint8Array, blinded: Uint8Array): Promise<Uint8Array> {
        const res = await new OPRFServer(this.id, key).evaluate(
            new Blinded(blinded),
            new Uint8Array()
        )
        return new Uint8Array(res.buffer)
    }

    finalize(input: Uint8Array, blind: Uint8Array, evaluation: Uint8Array): Promise<Uint8Array> {
        return new OPRFClient(this.id).finalize(
            input,
            new Uint8Array(),
            new Blind(blind),
            new Evaluation(evaluation)
        )
    }

    async deriveOPRFKey(seed: Uint8Array): Promise<Uint8Array> {
        const { gg } = Oprf.params(this.id)
        const priv = await gg.hashToScalar(seed, Uint8Array.from(LABELS.OPAQUE_DeriveKeyPair))
        return new Uint8Array(gg.serializeScalar(priv))
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
    ke1: KE1,
    ke2: KE2,
    server_identity: Uint8Array,
    client_identity: Uint8Array,
    context: Uint8Array
): Uint8Array {
    return joinAll([
        Uint8Array.from(LABELS.RFC),
        encode_vector_16(context),
        encode_vector_16(client_identity),
        Uint8Array.from(ke1.serialize()),
        encode_vector_16(server_identity),
        Uint8Array.from(ke2.response.serialize()),
        ke2.auth_response.server_nonce,
        ke2.auth_response.server_keyshare
    ])
}

type scalarElt = { sk: Uint8Array; pk: Uint8Array }
type scalarElt3 = [scalarElt, scalarElt, scalarElt]

export function tripleDH_IKM(cfg: Config, keys: scalarElt3): Uint8Array {
    const { gg } = Oprf.params(cfg.oprf.id)
    const ikm = new Array<Uint8Array>(3)

    for (let i = 0; i < 3; i++) {
        const { sk, pk } = keys[i as number]
        const point = gg.deserialize(new SerializedElt(pk))
        const scalar = gg.deserializeScalar(new SerializedScalar(sk))
        const p = Group.mul(scalar, point)
        ikm[i as number] = gg.serialize(p)
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

    constructor(private readonly oprfID: OprfID) {
        const { Npk, Nsk } = getKeySizes(oprfID)
        this.Npk = Npk
        this.Nsk = Nsk
    }

    async deriveAuthKeyPair(seed: Uint8Array): Promise<AKEKeyPair> {
        const { gg } = Oprf.params(this.oprfID)
        const priv = await gg.hashToScalar(seed, Uint8Array.from(LABELS.OPAQUE_DeriveAuthKeyPair))
        const private_key = new Uint8Array(gg.serializeScalar(priv))
        const public_key = generatePublicKey(this.oprfID, private_key)
        return { private_key, public_key }
    }

    recoverPublicKey(private_key: Uint8Array): AKEKeyPair {
        const public_key = generatePublicKey(this.oprfID, private_key)
        return { private_key, public_key }
    }

    async generateAuthKeyPair(): Promise<AKEExportKeyPair> {
        const keypair = this.recoverPublicKey(await randomPrivateKey(this.oprfID))
        return {
            private_key: Array.from(keypair.private_key),
            public_key: Array.from(keypair.public_key)
        }
    }
}
