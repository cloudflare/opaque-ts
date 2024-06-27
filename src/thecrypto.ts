// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { ctEqual, joinAll } from './util.js'

import { scrypt } from '@noble/hashes/scrypt'

export interface PrngFn {
    random(numBytes: number): number[]
}

export class Prng implements PrngFn {
    /* eslint-disable-next-line class-methods-use-this */
    random(numBytes: number): number[] {
        return Array.from(crypto.getRandomValues(new Uint8Array(numBytes)))
    }
}

export interface HashFn {
    name: string
    Nh: number //  Nh: The output size of the Hash function in bytes.
    sum(msg: Uint8Array): Promise<Uint8Array>
}

export class Hash implements HashFn {
    readonly Nh: number

    constructor(public readonly name: string | Hash.ID) {
        switch (name) {
            case Hash.ID.SHA1:
                this.Nh = 20
                break
            case Hash.ID.SHA256:
                this.Nh = 32
                break
            case Hash.ID.SHA384:
                this.Nh = 48
                break
            case Hash.ID.SHA512:
                this.Nh = 64
                break
            default:
                throw new Error(`invalid hash name: ${name}`)
        }
    }

    async sum(msg: Uint8Array): Promise<Uint8Array> {
        return new Uint8Array(await crypto.subtle.digest(this.name, msg))
    }
}

/* eslint-disable-next-line @typescript-eslint/no-namespace */
export namespace Hash {
    export const ID = {
        SHA1: 'SHA-1',
        SHA256: 'SHA-256',
        SHA384: 'SHA-384',
        SHA512: 'SHA-512'
    } as const
    export type ID = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'
}

export interface MACOps {
    sign(msg: Uint8Array): Promise<Uint8Array>
    verify(msg: Uint8Array, output: Uint8Array): Promise<boolean>
}

export interface MACFn {
    Nm: number // The output size of the MAC() function in bytes.
    with_key(key: Uint8Array): Promise<MACOps>
}

export class Hmac implements MACFn {
    readonly Nm: number

    constructor(private readonly hash: string | Hash.ID) {
        this.Nm = new Hash(hash).Nh
    }

    async with_key(key: Uint8Array): Promise<MACOps> {
        return new Hmac.Macops(
            await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: this.hash }, false, [
                'sign'
            ])
        )
    }

    private static Macops = class implements MACOps {
        constructor(private readonly crypto_key: CryptoKey) {}

        async sign(msg: Uint8Array): Promise<Uint8Array> {
            return new Uint8Array(
                await crypto.subtle.sign(this.crypto_key.algorithm.name, this.crypto_key, msg)
            )
        }

        async verify(msg: Uint8Array, output: Uint8Array): Promise<boolean> {
            return ctEqual(output, await this.sign(msg))
        }
    }
}

export interface KDFFn {
    Nx: number // The output size of the Extract() function in bytes.
    extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array>
    expand(prk: Uint8Array, info: Uint8Array, lenBytes: number): Promise<Uint8Array>
}

export class Hkdf implements KDFFn {
    readonly Nx: number

    constructor(public hash: string | Hash.ID) {
        this.Nx = new Hmac(hash).Nm
    }

    async extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
        if (salt.length === 0) {
            salt = new Uint8Array(this.Nx)
        }
        return (await new Hmac(this.hash).with_key(salt)).sign(ikm)
    }

    async expand(prk: Uint8Array, info: Uint8Array, lenBytes: number): Promise<Uint8Array> {
        const hashLen = new Hash(this.hash).Nh
        const N = Math.ceil(lenBytes / hashLen)
        const T = new Uint8Array(N * hashLen)
        const hm = await new Hmac(this.hash).with_key(prk)
        let Ti = new Uint8Array()
        let offset = 0
        for (let i = 0; i < N; i++) {
            Ti = await hm.sign(joinAll([Ti, info, Uint8Array.of(i + 1)])) // eslint-disable-line no-await-in-loop
            T.set(Ti, offset)
            offset += hashLen
        }
        return T.slice(0, lenBytes)
    }
}

export interface KSFFn {
    readonly name: string
    readonly harden: (input: Uint8Array) => Uint8Array
}

export const IdentityKSFFn: KSFFn = { name: 'Identity', harden: (x) => x } as const

export const ScryptKSFFn: KSFFn = {
    name: 'scrypt',
    harden: (msg: Uint8Array): Uint8Array => scrypt(msg, new Uint8Array(), { N: 32768, r: 8, p: 1 })
} as const

export interface AKEKeyPair {
    private_key: Uint8Array
    public_key: Uint8Array
}

export interface AKEExportKeyPair {
    private_key: number[]
    public_key: number[]
}

export interface AKEFn {
    readonly Nsk: number // Nsk: The size of AKE private keys.
    readonly Npk: number // Npk: The size of AKE public keys.
    deriveDHKeyPair(seed: Uint8Array): Promise<AKEKeyPair>
}

export interface OPRFFn {
    readonly Noe: number // Noe: The size of a serialized OPRF group element.
    readonly hash: string // hash: Name of the hash function used.
    readonly id: string // id: Identifier of the OPRF.
    readonly name: string // name: Name of the OPRF function.
    blind(input: Uint8Array): Promise<{ blind: Uint8Array; blindedElement: Uint8Array }>
    evaluate(key: Uint8Array, blinded: Uint8Array): Promise<Uint8Array>
    finalize(input: Uint8Array, blind: Uint8Array, evaluation: Uint8Array): Promise<Uint8Array>
    deriveOPRFKey(seed: Uint8Array): Promise<Uint8Array>
}
