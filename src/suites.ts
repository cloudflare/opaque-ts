// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { AKE3DH, OPRFBaseMode } from './common.js'
import { AKEFn, Hash, HashFn, Hkdf, Hmac, KDFFn, MACFn, OPRFFn, Prng, PrngFn } from './thecrypto.js'

import { Config } from './config.js'
import { OprfID } from '@cloudflare/voprf-ts'

export enum OpaqueID { // eslint-disable-line no-shadow
    OPAQUE_P256 = 3,
    OPAQUE_P384 = 4,
    OPAQUE_P521 = 5
}

class OpaqueConfig implements Config {
    readonly constants: {
        readonly Nn: number
        readonly Nseed: number
    }

    readonly prng: PrngFn

    readonly oprf: OPRFFn

    readonly hash: HashFn

    readonly mac: MACFn

    readonly kdf: KDFFn

    readonly ake: AKEFn

    constructor(public readonly opaqueID: OpaqueID) {
        let oprfID: OprfID = 0
        switch (opaqueID) {
            case OpaqueID.OPAQUE_P256:
                oprfID = OprfID.OPRF_P256_SHA256
                break
            case OpaqueID.OPAQUE_P384:
                oprfID = OprfID.OPRF_P384_SHA384
                break
            case OpaqueID.OPAQUE_P521:
                oprfID = OprfID.OPRF_P521_SHA512
                break
            default:
                throw new Error('invalid opaque id')
        }

        this.constants = { Nn: 32, Nseed: 32 }
        this.prng = new Prng()
        this.oprf = new OPRFBaseMode(oprfID)
        this.hash = new Hash(this.oprf.hash)
        this.mac = new Hmac(this.hash.name)
        this.kdf = new Hkdf(this.hash.name)
        this.ake = new AKE3DH(this.oprf.id)
    }

    toString(): string {
        return (
            `${OpaqueID[this.opaqueID]} = {` +
            `OPRF: ${this.oprf.name}, ` +
            `Hash: ${this.hash.name}}`
        )
    }
}

export function getOpaqueConfig(opaqueID: number | OpaqueID): Readonly<Config> {
    return new OpaqueConfig(opaqueID)
}
