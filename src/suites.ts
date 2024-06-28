// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import type { Result } from './common.js'
import { AKE3DH, Err, OPRFBaseMode, Ok } from './common.js'
import type { AKEFn, HashFn, KDFFn, MACFn, OPRFFn, PrngFn } from './thecrypto.js'
import { Hash, Hkdf, Hmac, Prng } from './thecrypto.js'
import type { SuiteID } from '@cloudflare/voprf-ts'
import { Oprf } from '@cloudflare/voprf-ts'

import type { Config } from './config.js'

export enum OpaqueID {
    OPAQUE_P256 = 'P256-SHA256',
    OPAQUE_P384 = 'P384-SHA384',
    OPAQUE_P521 = 'P521-SHA512'
}

export class OpaqueConfig implements Config {
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
        let oprfID: SuiteID
        switch (opaqueID) {
            case OpaqueID.OPAQUE_P256:
                oprfID = Oprf.Suite.P256_SHA256
                break
            case OpaqueID.OPAQUE_P384:
                oprfID = Oprf.Suite.P384_SHA384
                break
            case OpaqueID.OPAQUE_P521:
                oprfID = Oprf.Suite.P521_SHA512
                break
            default:
                throw new Error(`invalid OpaqueID ${opaqueID}`)
        }

        this.constants = { Nn: 32, Nseed: 32 }
        this.prng = new Prng()
        this.oprf = new OPRFBaseMode(oprfID)
        this.hash = new Hash(this.oprf.hash)
        this.mac = new Hmac(this.hash.name)
        this.kdf = new Hkdf(this.hash.name)
        this.ake = new AKE3DH(oprfID)
    }

    static fromString(opaqueID: string): Result<Readonly<Config>, Error> {
        if (!Object.values<string>(OpaqueID).includes(opaqueID)) {
            return Err(new Error(`OpaqueID ${opaqueID} not supported`))
        }
        return Ok(new OpaqueConfig(opaqueID as OpaqueID))
    }

    toString(): string {
        return `${this.opaqueID} = {` + `OPRF: ${this.oprf.name}, ` + `Hash: ${this.hash.name}}`
    }
}
