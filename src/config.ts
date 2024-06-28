// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import type { AKEFn, HashFn, KDFFn, MACFn, OPRFFn, PrngFn } from './thecrypto.js'

export interface Config {
    readonly constants: {
        readonly Nn: number // Nn: The size of the nonce in bytes.
        readonly Nseed: number // Nseed: The size of key derivation seeds in bytes.
    }
    readonly prng: PrngFn // A pseudo-random number generator.
    readonly oprf: OPRFFn // An oblivious pseudorandom function.
    readonly hash: HashFn // A hash function.
    readonly mac: MACFn // A message authentication code.
    readonly kdf: KDFFn // A key derivation function.
    readonly ake: AKEFn // An authenticated key exchange mechanism.
}
