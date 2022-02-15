// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { fromHex, toHex } from './common.js'

import { Hkdf } from '../src/thecrypto.js'
import vectors from './testdata/hkdf.json'

describe.each(vectors)('HKDF', (vector: typeof vectors[number]) => {
    const { hash } = vector
    const hkdf = new Hkdf(hash)
    const ikm = fromHex(vector.ikm)
    const salt = fromHex(vector.salt)
    const info = fromHex(vector.info)
    const len = vector.length

    test(`${vector.name}/${vector.hash}`, async () => {
        const prk = await hkdf.extract(salt, ikm)
        const okm = await hkdf.expand(prk, info, len)
        expect(toHex(prk)).toEqual(vector.PRK)
        expect(toHex(okm)).toEqual(vector.OKM)
    })
})
