// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { OpaqueClient, OpaqueConfig, OpaqueID, RegistrationRequest } from '../src/index.js'
import { expectNotError } from './common.js'

test('serde', async () => {
    const te = new TextEncoder()
    const cfg = new OpaqueConfig(OpaqueID.OPAQUE_P256)
    const client_password = te.encode('user_password')
    const client = new OpaqueClient(cfg)
    const request = await client.registerInit(new TextDecoder().decode(client_password))
    expectNotError(request)

    const bytes = request.serialize()
    const expected = RegistrationRequest.deserialize(client.config, bytes)
    expect(expected).toEqual(request)
})
