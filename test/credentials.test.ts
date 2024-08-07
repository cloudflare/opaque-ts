// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import type {
    AKEExportKeyPair,
    Config,
    RegistrationClient,
    RegistrationServer
} from '../src/index.js'
import {
    CredentialFile,
    OpaqueClient,
    OpaqueConfig,
    OpaqueID,
    OpaqueServer,
    RegistrationRecord,
    RegistrationRequest,
    RegistrationResponse
} from '../src/index.js'

import { KVStorage, expectNotError } from './common.js'

interface inputTest {
    cfg: Config
    database: KVStorage
    password: string
    credential_identifier: string
    client_identity: string
    server_identity: string
    oprf_seed: number[]
    server_ake_keypair: AKEExportKeyPair
}

interface outputTest {
    record?: RegistrationRecord
    export_key?: Uint8Array
}

async function test_credentials(input: inputTest, output: outputTest): Promise<boolean> {
    // Setup
    const { cfg, password, server_identity, client_identity, credential_identifier, database } =
        input
    // Client
    const client: RegistrationClient = new OpaqueClient(cfg)
    const request = await client.registerInit(password)
    expectNotError(request)

    const serReq = request.serialize()
    // Client        request         Server
    //           ------------->>>

    // Server
    const deserReq = RegistrationRequest.deserialize(cfg, serReq)
    const server: RegistrationServer = new OpaqueServer(
        cfg,
        input.oprf_seed,
        input.server_ake_keypair,
        server_identity
    )
    const response = await server.registerInit(deserReq, credential_identifier)
    expectNotError(response)

    const serRes = response.serialize()
    // Client        response        Server
    //           <<<-------------

    // Client
    const deserRes = RegistrationResponse.deserialize(cfg, serRes)
    const rec = await client.registerFinish(deserRes, server_identity, client_identity)
    expectNotError(rec)

    const { record, export_key } = rec
    const serRec = record.serialize()
    // Client        record          Server
    //           ------------->>>

    // Server
    const deserRec = RegistrationRecord.deserialize(cfg, serRec)
    const credential_file = new CredentialFile(credential_identifier, deserRec, client_identity)

    expect(credential_file.credential_identifier).toBe(credential_identifier)
    expect(credential_file.client_identity).toBe(client_identity)

    expect(export_key).toBe(export_key)
    expect(database).toBe(database)
    expect(output).toBe(output)

    return true
}

describe.each([OpaqueID.OPAQUE_P256, OpaqueID.OPAQUE_P384, OpaqueID.OPAQUE_P521])(
    'full',
    (opaqueID: OpaqueID) => {
        const cfg = new OpaqueConfig(opaqueID)

        describe(`${cfg}`, () => {
            let input: inputTest = {} as unknown as inputTest
            let output: outputTest = {}

            beforeAll(async () => {
                const seed = Uint8Array.from(cfg.prng.random(cfg.constants.Nseed))
                const server_ake_keypair = await cfg.ake.deriveDHKeyPair(seed)
                input = {
                    cfg,
                    database: new KVStorage(),
                    password: 'my favorite password123',
                    client_identity: 'user_identifier@example.com',
                    server_identity: 'server.opaque.example.com',
                    credential_identifier: 'client_identifier_defined_by_server',
                    oprf_seed: cfg.prng.random(cfg.hash.Nh),
                    server_ake_keypair: {
                        private_key: Array.from(server_ake_keypair.private_key),
                        public_key: Array.from(server_ake_keypair.public_key)
                    }
                }
                output = {}
            })

            test('Opaque-credentials', async () => {
                expect(await test_credentials(input, output)).toBe(true)
            })
        })
    }
)
