// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    AKEExportKeyPair,
    Config,
    CredentialFile,
    OpaqueClient,
    OpaqueConfig,
    OpaqueID,
    OpaqueServer,
    RegistrationClient,
    RegistrationRecord,
    RegistrationRequest,
    RegistrationResponse,
    RegistrationServer
} from '../src/index.js'

import { KVStorage } from './common.js'

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
    expect(request).not.toBeInstanceOf(Error)
    if (request instanceof Error) {
        throw new Error(`client failed to registerInit: ${request}`)
    }
    let serReq = request.serialize()

    // include being passed through a JSON encoding and decoding
    serReq = JSON.parse(JSON.stringify(serReq))
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
    expect(response).not.toBeInstanceOf(Error)
    if (response instanceof Error) {
        throw new Error(`server failed to registerInit: ${response}`)
    }
    const serRes = response.serialize()
    // Client        response        Server
    //           <<<-------------

    // Client
    const deserRes = RegistrationResponse.deserialize(cfg, serRes)
    const rec = await client.registerFinish(deserRes, server_identity, client_identity)
    expect(rec).not.toBeInstanceOf(Error)
    if (rec instanceof Error) {
        throw new Error(`client failed to registerFinish: ${rec}`)
    }
    const { record, export_key } = rec
    let serRec = record.serialize()
    // Client        record          Server
    //           ------------->>>

    serRec = JSON.parse(JSON.stringify(serRec))

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

        describe(`${cfg.toString()}`, () => {
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

            test('Opaque-credentials', async () =>
                expect(await test_credentials(input, output)).toBe(true))
        })
    }
)
