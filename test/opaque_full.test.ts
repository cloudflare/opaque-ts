// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import type {
    AKEExportKeyPair,
    AuthClient,
    AuthServer,
    Config,
    RegistrationClient,
    RegistrationServer
} from '../src/index.js'
import {
    CredentialFile,
    KE1,
    KE2,
    KE3,
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
    export_key?: number[]
}

async function test_full_registration(input: inputTest, output: outputTest): Promise<boolean> {
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
    const success = database.store(
        credential_identifier,
        Uint8Array.from(credential_file.serialize())
    )
    // Client        success         Server
    //           <<<-------------

    expect(success).toBe(true)
    output.export_key = export_key
    output.record = record

    return true
}

async function test_full_login(input: inputTest, output: outputTest): Promise<boolean> {
    expect(output.record).toBeDefined()
    expect(output.export_key).toBeDefined()

    // Setup
    const { cfg, password, server_identity, client_identity, credential_identifier, database } =
        input
    const context = 'context is a public, shared string'
    // Client
    const client: AuthClient = new OpaqueClient(cfg)
    const ke1 = await client.authInit(password)
    expectNotError(ke1)

    const ser_ke1 = ke1.serialize()
    // Client        ke1         Server
    //           ------------->>>

    // Server
    const credFileBytes = database.lookup(credential_identifier)
    expect(credFileBytes).not.toBe(false)

    if (credFileBytes === false) {
        throw new Error('client not registered in database')
    }

    const credential_file = CredentialFile.deserialize(cfg, Array.from(credFileBytes))
    expect(credential_file.credential_identifier).toBe(credential_identifier)
    expect(credential_file.client_identity).toBe(client_identity)

    const server: AuthServer = new OpaqueServer(
        cfg,
        input.oprf_seed,
        input.server_ake_keypair,
        server_identity
    )
    const deser_ke1 = KE1.deserialize(cfg, ser_ke1)
    const ke2 = await server.authInit(
        deser_ke1,
        credential_file.record,
        credential_file.credential_identifier,
        credential_file.client_identity,
        context
    )
    expectNotError(ke2)

    const ser_ke2 = ke2.serialize()
    // Client           ke2          Server
    //           <<<-------------        |_ stores expected

    // Client
    const deser_ke2 = KE2.deserialize(cfg, ser_ke2)
    expect(deser_ke2).toStrictEqual(ke2)

    const finClient = await client.authFinish(deser_ke2, server_identity, client_identity, context)
    expectNotError(finClient)

    const { ke3, session_key: session_key_client } = finClient
    const ser_ke3 = ke3.serialize()
    // Client           ke3          Server
    //           ------------->>>       |_ recovers expected

    // Server
    const deser_ke3 = KE3.deserialize(cfg, ser_ke3)
    expect(deser_ke3).toStrictEqual(ke3)

    const finServer = server.authFinish(deser_ke3)
    expectNotError(finServer)

    // At the end, server and client MUST arrive to the same session key.
    const { session_key: session_key_server } = finServer
    expect(session_key_client).toStrictEqual(session_key_server)

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

            test('Opaque-full-registration', async () => {
                expect(await test_full_registration(input, output)).toBe(true)
            })

            test('Opaque-full-login', async () => {
                expect(await test_full_login(input, output)).toBe(true)
            })
        })
    }
)
