// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    AKEExportKeyPair,
    AuthClient,
    AuthServer,
    Config,
    CredentialFile,
    ExpectedAuthResult,
    KE1,
    KE2,
    KE3,
    OpaqueClient,
    OpaqueID,
    OpaqueServer,
    RegistrationClient,
    RegistrationRecord,
    RegistrationRequest,
    RegistrationResponse,
    RegistrationServer,
    getOpaqueConfig
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
    export_key?: number[]
}

async function test_full_registration(input: inputTest, output: outputTest): Promise<void> {
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
}

async function test_full_login(input: inputTest, output: outputTest): Promise<void> {
    expect(output.record).toBeDefined()
    expect(output.export_key).toBeDefined()

    // Setup
    const { cfg, password, server_identity, client_identity, credential_identifier, database } =
        input
    const context = 'context is a public, shared string'
    // Client
    const client: AuthClient = new OpaqueClient(cfg)
    const ke1 = await client.authInit(password)
    expect(ke1).not.toBeInstanceOf(Error)
    if (ke1 instanceof Error) {
        throw new Error(`client failed to authInit: ${ke1}`)
    }

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
    const ret_auth_init = await server.authInit(
        deser_ke1,
        credential_file.record,
        credential_file.credential_identifier,
        credential_file.client_identity,
        context
    )
    expect(ret_auth_init).not.toBeInstanceOf(Error)
    if (ret_auth_init instanceof Error) {
        throw new Error(`server failed to authInit: ${ret_auth_init}`)
    }
    const { ke2, expected } = ret_auth_init
    const ser_expected = JSON.stringify(expected.serialize())
    const ser_ke2 = ke2.serialize()
    // Client           ke2          Server
    //           <<<-------------        |_ stores expected

    // Client
    const deser_ke2 = KE2.deserialize(cfg, ser_ke2)
    expect(deser_ke2).toStrictEqual(ke2)

    const finClient = await client.authFinish(deser_ke2, server_identity, client_identity, context)
    expect(finClient).not.toBeInstanceOf(Error)
    if (finClient instanceof Error) {
        throw new Error(`client failed to authFinish: ${finClient}`)
    }

    const { ke3, session_key: session_key_client } = finClient
    const ser_ke3 = ke3.serialize()
    // Client           ke3          Server
    //           ------------->>>       |_ recovers expected

    // Server
    const server2: AuthServer = new OpaqueServer(
        cfg,
        input.oprf_seed,
        input.server_ake_keypair,
        server_identity
    )
    const deser_expected = ExpectedAuthResult.deserialize(cfg, JSON.parse(ser_expected))
    const deser_ke3 = KE3.deserialize(cfg, ser_ke3)
    expect(deser_ke3).toStrictEqual(ke3)
    expect(deser_expected).toStrictEqual(expected)

    const finServer = server2.authFinish(deser_ke3, deser_expected)
    expect(finServer).not.toBeInstanceOf(Error)
    if (finServer instanceof Error) {
        throw new Error(`server failed to authenticate user: ${finServer}`)
    }

    const { session_key: session_key_server } = finServer

    // At the end, server and client MUST arrive to the same session key.
    expect(session_key_client).toStrictEqual(session_key_server)
}

describe.each([OpaqueID.OPAQUE_P256, OpaqueID.OPAQUE_P384, OpaqueID.OPAQUE_P521])(
    'full',
    (opaqueID: OpaqueID) => {
        const cfg = getOpaqueConfig(opaqueID)

        describe(`${cfg.toString()}`, () => {
            let input: inputTest = {} as unknown as inputTest
            let output: outputTest = {}

            beforeAll(async () => {
                const server_ake_keypair = await cfg.ake.generateAuthKeyPair()
                input = {
                    cfg,
                    database: new KVStorage(),
                    password: 'my favorite password123',
                    client_identity: 'user_identifier@example.com',
                    server_identity: 'server.opaque.example.com',
                    credential_identifier: 'client_identifier_defined_by_server',
                    oprf_seed: cfg.prng.random(cfg.hash.Nh),
                    server_ake_keypair
                }
                output = {}
            })

            test('Opaque-full-registration', () => test_full_registration(input, output))

            test('Opaque-full-login', () => test_full_login(input, output))
        })
    }
)
