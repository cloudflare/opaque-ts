// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    AKEKeyPair,
    Config,
    CredentialFile,
    OpaqueConfig,
    OpaqueID,
    RegistrationRecord
} from '../src/index.js'

import { KVStorage } from './common.js'
import { OpaqueCoreClient } from '../src/core_client.js'
import { OpaqueCoreServer } from '../src/core_server.js'

interface inputTest {
    cfg: Config
    database: KVStorage
    password: Uint8Array
    credential_identifier: Uint8Array
    client_identity: Uint8Array
    server_identity: Uint8Array
    oprf_seed: Uint8Array
    server_ake_keypair: AKEKeyPair
}

interface outputTest {
    record?: RegistrationRecord
    export_key?: number[]
}

async function test_core_registration(input: inputTest, output: outputTest): Promise<boolean> {
    // Setup
    const { cfg, password, server_identity, client_identity, credential_identifier, database } =
        input
    // Client
    const client = new OpaqueCoreClient(cfg)
    const { request, blind } = await client.createRegistrationRequest(password)
    // Client        request         Server
    //           ------------->>>

    // Server
    const server = new OpaqueCoreServer(cfg, input.oprf_seed)
    const response = await server.createRegistrationResponse(
        request,
        input.server_ake_keypair.public_key,
        credential_identifier
    )
    // Client        response        Server
    //           <<<-------------

    // Client
    const { record, export_key } = await client.finalizeRequest(
        password,
        blind,
        response,
        server_identity,
        client_identity
    )
    // Client        record          Server
    //           ------------->>>

    // Server
    const credential_file = new CredentialFile(
        credential_identifier.toString(),
        record,
        client_identity.toString()
    )
    const success = database.store(
        credential_identifier.toString(),
        Uint8Array.from(credential_file.serialize())
    )
    // Client        success         Server
    //           <<<-------------

    expect(success).toBe(true)
    output.export_key = export_key
    output.record = record

    return true
}

async function test_core_login(input: inputTest, output: outputTest): Promise<boolean> {
    expect(output.record).toBeDefined()
    expect(output.export_key).toBeDefined()

    // Setup
    const { cfg, password, server_identity, client_identity, credential_identifier, database } =
        input
    // Client
    const client = new OpaqueCoreClient(cfg)
    const { request, blind } = await client.createCredentialRequest(password)
    // Client        request         Server
    //           ------------->>>

    // Server
    const credential_file_bytes = database.lookup(credential_identifier.toString())
    expect(credential_file_bytes).not.toBe(false)
    if (credential_file_bytes === false) {
        throw new Error('client not found')
    }

    const credential_file = CredentialFile.deserialize(cfg, Array.from(credential_file_bytes))
    expect(credential_file.credential_identifier).toBe(credential_identifier.toString())
    expect(credential_file.client_identity).toBe(client_identity.toString())

    const server = new OpaqueCoreServer(cfg, input.oprf_seed)
    const response = await server.createCredentialResponse(
        request,
        credential_file.record,
        input.server_ake_keypair.public_key,
        credential_identifier
    )
    // Client        response        Server
    //           <<<-------------

    // Client
    const result = await client.recoverCredentials(
        password,
        blind,
        response,
        server_identity,
        client_identity
    )

    expect(result).not.toBeInstanceOf(Error)
    if (result instanceof Error) {
        throw new Error('client failed to recover credentials')
    }

    expect(result.client_ake_keypair.public_key).toStrictEqual(output.record?.client_public_key)
    expect(result.server_public_key).toStrictEqual(input.server_ake_keypair.public_key)
    expect(Array.from(result.export_key)).toStrictEqual(output.export_key)

    return true
}

describe.each([OpaqueID.OPAQUE_P256, OpaqueID.OPAQUE_P384, OpaqueID.OPAQUE_P521])(
    'core',
    (opaqueID: OpaqueID) => {
        const cfg = new OpaqueConfig(opaqueID)

        describe(`${cfg.toString()}`, () => {
            let input: inputTest = {} as unknown as inputTest
            let output: outputTest = {}

            beforeAll(async () => {
                const te = new TextEncoder()
                const seed = Uint8Array.from(cfg.prng.random(cfg.constants.Nseed))
                const server_ake_keypair = await cfg.ake.deriveDHKeyPair(seed)
                input = {
                    cfg,
                    database: new KVStorage(),
                    password: te.encode('my favorite password'),
                    client_identity: te.encode('user_identifier'),
                    server_identity: te.encode('server.Opaque.example.com'),
                    credential_identifier: te.encode('client_identifier_defined_by_server'),
                    oprf_seed: new Uint8Array(cfg.prng.random(cfg.hash.Nh)),
                    server_ake_keypair
                }
                output = {}
            })

            test('Opaque-core-registration', async () =>
                expect(await test_core_registration(input, output)).toBe(true))

            test('Opaque-core-login', async () =>
                expect(await test_core_login(input, output)).toBe(true))
        })
    }
)
