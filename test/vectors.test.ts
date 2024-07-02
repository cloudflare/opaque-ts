// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import type { Config, KSFFn } from '../src/index.js'
import {
    AKE3DH,
    CredentialFile,
    IdentityKSFFn,
    KE1,
    KE2,
    KE3,
    OpaqueClient,
    OpaqueConfig,
    OpaqueServer,
    RegistrationRecord,
    isOk
} from '../src/index.js'
import {
    expectToBeError,
    expectNotError,
    KVStorage,
    fromHex,
    fromHexString,
    notNullHex,
    notNullHexString,
    toHex
} from './common.js'
import type { SuiteID } from '@cloudflare/voprf-ts'
import { OPRFClient, Oprf } from '@cloudflare/voprf-ts'

import { jest } from '@jest/globals'
import { readFileSync } from 'node:fs'
import { unzipSync } from 'node:zlib'

interface Vector {
    config: Configuration
    inputs: Inputs
    intermediates: Intermediates
    outputs: Outputs
}

interface Configuration {
    Context: string
    Fake: string
    Group: string
    Hash: string
    KDF: string
    KSF: string
    MAC: string
    Name: string
    Nh: string
    Nm: string
    Nok: string
    Npk: string
    Nsk: string
    Nx: string
    OPRF: string
}

interface Inputs {
    blind_login: string
    blind_registration: string
    client_identity?: string
    client_keyshare_seed: string
    client_nonce: string
    client_private_key?: string
    client_public_key?: string
    credential_identifier: string
    envelope_nonce: string
    masking_nonce: string
    masking_key?: string
    oprf_seed: string
    password: string
    server_identity?: string
    server_keyshare_seed: string
    server_nonce: string
    server_private_key: string
    server_public_key: string
    KE1?: string
}

interface Intermediates {
    auth_key: string
    client_mac_key: string
    client_public_key: string
    envelope: string
    handshake_secret: string
    masking_key: string
    oprf_key: string
    randomized_password: string
    server_mac_key: string
}

interface Outputs {
    KE1: string
    KE2: string
    KE3: string
    export_key: string
    registration_request: string
    registration_response: string
    registration_upload: string
    session_key: string
}

async function createMocks(vector: Vector, cfg: Config, isFake: boolean) {
    jest.clearAllMocks()

    // Setup: Values used to create a fake record.
    if (!isFake) {
        jest.spyOn(crypto, 'getRandomValues')
            .mockReturnValueOnce(notNullHex(vector.intermediates.client_public_key))
            .mockReturnValueOnce(notNullHex(vector.intermediates.masking_key))
    } else {
        jest.spyOn(AKE3DH.prototype, 'generateDHKeyPair').mockImplementationOnce(async () => ({
            private_key: notNullHex(vector.inputs.client_private_key),
            public_key: notNullHex(vector.inputs.client_public_key)
        }))

        jest.spyOn(crypto, 'getRandomValues').mockReturnValueOnce(
            notNullHex(vector.inputs.masking_key)
        )
    }

    // Registration
    if (!isFake) {
        // Creates a mock for OPRFClient.randomBlinder method to
        // inject the blind value given by the test vector.
        jest.spyOn(OPRFClient.prototype, 'randomBlinder').mockImplementationOnce(async () => {
            const blind = notNullHex(vector.inputs.blind_registration)
            const group = Oprf.getGroup(cfg.oprf.id as SuiteID)
            return group.desScalar(blind)
        })
    }

    // Login
    jest.spyOn(OPRFClient.prototype, 'randomBlinder').mockImplementationOnce(async () => {
        const blind = notNullHex(vector.inputs.blind_login)
        const group = Oprf.getGroup(cfg.oprf.id as SuiteID)
        return group.desScalar(blind)
    })

    // Registration
    if (!isFake) {
        jest.spyOn(crypto, 'getRandomValues').mockReturnValueOnce(
            notNullHex(vector.inputs.envelope_nonce)
        )
    }

    jest.spyOn(crypto, 'getRandomValues')
        .mockReturnValueOnce(notNullHex(vector.inputs.client_nonce))
        .mockReturnValueOnce(notNullHex(vector.inputs.client_keyshare_seed))
        .mockReturnValueOnce(notNullHex(vector.inputs.masking_nonce))
        .mockReturnValueOnce(notNullHex(vector.inputs.server_nonce))
        .mockReturnValueOnce(notNullHex(vector.inputs.server_keyshare_seed))
}

interface inputsRaw {
    password: string
    credential_identifier: string
    server_private_key: Uint8Array
    server_public_key: Uint8Array
    oprf_seed: Uint8Array
    masking_key: Uint8Array
    client_public_key: Uint8Array
    client_private_key: Uint8Array
    context: string
    ksf: KSFFn
}

interface inputsRawOpt {
    client_identity?: string
    server_identity?: string
    ke1?: Uint8Array
}

function getTestInputs(vector: Vector): inputsRaw & inputsRawOpt {
    const opt: inputsRawOpt = {}
    if (vector.inputs.client_identity) {
        opt.client_identity = fromHexString(vector.inputs.client_identity)
    }
    if (vector.inputs.server_identity) {
        opt.server_identity = fromHexString(vector.inputs.server_identity)
    }
    if (vector.inputs.KE1) {
        opt.ke1 = fromHex(vector.inputs.KE1)
    }

    return {
        client_private_key: notNullHex(vector.inputs.client_private_key),
        client_public_key: notNullHex(vector.inputs.client_public_key),
        server_private_key: fromHex(vector.inputs.server_private_key),
        server_public_key: fromHex(vector.inputs.server_public_key),
        password: notNullHexString(vector.inputs.password),
        credential_identifier: fromHexString(vector.inputs.credential_identifier),
        oprf_seed: fromHex(vector.inputs.oprf_seed),
        masking_key: notNullHex(vector.inputs.masking_key),
        context: fromHexString(vector.config.Context),
        ksf: IdentityKSFFn,
        ...opt
    }
}

interface inputTest extends inputsRaw, inputsRawOpt {
    cfg: Config
    database: KVStorage
}

const FAKE_CREDENTIAL_IDENTIFIER = 'FAKE_CREDENTIAL_IDENTIFIER'
const FAKE_CLIENT_IDENTITY = 'FAKE_CLIENT_IDENTITY'

async function test_setup(input: inputTest): Promise<{
    client: OpaqueClient
    server: OpaqueServer
}> {
    const {
        cfg,
        database,
        ksf,
        server_identity,
        server_private_key,
        server_public_key,
        oprf_seed
    } = input

    // Client
    const client = new OpaqueClient(cfg, ksf)

    // Server
    const server = new OpaqueServer(
        cfg,
        Array.from(oprf_seed),
        {
            private_key: Array.from(server_private_key),
            public_key: Array.from(server_public_key)
        },
        server_identity
    )

    // To prevent Client enumeration, the server stores a fake record in
    // advance to be use when a non-registered user tries to login.
    const fake_record = await RegistrationRecord.createFakeRecord(cfg)
    const credential_file = new CredentialFile(
        FAKE_CREDENTIAL_IDENTIFIER,
        fake_record,
        FAKE_CLIENT_IDENTITY
    )

    const success = database.set_default(
        FAKE_CREDENTIAL_IDENTIFIER,
        Uint8Array.from(credential_file.serialize())
    )
    expect(success).toBe(true)

    return { client, server }
}

async function test_fake_registration(
    _client: OpaqueClient,
    _server: OpaqueServer,
    _input: inputTest,
    _vector: Vector
): Promise<boolean> {
    // This is a NOP since the Client never registers a password.
    return true
}

async function test_real_registration(
    client: OpaqueClient,
    server: OpaqueServer,
    input: inputTest,
    vector: Vector
): Promise<boolean> {
    const { password, server_identity, client_identity, credential_identifier, database } = input

    // Client
    const request = await client.registerInit(password)
    expectNotError(request)
    expect(toHex(Uint8Array.from(request.serialize()))).toBe(vector.outputs.registration_request)
    // Client        request         Server
    //           ------------->>>

    // Server
    const response = await server.registerInit(request, credential_identifier)
    expectNotError(response)
    expect(toHex(Uint8Array.from(response.serialize()))).toBe(vector.outputs.registration_response)
    // Client        response        Server
    //           <<<-------------

    // Client
    const rec = await client.registerFinish(response, server_identity, client_identity)
    expectNotError(rec)

    const { record, export_key } = rec
    expect(toHex(Uint8Array.from(record.serialize()))).toBe(vector.outputs.registration_upload)
    expect(toHex(Uint8Array.from(export_key))).toBe(vector.outputs.export_key)
    // Client        record          Server
    //           ------------->>>

    // Server
    const credential_file = new CredentialFile(credential_identifier, record, client_identity)
    const success = database.store(
        credential_identifier,
        Uint8Array.from(credential_file.serialize())
    )
    expect(success).toBe(true)
    // Client        success         Server
    //           <<<-------------

    return true
}

async function test_fake_login(
    client: OpaqueClient,
    server: OpaqueServer,
    input: inputTest,
    vector: Vector
): Promise<boolean> {
    const {
        cfg,
        context,
        server_identity,
        client_identity,
        credential_identifier,
        database,
        password
    } = input

    // Client
    const ke1 = await client.authInit(password)
    expectNotError(ke1)

    const ser_ke1 = ke1.serialize()
    expect(toHex(Uint8Array.from(ser_ke1))).toBe(vector.inputs.KE1)
    // Client          ke1           Server
    //           ------------->>>

    // Server
    const credFileBytes = database.lookup_or_default(credential_identifier)
    const credential_file = CredentialFile.deserialize(cfg, Array.from(credFileBytes))
    expect(credential_file.credential_identifier).toBe(FAKE_CREDENTIAL_IDENTIFIER)
    expect(credential_file.client_identity).toBe(FAKE_CLIENT_IDENTITY)

    // Set the inputs from the allegedly-register client.
    credential_file.credential_identifier = credential_identifier
    credential_file.client_identity = client_identity

    const deser_ke1 = KE1.deserialize(cfg, Array.from(ser_ke1))
    const ke2 = await server.authInit(
        deser_ke1,
        credential_file.record,
        credential_file.credential_identifier,
        credential_file.client_identity,
        context
    )
    expectNotError(ke2)

    const ser_ke2 = Uint8Array.from(ke2.serialize())
    expect(toHex(ser_ke2)).toBe(vector.outputs.KE2)

    // Client           ke2          Server
    //           <<<-------------

    // Client
    const deser_ke2 = KE2.deserialize(cfg, Array.from(ser_ke2))
    const finClient = await client.authFinish(deser_ke2, server_identity, client_identity, context)
    expectToBeError(finClient)
    expect(finClient.message).toBe('EnvelopeRecoveryError')

    return true
}

async function test_real_login(
    client: OpaqueClient,
    server: OpaqueServer,
    input: inputTest,
    vector: Vector
): Promise<boolean> {
    const {
        cfg,
        context,
        server_identity,
        client_identity,
        credential_identifier,
        database,
        password
    } = input

    // Client
    const ke1 = await client.authInit(password)
    expectNotError(ke1)

    const ser_ke1 = ke1.serialize()
    expect(toHex(Uint8Array.from(ser_ke1))).toBe(vector.outputs.KE1)
    // Client          ke1           Server
    //           ------------->>>

    // Server
    const credFileBytes = database.lookup_or_default(credential_identifier)
    expect(credFileBytes).not.toBe(false)

    const credential_file = CredentialFile.deserialize(cfg, Array.from(credFileBytes))
    expect(credential_file.credential_identifier).toBe(credential_identifier)
    expect(credential_file.client_identity).toBe(client_identity)

    const deser_ke1 = KE1.deserialize(cfg, ser_ke1)
    const ke2 = await server.authInit(
        deser_ke1,
        credential_file.record,
        credential_file.credential_identifier,
        credential_file.client_identity,
        context
    )
    expectNotError(ke2)

    const ser_ke2 = Uint8Array.from(ke2.serialize())
    expect(toHex(ser_ke2)).toBe(vector.outputs.KE2)
    // Client           ke2          Server
    //           <<<-------------

    // Client
    const deser_ke2 = KE2.deserialize(cfg, Array.from(ser_ke2))
    const finClient = await client.authFinish(deser_ke2, server_identity, client_identity, context)
    expectNotError(finClient)

    const { ke3, export_key } = finClient
    const ser_ke3 = Uint8Array.from(ke3.serialize())
    expect(toHex(ser_ke3)).toBe(vector.outputs.KE3)
    expect(toHex(Uint8Array.from(export_key))).toBe(vector.outputs.export_key)
    // Client           ke3          Server
    //           ------------->>>

    // Server
    const deser_ke3 = KE3.deserialize(cfg, Array.from(ser_ke3))
    const finServer = server.authFinish(deser_ke3)
    expectNotError(finServer)
    expect(toHex(Uint8Array.from(finServer.session_key))).toBe(vector.outputs.session_key)

    return true
}

function read_test_vectors(): Array<Vector> {
    const filename = './test/testdata/vectors_v16.json.gz'
    try {
        const file = readFileSync(filename)
        const json = unzipSync(file)
        const vectors = JSON.parse(json.toString())
        return vectors
    } catch (error) {
        console.error(`Error reading ${filename}: ${error}`)
        process.abort()
    }
}

describe.each(read_test_vectors())('test-vector-$#', (vector: Vector) => {
    const opaqueID = vector.config.OPRF
    const res = OpaqueConfig.fromString(opaqueID)
    const describe_or_skip = isOk(res) ? describe : describe.skip

    describe_or_skip(`${opaqueID}`, () => {
        const isFake = vector.config.Fake === 'True'
        let label = 'real'
        let test_registration = test_real_registration
        let test_login = test_real_login
        if (isFake) {
            label = 'fake'
            test_registration = test_fake_registration
            test_login = test_fake_login
        }

        let cfg: Config
        let input: inputTest
        let client: OpaqueClient
        let server: OpaqueServer

        beforeAll(() => {
            if (isOk(res)) {
                cfg = res.value
            }

            createMocks(vector, cfg, isFake)

            input = { cfg, database: new KVStorage(), ...getTestInputs(vector) }
        })

        test('Opaque-setup', async () => {
            expect(input.ksf.name).toBe(vector.config.KSF)
            ;({ client, server } = await test_setup(input))
            expect(client).toBeDefined()
            expect(server).toBeDefined()
        })

        test('Opaque-registration-' + label, async () => {
            expect(await test_registration(client, server, input, vector)).toBe(true)
        })

        test('Opaque-login-' + label, async () => {
            expect(await test_login(client, server, input, vector)).toBe(true)
        })
    })
})
