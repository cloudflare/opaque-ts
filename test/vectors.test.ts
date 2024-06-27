// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    AuthClient,
    AuthServer,
    Config,
    CredentialFile,
    Envelope,
    IdentityKSFFn,
    KE1,
    KE2,
    KE3,
    KSFFn,
    OpaqueClient,
    OpaqueConfig,
    OpaqueServer,
    RegistrationRecord,
    isOk
} from '../src/index.js'
import { KVStorage, fromHex, fromHexString, notNullHex, notNullHexString, toHex } from './common.js'
import { OPRFClient, Oprf, SuiteID } from '@cloudflare/voprf-ts'

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

    if (!isFake) {
        // Creates a mock for OPRFClient.randomBlinder method to
        // inject the blind value given by the test vector.
        jest.spyOn(OPRFClient.prototype, 'randomBlinder').mockImplementationOnce(() => {
            const blind = notNullHex(vector.inputs.blind_registration)
            const group = Oprf.getGroup(cfg.oprf.id as SuiteID)
            const scalar = group.desScalar(blind)
            return Promise.resolve(scalar)
        })

        jest.spyOn(OPRFClient.prototype, 'randomBlinder').mockImplementationOnce(() => {
            const blind = notNullHex(vector.inputs.blind_login)
            const group = Oprf.getGroup(cfg.oprf.id as SuiteID)
            const scalar = group.desScalar(blind)
            return Promise.resolve(scalar)
        })

        jest.spyOn(crypto, 'getRandomValues')
            .mockReturnValueOnce(notNullHex(vector.inputs.envelope_nonce))
            .mockReturnValueOnce(notNullHex(vector.inputs.client_nonce))
            .mockReturnValueOnce(notNullHex(vector.inputs.client_keyshare_seed))
    }

    jest.spyOn(crypto, 'getRandomValues')
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

async function test_fake_registration(input: inputTest, _vector: Vector): Promise<boolean> {
    const fake_client_public_key = input.client_public_key
    const fake_masking_key = input.masking_key
    const nonce = new Uint8Array(input.cfg.constants.Nn)
    const auth_tag = new Uint8Array(input.cfg.mac.Nm)
    const fake_envelope = new Envelope(input.cfg, nonce, auth_tag)
    const record = new RegistrationRecord(
        input.cfg,
        fake_client_public_key,
        fake_masking_key,
        fake_envelope
    )

    // Server
    const credential_file = new CredentialFile(
        input.credential_identifier,
        record,
        input.client_identity
    )
    const success = input.database.store(
        input.credential_identifier,
        Uint8Array.from(credential_file.serialize())
    )
    expect(success).toBe(true)
    return true
}

async function test_real_registration(input: inputTest, vector: Vector): Promise<boolean> {
    // Setup
    const {
        cfg,
        password,
        server_identity,
        client_identity,
        credential_identifier,
        database,
        ksf
    } = input
    const { server_private_key, server_public_key, oprf_seed } = input
    // Client
    const client = new OpaqueClient(cfg, ksf)
    const request = await client.registerInit(password)
    expect(request).not.toBeInstanceOf(Error)
    if (request instanceof Error) {
        throw new Error('client failed to registerInit')
    }

    expect(toHex(Uint8Array.from(request.serialize()))).toBe(vector.outputs.registration_request)
    // Client        request         Server
    //           ------------->>>

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
    const response = await server.registerInit(request, credential_identifier)
    expect(response).not.toBeInstanceOf(Error)
    if (response instanceof Error) {
        throw new Error('server failed to registerInit')
    }

    expect(toHex(Uint8Array.from(response.serialize()))).toBe(vector.outputs.registration_response)
    // Client        response        Server
    //           <<<-------------

    // Client
    const rec = await client.registerFinish(response, server_identity, client_identity)
    expect(rec).not.toBeInstanceOf(Error)
    if (rec instanceof Error) {
        throw new Error('client failed to registerFinish')
    }

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

async function test_fake_login(input: inputTest, vector: Vector): Promise<boolean> {
    // Setup
    const {
        cfg,
        context,
        server_identity,
        client_identity,
        credential_identifier,
        database,
        ke1: ser_ke1
    } = input
    const { server_private_key, server_public_key, oprf_seed } = input

    if (!ser_ke1) {
        throw new Error('KE1 is not present')
    }

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
        Array.from(oprf_seed),
        {
            private_key: Array.from(server_private_key),
            public_key: Array.from(server_public_key)
        },
        server_identity
    )

    const ke1 = KE1.deserialize(cfg, Array.from(ser_ke1))
    const ke2 = await server.authInit(
        ke1,
        credential_file.record,
        credential_file.credential_identifier,
        credential_file.client_identity,
        context
    )
    expect(ke2).not.toBeInstanceOf(Error)
    if (ke2 instanceof Error) {
        throw new Error('server failed to authInit')
    }
    const ser_ke2 = Uint8Array.from(ke2.serialize())
    expect(toHex(ser_ke2)).toBe(vector.outputs.KE2)

    // Client           ke2          Server
    //           <<<-------------

    // Client
    // [TODO] We must check that the client tries to complete the
    // protocol and fails.
    //
    // const deser_ke2 = KE2.deserialize(cfg, Array.from(ser_ke2))
    // const finClient = await client.authFinish(deser_ke2, server_identity, client_identity, context)

    // if (finClient instanceof Error) {
    //     expect(finClient.message).toBe('EnvelopeRecoveryError')
    // }

    return true
}

async function test_real_login(input: inputTest, vector: Vector): Promise<boolean> {
    // Setup
    const {
        cfg,
        context,
        server_identity,
        client_identity,
        credential_identifier,
        database,
        password,
        ksf
    } = input
    const { server_private_key, server_public_key, oprf_seed } = input
    // Client
    const client: AuthClient = new OpaqueClient(cfg, ksf)
    const ke1 = await client.authInit(password)
    expect(ke1).not.toBeInstanceOf(Error)
    if (ke1 instanceof Error) {
        throw new Error('client failed to authInit')
    }

    const ser_ke1 = ke1.serialize()
    expect(toHex(Uint8Array.from(ser_ke1))).toBe(vector.outputs.KE1)
    // Client          ke1           Server
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
        Array.from(oprf_seed),
        {
            private_key: Array.from(server_private_key),
            public_key: Array.from(server_public_key)
        },
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
    expect(ke2).not.toBeInstanceOf(Error)
    if (ke2 instanceof Error) {
        throw new Error('server failed to authInit')
    }
    const ser_ke2 = Uint8Array.from(ke2.serialize())
    expect(toHex(ser_ke2)).toBe(vector.outputs.KE2)
    // Client           ke2          Server
    //           <<<-------------

    // Client
    const deser_ke2 = KE2.deserialize(cfg, Array.from(ser_ke2))
    const finClient = await client.authFinish(deser_ke2, server_identity, client_identity, context)
    expect(finClient).not.toBeInstanceOf(Error)
    if (finClient instanceof Error) {
        throw new Error('client failed to authFinish')
    }
    const { ke3, export_key } = finClient
    const ser_ke3 = Uint8Array.from(ke3.serialize())
    expect(toHex(ser_ke3)).toBe(vector.outputs.KE3)
    expect(toHex(Uint8Array.from(export_key))).toBe(vector.outputs.export_key)
    // Client           ke3          Server
    //           ------------->>>

    // Server
    const deser_ke3 = KE3.deserialize(cfg, Array.from(ser_ke3))
    const finServer = server.authFinish(deser_ke3)
    expect(finServer).not.toBeInstanceOf(Error)
    if (finServer instanceof Error) {
        throw new Error('server failed to authenticate user')
    }

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

        beforeAll(() => {
            if (isOk(res)) {
                cfg = res.value
            }

            createMocks(vector, cfg, isFake)

            input = { cfg, database: new KVStorage(), ...getTestInputs(vector) }
        })

        test('Opaque-setup', () => {
            expect(input.ksf.name).toBe(vector.config.KSF)
        })

        test('Opaque-registration-' + label, async () => {
            expect(await test_registration(input, vector)).toBe(true)
        })

        test('Opaque-login-' + label, async () => {
            expect(await test_login(input, vector)).toBe(true)
        })
    })
})
