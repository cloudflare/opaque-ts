// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    AuthClient,
    AuthServer,
    Config,
    CredentialFile,
    IdentityMemHardFn,
    KE1,
    KE2,
    KE3,
    MemoryHardFn,
    OpaqueClient,
    OpaqueID,
    OpaqueServer,
    getOpaqueConfig
} from '../src/index.js'
import { Blind, OPRFClient, Oprf } from '@cloudflare/voprf-ts'
import { KVStorage, fromHex, fromHexString, notNullHex, notNullHexString, toHex } from './common.js'

import { AKE3DH } from '../src/common.js'
import { jest } from '@jest/globals'
import vectors from './testdata/vectors_v07.json'

function createMocks(vector: typeof vectors[number], cfg: Config) {
    jest.clearAllMocks()

    // Creates a mock for OPRFClient.randomBlinder method to
    // inject the blind value given by the test vector.
    jest.spyOn(OPRFClient.prototype, 'randomBlinder')
        .mockImplementationOnce(() => {
            const blind = new Blind(notNullHex(vector.inputs.blind_registration))
            const group = Oprf.params(cfg.oprf.id).gg
            const scalar = group.deserializeScalar(blind)
            return Promise.resolve({ scalar, blind })
        })
        .mockImplementationOnce(() => {
            const blind = new Blind(notNullHex(vector.inputs.blind_login))
            const group = Oprf.params(cfg.oprf.id).gg
            const scalar = group.deserializeScalar(blind)
            return Promise.resolve({ scalar, blind })
        })

    jest.spyOn(AKE3DH.prototype, 'generateAuthKeyPair')
        .mockResolvedValueOnce({
            private_key: Array.from(notNullHex(vector.inputs.client_private_keyshare)),
            public_key: Array.from(notNullHex(vector.inputs.client_keyshare))
        })
        .mockResolvedValueOnce({
            private_key: Array.from(notNullHex(vector.inputs.server_private_keyshare)),
            public_key: Array.from(notNullHex(vector.inputs.server_keyshare))
        })

    jest.spyOn(crypto, 'getRandomValues')
        .mockReturnValueOnce(notNullHex(vector.inputs.envelope_nonce))
        .mockReturnValueOnce(notNullHex(vector.inputs.client_nonce))
        .mockReturnValueOnce(notNullHex(vector.inputs.masking_nonce))
        .mockReturnValueOnce(notNullHex(vector.inputs.server_nonce))
}

interface inputsRaw {
    password: string
    credential_identifier: string
    server_private_key: Uint8Array
    server_public_key: Uint8Array
    oprf_seed: Uint8Array
    context: string
    memHard: MemoryHardFn
}

interface inputsRawOpt {
    client_private_key?: Uint8Array
    client_identity?: string
    server_identity?: string
}

function getTestInputs(vector: typeof vectors[number]): inputsRaw & inputsRawOpt {
    const opt: inputsRawOpt = {}

    if (vector.inputs.client_identity) {
        opt.client_identity = fromHexString(vector.inputs.client_identity)
    }
    if (vector.inputs.server_identity) {
        opt.server_identity = fromHexString(vector.inputs.server_identity)
    }
    if (vector.inputs.client_private_key) {
        opt.client_private_key = fromHex(vector.inputs.client_private_key)
    }

    return {
        server_private_key: fromHex(vector.inputs.server_private_key),
        server_public_key: fromHex(vector.inputs.server_public_key),
        password: notNullHexString(vector.inputs.password),
        credential_identifier: fromHexString(vector.inputs.credential_identifier),
        oprf_seed: fromHex(vector.inputs.oprf_seed),
        context: fromHexString(vector.config.Context),
        memHard: IdentityMemHardFn,
        ...opt
    }
}

interface inputTest extends inputsRaw, inputsRawOpt {
    cfg: Config
    database: KVStorage
}

async function test_full_registration(input: inputTest, vector: typeof vectors[number]) {
    // Setup
    const {
        cfg,
        password,
        server_identity,
        client_identity,
        credential_identifier,
        database,
        memHard
    } = input
    const { server_private_key, server_public_key, oprf_seed } = input
    // Client
    const client = new OpaqueClient(cfg, memHard)
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
}

async function test_full_login(input: inputTest, vector: typeof vectors[number]) {
    // Setup
    const {
        cfg,
        context,
        password,
        server_identity,
        client_identity,
        credential_identifier,
        database,
        memHard
    } = input
    const { server_private_key, server_public_key, oprf_seed } = input
    // Client
    const client: AuthClient = new OpaqueClient(cfg, memHard)
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
    const ret_auth_init = await server.authInit(
        deser_ke1,
        credential_file.record,
        credential_file.credential_identifier,
        credential_file.client_identity,
        context
    )
    expect(ret_auth_init).not.toBeInstanceOf(Error)
    if (ret_auth_init instanceof Error) {
        throw new Error('server failed to authInit')
    }
    const { ke2, expected } = ret_auth_init
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
    const finServer = server.authFinish(deser_ke3, expected)
    expect(finServer).not.toBeInstanceOf(Error)
    if (finServer instanceof Error) {
        throw new Error('server failed to authenticate user')
    }

    expect(toHex(Uint8Array.from(finServer.session_key))).toBe(vector.outputs.session_key)
}

describe.each(vectors)('test-vector-$#', (vector: typeof vectors[number]) => {
    const opaqueID = parseInt(vector.config.OPRF, 10)

    if (vector.config.Fake === 'False' && opaqueID in OpaqueID) {
        const cfg = getOpaqueConfig(opaqueID)

        describe(`${cfg.toString()}`, () => {
            createMocks(vector, cfg)

            const input = { cfg, database: new KVStorage(), ...getTestInputs(vector) }

            test('Opaque-setup', () => expect(input.memHard.name).toBe(vector.config.MHF))

            test('Opaque-registration', () => test_full_registration(input, vector))

            test('Opaque-login', () => test_full_login(input, vector))
        })
    }
})
