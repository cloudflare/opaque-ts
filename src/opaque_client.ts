// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    KE1,
    KE2,
    KE3,
    RegistrationRecord,
    RegistrationRequest,
    RegistrationResponse
} from './messages.js'
import { KSFFn, ScryptKSFFn } from './thecrypto.js'

import { AKE3DHClient } from './3dh_client.js'
import { Config } from './config.js'
import { OpaqueCoreClient } from './core_client.js'

export interface RegistrationClient {
    registerInit(password: string): Promise<RegistrationRequest | Error>
    registerFinish(
        response: RegistrationResponse,
        server_identity?: string,
        client_identity?: string
    ): Promise<
        | {
              record: RegistrationRecord
              export_key: number[]
          }
        | Error
    >
}

export interface AuthClient {
    authInit(password: string): Promise<KE1 | Error>
    authFinish(
        ke2: KE2,
        server_identity?: string,
        client_identity?: string,
        context?: string
    ): Promise<
        | {
              ke3: KE3
              session_key: number[]
              export_key: number[]
          }
        | Error
    >
}

export class OpaqueClient implements RegistrationClient, AuthClient {
    private static States = {
        NEW: 0,
        REG_STARTED: 1,
        LOG_STARTED: 2
    } as const

    private status: (typeof OpaqueClient.States)[keyof typeof OpaqueClient.States]

    private blind?: Uint8Array

    private password?: Uint8Array

    private readonly opaque_core: OpaqueCoreClient

    private readonly ake: AKE3DHClient

    constructor(
        public readonly config: Config,
        ksf: KSFFn = ScryptKSFFn
    ) {
        this.status = OpaqueClient.States.NEW
        this.opaque_core = new OpaqueCoreClient(config, ksf)
        this.ake = new AKE3DHClient(this.config)
    }

    async registerInit(password: string): Promise<RegistrationRequest | Error> {
        if (this.status !== OpaqueClient.States.NEW) {
            return new Error('client not ready')
        }
        const password_uint8array = new TextEncoder().encode(password)
        const { request, blind } =
            await this.opaque_core.createRegistrationRequest(password_uint8array)
        this.blind = blind
        this.password = password_uint8array
        this.status = OpaqueClient.States.REG_STARTED
        return request
    }

    async registerFinish(
        response: RegistrationResponse,
        server_identity?: string,
        client_identity?: string
    ): Promise<
        | {
              record: RegistrationRecord
              export_key: number[]
          }
        | Error
    > {
        if (
            this.status !== OpaqueClient.States.REG_STARTED ||
            typeof this.password === 'undefined' ||
            typeof this.blind === 'undefined'
        ) {
            return new Error('client not ready')
        }
        const te = new TextEncoder()
        const server_identity_u8array = server_identity ? te.encode(server_identity) : undefined
        const client_identity_u8array = client_identity ? te.encode(client_identity) : undefined
        const out = await this.opaque_core.finalizeRequest(
            this.password,
            this.blind,
            response,
            server_identity_u8array,
            client_identity_u8array
        )
        this.clean()
        return out
    }

    async authInit(password: string): Promise<KE1 | Error> {
        if (this.status !== OpaqueClient.States.NEW) {
            return new Error('client not ready')
        }
        const password_u8array = new TextEncoder().encode(password)
        const { request, blind } = await this.opaque_core.createCredentialRequest(password_u8array)
        const ke1 = await this.ake.start(request)

        this.blind = blind
        this.password = password_u8array
        this.status = OpaqueClient.States.LOG_STARTED

        return ke1
    }

    async authFinish(
        ke2: KE2,
        server_identity?: string,
        client_identity?: string,
        context?: string
    ): Promise<
        | {
              ke3: KE3
              session_key: number[]
              export_key: number[]
          }
        | Error
    > {
        if (
            this.status !== OpaqueClient.States.LOG_STARTED ||
            typeof this.password === 'undefined' ||
            typeof this.blind === 'undefined'
        ) {
            return new Error('client not ready')
        }

        const te = new TextEncoder()
        const server_identity_u8array = server_identity ? te.encode(server_identity) : undefined
        const client_identity_u8array = client_identity ? te.encode(client_identity) : undefined
        const context_u8array = context ? te.encode(context) : new Uint8Array(0)
        const rec = await this.opaque_core.recoverCredentials(
            this.password,
            this.blind,
            ke2.credential_response,
            server_identity_u8array,
            client_identity_u8array
        )
        if (rec instanceof Error) {
            return rec
        }

        const { client_ake_keypair, server_public_key, export_key } = rec
        const fin = await this.ake.finalize(
            client_identity_u8array ? client_identity_u8array : client_ake_keypair.public_key,
            client_ake_keypair.private_key,
            server_identity_u8array ? server_identity_u8array : server_public_key,
            server_public_key,
            ke2,
            context_u8array
        )
        if (fin instanceof Error) {
            return fin
        }
        const { auth_finish, session_key } = fin
        const ke3 = new KE3(auth_finish)

        this.clean()
        return { ke3, session_key: Array.from(session_key), export_key: Array.from(export_key) }
    }

    private clean(): void {
        this.status = OpaqueClient.States.NEW
        this.password = undefined // eslint-disable-line no-undefined
        this.blind = undefined // eslint-disable-line no-undefined
    }
}
