// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { AKEExportKeyPair, AKEKeyPair } from './thecrypto.js'
import {
    KE1,
    KE2,
    KE3,
    RegistrationRecord,
    RegistrationRequest,
    RegistrationResponse,
    Serializable
} from './messages.js'

import { AKE3DHServer } from './3dh_server.js'
import { Config } from './config.js'
import { OpaqueCoreServer } from './core_server.js'

export interface RegistrationServer {
    registerInit(
        request: RegistrationRequest,
        credential_identifier: string
    ): Promise<RegistrationResponse | Error>
}

export interface AuthServer {
    authInit(
        ke1: KE1,
        record: RegistrationRecord,
        credential_identifier: string,
        client_identity?: string,
        context?: string
    ): Promise<KE2 | Error>

    authFinish(ke3: KE3): { session_key: number[] } | Error
}

export class OpaqueServer implements RegistrationServer, AuthServer {
    private readonly ake_keypair: AKEKeyPair

    private readonly opaque_core: OpaqueCoreServer

    private readonly server_identity: Uint8Array

    private readonly ake: AKE3DHServer

    constructor(
        public readonly config: Config,
        oprf_seed: number[],
        ake_keypair_export: AKEExportKeyPair,
        server_identity?: string
    ) {
        Serializable.check_bytes_arrays([
            ake_keypair_export.public_key,
            ake_keypair_export.private_key
        ])
        this.ake_keypair = {
            private_key: new Uint8Array(ake_keypair_export.private_key),
            public_key: new Uint8Array(ake_keypair_export.public_key)
        }
        Serializable.check_bytes_array(oprf_seed)

        this.server_identity = server_identity
            ? new TextEncoder().encode(server_identity)
            : this.ake_keypair.public_key
        this.opaque_core = new OpaqueCoreServer(config, new Uint8Array(oprf_seed))
        this.ake = new AKE3DHServer(this.config)
    }

    registerInit(
        request: RegistrationRequest,
        credential_identifier: string
    ): Promise<RegistrationResponse | Error> {
        return this.opaque_core.createRegistrationResponse(
            request,
            this.ake_keypair.public_key,
            new TextEncoder().encode(credential_identifier)
        )
    }

    async authInit(
        ke1: KE1,
        record: RegistrationRecord,
        credential_identifier: string,
        client_identity?: string,
        context?: string
    ): Promise<KE2 | Error> {
        const credential_identifier_u8array = new TextEncoder().encode(credential_identifier)
        const credential_response = await this.opaque_core.createCredentialResponse(
            ke1.credential_request,
            record,
            this.ake_keypair.public_key,
            credential_identifier_u8array
        )
        const te = new TextEncoder()
        // eslint-disable-next-line no-undefined
        const client_identity_u8array = client_identity ? te.encode(client_identity) : undefined
        const context_u8array = context ? te.encode(context) : new Uint8Array(0)
        const auth_response = await this.ake.response(
            this.ake_keypair.private_key,
            this.server_identity,
            ke1,
            credential_response,
            context_u8array,
            record.client_public_key,
            client_identity_u8array
        )
        const ke2 = new KE2(credential_response, auth_response)

        return ke2
    }

    authFinish(ke3: KE3): { session_key: number[] } | Error {
        return this.ake.finish(ke3.auth_finish)
    }
}
