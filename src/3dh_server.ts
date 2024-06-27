// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    AuthFinish,
    AuthResponse,
    CredentialResponse,
    ExpectedAuthResult,
    KE1
} from './messages.js'
import { ctEqual, joinAll } from './util.js'
import { deriveKeys, preambleBuild, tripleDH_IKM } from './common.js'

import { Config } from './config.js'

export class AKE3DHServer {
    private expected?: ExpectedAuthResult

    constructor(private readonly config: Config) {}

    async response(
        server_private_key: Uint8Array,
        server_identity: Uint8Array,
        ke1: KE1,
        credential_response: CredentialResponse,
        context: Uint8Array,
        client_public_key: Uint8Array,
        client_identity?: Uint8Array
    ): Promise<AuthResponse> {
        const server_nonce = Uint8Array.from(this.config.prng.random(this.config.constants.Nn))
        const server_keyshare_seed = Uint8Array.from(
            this.config.prng.random(this.config.constants.Nseed)
        )
        const { private_key: server_secret, public_key: server_public_keyshare } =
            await this.config.ake.deriveDHKeyPair(server_keyshare_seed)
        const preamble = preambleBuild(
            client_identity ? client_identity : client_public_key,
            ke1,
            server_identity,
            credential_response,
            server_nonce,
            server_public_keyshare,
            context
        )
        const ikm = tripleDH_IKM(this.config, [
            { sk: new Uint8Array(server_secret), pk: ke1.auth_request.client_public_keyshare },
            { sk: server_private_key, pk: ke1.auth_request.client_public_keyshare },
            { sk: new Uint8Array(server_secret), pk: client_public_key }
        ])
        const { Km2, Km3, session_key } = await deriveKeys(this.config, ikm, preamble)
        const h_preamble = await this.config.hash.sum(preamble)
        const server_mac = await (await this.config.mac.with_key(Km2)).sign(h_preamble)
        const h_preamble_mac = await this.config.hash.sum(joinAll([preamble, server_mac]))
        const expected_client_mac = await (await this.config.mac.with_key(Km3)).sign(h_preamble_mac)
        this.expected = new ExpectedAuthResult(this.config, expected_client_mac, session_key)

        const auth_response = new AuthResponse(
            this.config,
            server_nonce,
            server_public_keyshare,
            server_mac
        )

        return auth_response
    }

    finish(auth_finish: AuthFinish): { session_key: number[] } | Error {
        if (!this.expected) {
            return new Error('handshake error')
        }
        if (!ctEqual(auth_finish.client_mac, this.expected.expected_client_mac)) {
            return new Error('handshake error')
        }
        return { session_key: Array.from(this.expected.session_key) }
    }
}
