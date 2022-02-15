// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    AuthFinish,
    AuthResponse,
    CredentialResponse,
    ExpectedAuthResult,
    KE1,
    KE2
} from './messages.js'
import { checked_vector, ctEqual, joinAll } from './util.js'
import { deriveKeys, preambleBuild, tripleDH_IKM } from './common.js'

import { Config } from './config.js'

export class AKE3DHServer {
    constructor(private readonly config: Config) {}

    async response(
        server_private_key: Uint8Array,
        server_identity: Uint8Array,
        ke1: KE1,
        credential_response: CredentialResponse,
        context: Uint8Array,
        client_public_key: Uint8Array,
        client_identity?: Uint8Array
    ): Promise<{ ke2: KE2; expected: ExpectedAuthResult }> {
        const server_nonce = this.config.prng.random(this.config.constants.Nn)
        const { private_key: server_secret, public_key: server_keyshare } =
            await this.config.ake.generateAuthKeyPair()
        const tmp_server_mac = new Uint8Array(this.config.mac.Nm)
        const auth_response = new AuthResponse(
            this.config,
            new Uint8Array(server_nonce),
            new Uint8Array(server_keyshare),
            tmp_server_mac
        )
        const ke2 = new KE2(credential_response, auth_response)
        const preamble = preambleBuild(
            ke1,
            ke2,
            server_identity,
            client_identity ? client_identity : client_public_key,
            context
        )
        const ikm = tripleDH_IKM(this.config, [
            { sk: new Uint8Array(server_secret), pk: ke1.auth_init.client_keyshare },
            { sk: server_private_key, pk: ke1.auth_init.client_keyshare },
            { sk: new Uint8Array(server_secret), pk: client_public_key }
        ])
        const { Km2, Km3, session_key } = await deriveKeys(this.config, ikm, preamble)
        const h_preamble = await this.config.hash.sum(preamble)
        const server_mac = await (await this.config.mac.with_key(Km2)).sign(h_preamble)
        const h_preamble_mac = await this.config.hash.sum(joinAll([preamble, server_mac]))
        const expected_client_mac = await (await this.config.mac.with_key(Km3)).sign(h_preamble_mac)
        const expected = new ExpectedAuthResult(this.config, expected_client_mac, session_key)

        ke2.auth_response.server_mac = checked_vector(server_mac, this.config.mac.Nm)

        return { ke2, expected }
    }

    // eslint-disable-next-line class-methods-use-this
    finish(
        auth_finish: AuthFinish,
        expected: ExpectedAuthResult
    ): { session_key: number[] } | Error {
        if (!ctEqual(auth_finish.client_mac, expected.expected_client_mac)) {
            return new Error('handshake error')
        }
        return { session_key: Array.from(expected.session_key) }
    }
}
