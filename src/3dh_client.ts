// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { AuthFinish, AuthInit, KE1, KE2 } from './messages.js'
import { deriveKeys, preambleBuild, tripleDH_IKM } from './common.js'

import { Config } from './config.js'
import { joinAll } from './util.js'

export class AKE3DHClient {
    private client_secret?: Uint8Array

    constructor(private readonly config: Config) {}

    async start(): Promise<AuthInit> {
        const client_nonce = this.config.prng.random(this.config.constants.Nn)
        const { private_key: client_secret, public_key: client_keyshare } =
            await this.config.ake.generateAuthKeyPair()

        this.client_secret = new Uint8Array(client_secret)

        return new AuthInit(
            this.config,
            new Uint8Array(client_nonce),
            new Uint8Array(client_keyshare)
        )
    }

    async finalize(
        client_identity: Uint8Array,
        client_private_key: Uint8Array,
        server_identity: Uint8Array,
        server_public_key: Uint8Array,
        ke1: KE1,
        ke2: KE2,
        context: Uint8Array
    ): Promise<
        | {
              auth_finish: AuthFinish
              session_key: Uint8Array
          }
        | Error
    > {
        if (typeof this.client_secret === 'undefined') {
            return new Error('ake3dhclient has not started yet')
        }

        const ikm = tripleDH_IKM(this.config, [
            { sk: this.client_secret, pk: ke2.auth_response.server_keyshare },
            { sk: this.client_secret, pk: server_public_key },
            { sk: client_private_key, pk: ke2.auth_response.server_keyshare }
        ])
        const preamble = preambleBuild(ke1, ke2, server_identity, client_identity, context)
        const { Km2, Km3, session_key } = await deriveKeys(this.config, ikm, preamble)
        const h_preamble = await this.config.hash.sum(preamble)

        if (
            !(await (
                await this.config.mac.with_key(Km2)
            ).verify(h_preamble, ke2.auth_response.server_mac))
        ) {
            return new Error('handshake error')
        }

        const hmacData = await this.config.hash.sum(
            joinAll([preamble, ke2.auth_response.server_mac])
        )
        const client_mac = await (await this.config.mac.with_key(Km3)).sign(hmacData)
        const auth_finish = new AuthFinish(this.config, client_mac)

        return { auth_finish, session_key }
    }
}
