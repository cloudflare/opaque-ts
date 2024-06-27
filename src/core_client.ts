// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { AKEKeyPair, KSFFn, ScryptKSFFn } from './thecrypto.js'
import {
    CredentialRequest,
    CredentialResponse,
    Envelope,
    RegistrationRecord,
    RegistrationRequest,
    RegistrationResponse
} from './messages.js'
import { checked_vector, encode_vector_16, joinAll, xor } from './util.js'

import { Config } from './config.js'
import { LABELS } from './common.js'

class CleartextCredentials {
    server_public_key: Uint8Array

    server_identity: Uint8Array

    client_identity: Uint8Array

    constructor(
        cfg: Config,
        server_public_key: Uint8Array,
        client_public_key: Uint8Array,
        server_identity?: Uint8Array,
        client_identity?: Uint8Array
    ) {
        this.server_public_key = checked_vector(server_public_key, cfg.ake.Npk)
        this.server_identity = server_identity ? server_identity : server_public_key
        this.client_identity = client_identity ? client_identity : client_public_key
    }

    serialize(): number[] {
        return Array.from(
            joinAll([
                this.server_public_key,
                encode_vector_16(this.server_identity),
                encode_vector_16(this.client_identity)
            ])
        )
    }
}

async function expand_keys(
    cfg: Config,
    randomized_pwd: Uint8Array,
    envelope_nonce: Uint8Array
): Promise<{
    auth_key: Uint8Array
    export_key: Uint8Array
    client_ake_keypair: AKEKeyPair
}> {
    const auth_key = await cfg.kdf.expand(
        randomized_pwd,
        joinAll([envelope_nonce, Uint8Array.from(LABELS.AuthKey)]),
        cfg.hash.Nh
    )
    const export_key = await cfg.kdf.expand(
        randomized_pwd,
        joinAll([envelope_nonce, Uint8Array.from(LABELS.ExportKey)]),
        cfg.hash.Nh
    )
    const seed = await cfg.kdf.expand(
        randomized_pwd,
        joinAll([envelope_nonce, Uint8Array.from(LABELS.PrivateKey)]),
        cfg.constants.Nseed
    )
    const client_ake_keypair = await cfg.ake.deriveDHKeyPair(seed)

    return { auth_key, export_key, client_ake_keypair }
}

async function store(
    cfg: Config,
    randomized_pwd: Uint8Array,
    server_public_key: Uint8Array,
    server_identity?: Uint8Array,
    client_identity?: Uint8Array
): Promise<{
    envelope: Envelope
    client_public_key: Uint8Array
    masking_key: Uint8Array
    export_key: Uint8Array
}> {
    const envelope_nonce = new Uint8Array(cfg.prng.random(cfg.constants.Nn))
    const { auth_key, export_key, client_ake_keypair } = await expand_keys(
        cfg,
        randomized_pwd,
        envelope_nonce
    )
    const { public_key: client_public_key } = client_ake_keypair
    const cleartext_creds = new CleartextCredentials(
        cfg,
        server_public_key,
        client_public_key,
        server_identity,
        client_identity
    )
    const auth_msg = joinAll([envelope_nonce, Uint8Array.from(cleartext_creds.serialize())])
    const auth_tag = await (await cfg.mac.with_key(auth_key)).sign(auth_msg)
    const envelope = new Envelope(cfg, envelope_nonce, auth_tag)
    const masking_key = await cfg.kdf.expand(
        randomized_pwd,
        Uint8Array.from(LABELS.MaskingKey),
        cfg.hash.Nh
    )

    return { envelope, client_public_key, masking_key, export_key }
}

async function recover(
    cfg: Config,
    envelope: Envelope,
    randomized_pwd: Uint8Array,
    server_public_key: Uint8Array,
    server_identity?: Uint8Array,
    client_identity?: Uint8Array
): Promise<
    | {
          client_ake_keypair: AKEKeyPair
          export_key: Uint8Array
      }
    | Error
> {
    const { auth_key, export_key, client_ake_keypair } = await expand_keys(
        cfg,
        randomized_pwd,
        envelope.nonce
    )
    const { public_key: client_public_key } = client_ake_keypair
    const cleartext_creds = new CleartextCredentials(
        cfg,
        server_public_key,
        client_public_key,
        server_identity,
        client_identity
    )
    const auth_msg = joinAll([envelope.nonce, Uint8Array.from(cleartext_creds.serialize())])
    const mac = await cfg.mac.with_key(auth_key)

    if (!(await mac.verify(auth_msg, envelope.auth_tag))) {
        return new Error('EnvelopeRecoveryError')
    }
    return { client_ake_keypair, export_key }
}

export class OpaqueCoreClient {
    constructor(
        public readonly config: Config,
        private ksf: KSFFn = ScryptKSFFn
    ) {}

    async createRegistrationRequest(
        password: Uint8Array
    ): Promise<{ request: RegistrationRequest; blind: Uint8Array }> {
        const { blindedElement: M, blind } = await this.config.oprf.blind(password)
        const request = new RegistrationRequest(this.config, M)
        return { request, blind }
    }

    async finalizeRequest(
        password: Uint8Array,
        blind: Uint8Array,
        response: RegistrationResponse,
        server_identity?: Uint8Array,
        client_identity?: Uint8Array
    ): Promise<{
        record: RegistrationRecord
        export_key: number[]
    }> {
        const oprf_output = await this.config.oprf.finalize(password, blind, response.evaluation)
        const nosalt = new Uint8Array(this.config.hash.Nh)
        const stretched_oprf_output = this.ksf.harden(oprf_output)
        const randomized_pwd = await this.config.kdf.extract(
            nosalt,
            joinAll([oprf_output, stretched_oprf_output])
        )
        const { envelope, client_public_key, masking_key, export_key } = await store(
            this.config,
            randomized_pwd,
            response.server_public_key,
            server_identity,
            client_identity
        )
        const record = new RegistrationRecord(this.config, client_public_key, masking_key, envelope)

        return { record, export_key: Array.from(export_key) }
    }

    async createCredentialRequest(
        password: Uint8Array
    ): Promise<{ request: CredentialRequest; blind: Uint8Array }> {
        const { blindedElement: M, blind } = await this.config.oprf.blind(password)
        const request = new CredentialRequest(this.config, M)
        return { request, blind }
    }

    async recoverCredentials(
        password: Uint8Array,
        blind: Uint8Array,
        response: CredentialResponse,
        server_identity?: Uint8Array,
        client_identity?: Uint8Array
    ): Promise<
        | {
              client_ake_keypair: AKEKeyPair
              server_public_key: Uint8Array
              export_key: Uint8Array
          }
        | Error
    > {
        const y = await this.config.oprf.finalize(password, blind, response.evaluation)
        const nosalt = new Uint8Array(this.config.hash.Nh)
        const randomized_pwd = await this.config.kdf.extract(
            nosalt,
            joinAll([y, this.ksf.harden(y)])
        )
        const masking_key = await this.config.kdf.expand(
            randomized_pwd,
            Uint8Array.from(LABELS.MaskingKey),
            this.config.hash.Nh
        )
        const Ne = Envelope.sizeSerialized(this.config)
        const credential_response_pad = await this.config.kdf.expand(
            masking_key,
            joinAll([response.masking_nonce, Uint8Array.from(LABELS.CredentialResponsePad)]),
            this.config.ake.Npk + Ne
        )
        const server_pub_key_enve = xor(credential_response_pad, response.masked_response)
        const server_public_key = server_pub_key_enve.slice(0, this.config.ake.Npk)
        const { Npk } = this.config.ake
        const envelope_bytes = server_pub_key_enve.slice(Npk, Npk + Ne)
        const envelope = Envelope.deserialize(this.config, Array.from(envelope_bytes))
        const rec = await recover(
            this.config,
            envelope,
            randomized_pwd,
            server_public_key,
            server_identity,
            client_identity
        )
        if (rec instanceof Error) {
            return rec
        }
        return { server_public_key, ...rec }
    }
}
