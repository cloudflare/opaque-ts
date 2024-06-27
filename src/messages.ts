// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { checked_vector, decode_vector_16, encode_vector_16, joinAll } from './util.js'

import { Config } from './config.js'

export abstract class Serializable {
    abstract serialize(): number[]

    static check_string(a: unknown): boolean {
        if (typeof a === 'string') {
            return true
        }
        throw new Error('string expected')
    }

    static check_uint8array(a: unknown): boolean {
        if (a instanceof Uint8Array) {
            return true
        }
        throw new Error('Uint8Array expected')
    }

    static check_uint8arrays(as: Uint8Array[]): boolean {
        return as.every(this.check_uint8array)
    }

    static check_bytes_array(a: unknown): boolean {
        if (
            !Array.isArray(a) ||
            !a.every((element) => Number.isInteger(element) && element >= 0 && element <= 255)
        ) {
            throw new Error('Array of byte-sized integers expected')
        }
        return true
    }

    static check_bytes_arrays(as: Array<unknown>): boolean {
        return as.every(this.check_bytes_array)
    }

    static sizeSerialized(_: Config): number {
        throw new Error('child class must implement')
    }

    static checked_bytes_to_uint8array(cfg: Config, bytes: number[]): Uint8Array {
        this.check_bytes_array(bytes)
        const u8array = Uint8Array.from(bytes)
        this.checked_object(cfg, u8array)
        return u8array
    }

    static checked_object(cfg: Config, u8array: Uint8Array): void {
        checked_vector(u8array, this.sizeSerialized(cfg), this.name)
    }
}

export class Envelope extends Serializable {
    nonce: Uint8Array

    auth_tag: Uint8Array

    constructor(cfg: Config, nonce: Uint8Array, auth_tag: Uint8Array) {
        super()
        this.nonce = checked_vector(nonce, cfg.constants.Nn)
        this.auth_tag = checked_vector(auth_tag, cfg.mac.Nm)
    }

    serialize(): number[] {
        return Array.from(joinAll([this.nonce, this.auth_tag]))
    }

    static sizeSerialized(cfg: Config): number {
        return cfg.constants.Nn + cfg.mac.Nm
    }

    static deserialize(cfg: Config, bytes: number[]): Envelope {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes)

        let start = 0
        let end = cfg.constants.Nn
        const nonce = u8array.slice(start, end)

        start = end
        end += cfg.mac.Nm
        const auth_tag = u8array.slice(start, end)
        return new Envelope(cfg, nonce, auth_tag)
    }
}

export class RegistrationRequest extends Serializable {
    data: Uint8Array

    constructor(cfg: Config, data: Uint8Array) {
        Serializable.check_uint8array(data)
        super()
        this.data = checked_vector(data, cfg.oprf.Noe)
    }

    serialize(): number[] {
        return Array.from(this.data)
    }

    static sizeSerialized(cfg: Config): number {
        return cfg.oprf.Noe
    }

    static deserialize(cfg: Config, bytes: number[]): RegistrationRequest {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes)
        const start = 0
        const end = cfg.oprf.Noe
        const data = u8array.slice(start, end)

        return new RegistrationRequest(cfg, data)
    }
}

export class RegistrationResponse extends Serializable {
    evaluation: Uint8Array

    server_public_key: Uint8Array

    constructor(cfg: Config, data: Uint8Array, server_public_key: Uint8Array) {
        Serializable.check_uint8arrays([data, server_public_key])
        super()
        this.evaluation = checked_vector(data, cfg.oprf.Noe)
        this.server_public_key = checked_vector(server_public_key, cfg.ake.Npk)
    }

    serialize(): number[] {
        return Array.from(joinAll([this.evaluation, this.server_public_key]))
    }

    static sizeSerialized(cfg: Config): number {
        return cfg.oprf.Noe + cfg.ake.Npk
    }

    static deserialize(cfg: Config, bytes: number[]): RegistrationResponse {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes)

        let start = 0
        let end = cfg.oprf.Noe
        const evaluation = u8array.slice(start, end)

        start = end
        end += cfg.ake.Npk
        const server_public_key = u8array.slice(start, end)
        return new RegistrationResponse(cfg, evaluation, server_public_key)
    }
}

export class RegistrationRecord extends Serializable {
    client_public_key: Uint8Array

    masking_key: Uint8Array

    envelope: Envelope

    constructor(
        cfg: Config,
        client_public_key: Uint8Array,
        masking_key: Uint8Array,
        envelope: Envelope
    ) {
        Serializable.check_uint8arrays([client_public_key, masking_key])
        super()
        this.client_public_key = checked_vector(client_public_key, cfg.ake.Npk)
        this.masking_key = checked_vector(masking_key, cfg.hash.Nh)
        this.envelope = envelope
    }

    serialize(): number[] {
        return Array.from(
            joinAll([
                this.client_public_key,
                this.masking_key,
                Uint8Array.from(this.envelope.serialize())
            ])
        )
    }

    static sizeSerialized(cfg: Config): number {
        return cfg.ake.Npk + cfg.hash.Nh + Envelope.sizeSerialized(cfg)
    }

    static deserialize(cfg: Config, bytes: number[]): RegistrationRecord {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes)

        let start = 0
        let end = cfg.ake.Npk
        const client_public_key = u8array.slice(start, end)

        start = end
        end += cfg.hash.Nh
        const masking_key = u8array.slice(start, end)

        start = end
        end += Envelope.sizeSerialized(cfg)
        const envelope_bytes = u8array.slice(start, end)
        const envelope = Envelope.deserialize(cfg, Array.from(envelope_bytes))
        return new RegistrationRecord(cfg, client_public_key, masking_key, envelope)
    }

    static async createFake(cfg: Config): Promise<RegistrationRecord> {
        const seed = cfg.prng.random(cfg.constants.Nseed)
        const { public_key: client_public_key } = await cfg.ake.deriveDHKeyPair(
            new Uint8Array(seed)
        )
        const masking_key = new Uint8Array(cfg.prng.random(cfg.hash.Nh))
        const envelope = Envelope.deserialize(cfg, new Array(Envelope.sizeSerialized(cfg)).fill(0))

        return new RegistrationRecord(cfg, client_public_key, masking_key, envelope)
    }
}

export class CredentialRequest extends Serializable {
    data: Uint8Array

    constructor(cfg: Config, data: Uint8Array) {
        Serializable.check_uint8array(data)
        super()
        this.data = checked_vector(data, cfg.oprf.Noe)
    }

    serialize(): number[] {
        return Array.from(this.data)
    }

    static sizeSerialized(cfg: Config): number {
        return cfg.oprf.Noe
    }

    static deserialize(cfg: Config, bytes: number[]): CredentialRequest {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes)
        const start = 0
        const end = cfg.oprf.Noe
        const data = u8array.slice(start, end)

        return new CredentialRequest(cfg, data)
    }
}

export class CredentialResponse extends Serializable {
    evaluation: Uint8Array

    masking_nonce: Uint8Array

    masked_response: Uint8Array

    constructor(
        cfg: Config,
        evaluation: Uint8Array,
        masking_nonce: Uint8Array,
        masked_response: Uint8Array
    ) {
        Serializable.check_uint8arrays([masking_nonce, masked_response])
        super()
        this.evaluation = evaluation
        this.masking_nonce = checked_vector(masking_nonce, cfg.constants.Nn)
        this.masked_response = checked_vector(
            masked_response,
            cfg.ake.Npk + Envelope.sizeSerialized(cfg)
        )
    }

    serialize(): number[] {
        return Array.from(joinAll([this.evaluation, this.masking_nonce, this.masked_response]))
    }

    static sizeSerialized(cfg: Config): number {
        return cfg.oprf.Noe + cfg.constants.Nn + cfg.ake.Npk + Envelope.sizeSerialized(cfg)
    }

    static deserialize(cfg: Config, bytes: number[]): CredentialResponse {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes)

        let start = 0
        let end = cfg.oprf.Noe
        const evaluation_bytes = u8array.slice(start, end)
        const evaluation = checked_vector(evaluation_bytes, cfg.oprf.Noe)

        start = end
        end += cfg.constants.Nn
        const masking_nonce = u8array.slice(start, end)

        start = end
        end += cfg.ake.Npk + Envelope.sizeSerialized(cfg)
        const masked_response = u8array.slice(start, end)

        return new CredentialResponse(cfg, evaluation, masking_nonce, masked_response)
    }
}

export class CredentialFile extends Serializable {
    credential_identifier: string

    record: RegistrationRecord

    client_identity?: string

    constructor(
        credential_identifier: string,
        record: RegistrationRecord,
        client_identity?: string
    ) {
        if (
            !(
                Serializable.check_string(credential_identifier) &&
                (client_identity ? Serializable.check_string(client_identity) : true)
            )
        ) {
            throw new Error('expected string inputs')
        }
        super()
        this.credential_identifier = credential_identifier
        this.record = record
        this.client_identity = client_identity
    }

    serialize(): number[] {
        const te = new TextEncoder()
        return Array.from(
            joinAll([
                encode_vector_16(te.encode(this.credential_identifier)),
                Uint8Array.from(this.record.serialize()),
                encode_vector_16(te.encode(this.client_identity))
            ])
        )
    }

    static sizeSerialized(cfg: Config): number {
        // This is the minimum size of a valid CredentialFile.
        return (
            2 + // Size of header for credential_identifier.
            RegistrationRecord.sizeSerialized(cfg) +
            2 // Size of header for client_identity.
        )
    }

    static deserialize(cfg: Config, bytes: number[]): CredentialFile {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes)
        const td = new TextDecoder()
        const res = decode_vector_16(u8array)
        const credential_identifier = td.decode(res.payload)
        let start = 0
        let end = res.consumed

        start = end
        end += RegistrationRecord.sizeSerialized(cfg)
        const record = RegistrationRecord.deserialize(cfg, Array.from(u8array.slice(start, end)))

        start = end
        const { payload } = decode_vector_16(u8array.slice(start))
        const client_identity = payload.length === 0 ? undefined : td.decode(payload) // eslint-disable-line no-undefined

        return new CredentialFile(credential_identifier, record, client_identity)
    }
}

export class AuthRequest extends Serializable {
    client_nonce: Uint8Array

    client_public_keyshare: Uint8Array

    constructor(cfg: Config, client_nonce: Uint8Array, client_public_keyshare: Uint8Array) {
        Serializable.check_uint8arrays([client_nonce, client_public_keyshare])
        super()
        this.client_nonce = checked_vector(client_nonce, cfg.constants.Nn)
        this.client_public_keyshare = checked_vector(client_public_keyshare, cfg.ake.Npk)
    }

    serialize(): number[] {
        return Array.from(joinAll([this.client_nonce, this.client_public_keyshare]))
    }

    static sizeSerialized(cfg: Config): number {
        return cfg.constants.Nn + cfg.ake.Npk
    }

    static deserialize(cfg: Config, bytes: number[]): AuthRequest {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes)

        let start = 0
        let end = cfg.constants.Nn
        const client_nonce = u8array.slice(start, end)

        start = end
        end += cfg.ake.Npk
        const client_public_keyshare = u8array.slice(start, end)

        return new AuthRequest(cfg, client_nonce, client_public_keyshare)
    }
}

export class AuthResponse extends Serializable {
    server_nonce: Uint8Array

    server_public_keyshare: Uint8Array

    server_mac: Uint8Array

    constructor(
        cfg: Config,
        server_nonce: Uint8Array,
        server_public_keyshare: Uint8Array,
        server_mac: Uint8Array
    ) {
        Serializable.check_uint8arrays([server_nonce, server_public_keyshare, server_mac])
        super()
        this.server_nonce = checked_vector(server_nonce, cfg.constants.Nn)
        this.server_public_keyshare = checked_vector(server_public_keyshare, cfg.ake.Npk)
        this.server_mac = checked_vector(server_mac, cfg.mac.Nm)
    }

    serialize(): number[] {
        return Array.from(
            joinAll([this.server_nonce, this.server_public_keyshare, this.server_mac])
        )
    }

    static sizeSerialized(cfg: Config): number {
        return cfg.constants.Nn + cfg.ake.Npk + cfg.mac.Nm
    }

    static deserialize(cfg: Config, bytes: number[]): AuthResponse {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes)

        let start = 0
        let end = cfg.constants.Nn
        const server_nonce = u8array.slice(start, end)

        start = end
        end += cfg.ake.Npk
        const server_public_keyshare = u8array.slice(start, end)

        start = end
        end += cfg.mac.Nm
        const server_mac = u8array.slice(start, end)

        return new AuthResponse(cfg, server_nonce, server_public_keyshare, server_mac)
    }
}

export class AuthFinish extends Serializable {
    client_mac: Uint8Array

    constructor(cfg: Config, client_mac: Uint8Array) {
        Serializable.check_uint8array(client_mac)
        super()
        this.client_mac = checked_vector(client_mac, cfg.mac.Nm)
    }

    serialize(): number[] {
        return Array.from(this.client_mac.slice())
    }

    static sizeSerialized(cfg: Config): number {
        return cfg.mac.Nm
    }

    static deserialize(cfg: Config, bytes: number[]): AuthFinish {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes)
        const start = 0
        const end = cfg.mac.Nm
        const client_mac = u8array.slice(start, end)

        return new AuthFinish(cfg, client_mac)
    }
}

export class ExpectedAuthResult extends Serializable {
    expected_client_mac: Uint8Array

    session_key: Uint8Array

    constructor(cfg: Config, expected_client_mac: Uint8Array, session_key: Uint8Array) {
        Serializable.check_uint8arrays([expected_client_mac, session_key])
        super()
        this.expected_client_mac = checked_vector(expected_client_mac, cfg.mac.Nm)
        this.session_key = checked_vector(session_key, cfg.kdf.Nx)
    }

    serialize(): number[] {
        return Array.from(joinAll([this.expected_client_mac, this.session_key]))
    }

    static sizeSerialized(cfg: Config): number {
        return cfg.mac.Nm + cfg.kdf.Nx
    }

    static deserialize(cfg: Config, bytes: number[]): ExpectedAuthResult {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes)

        let start = 0
        let end = cfg.mac.Nm
        const expected_client_mac = u8array.slice(start, end)

        start = end
        end += cfg.kdf.Nx
        const session_key = u8array.slice(start, end)

        return new ExpectedAuthResult(cfg, expected_client_mac, session_key)
    }
}

export class KE1 extends Serializable {
    constructor(
        public credential_request: CredentialRequest,
        public auth_request: AuthRequest
    ) {
        super()
    }

    serialize(): number[] {
        return [...this.credential_request.serialize(), ...this.auth_request.serialize()]
    }

    static sizeSerialized(cfg: Config): number {
        return CredentialRequest.sizeSerialized(cfg) + AuthRequest.sizeSerialized(cfg)
    }

    static deserialize(cfg: Config, bytes: number[]): KE1 {
        this.checked_bytes_to_uint8array(cfg, bytes)
        let start = 0
        let end = CredentialRequest.sizeSerialized(cfg)
        const credential_request = CredentialRequest.deserialize(cfg, bytes.slice(start, end))

        start = end
        end += AuthRequest.sizeSerialized(cfg)
        const auth_request = AuthRequest.deserialize(cfg, bytes.slice(start, end))

        return new KE1(credential_request, auth_request)
    }
}

export class KE2 extends Serializable {
    constructor(
        public credential_response: CredentialResponse,
        public auth_response: AuthResponse
    ) {
        super()
    }

    serialize(): number[] {
        return [...this.credential_response.serialize(), ...this.auth_response.serialize()]
    }

    static sizeSerialized(cfg: Config): number {
        return CredentialResponse.sizeSerialized(cfg) + AuthResponse.sizeSerialized(cfg)
    }

    static deserialize(cfg: Config, bytes: number[]): KE2 {
        this.checked_bytes_to_uint8array(cfg, bytes)
        let start = 0
        let end = CredentialResponse.sizeSerialized(cfg)
        const credential_response = CredentialResponse.deserialize(cfg, bytes.slice(start, end))

        start = end
        end += AuthResponse.sizeSerialized(cfg)
        const auth_response = AuthResponse.deserialize(cfg, bytes.slice(start, end))

        return new KE2(credential_response, auth_response)
    }
}

export class KE3 extends Serializable {
    constructor(public auth_finish: AuthFinish) {
        super()
    }

    serialize(): number[] {
        return this.auth_finish.serialize()
    }

    static sizeSerialized(cfg: Config): number {
        return AuthFinish.sizeSerialized(cfg)
    }

    static deserialize(cfg: Config, bytes: number[]): KE3 {
        this.checked_bytes_to_uint8array(cfg, bytes)

        const start = 0
        const end = Number(AuthFinish.sizeSerialized(cfg))
        const auth_finish = AuthFinish.deserialize(cfg, bytes.slice(start, end))

        return new KE3(auth_finish)
    }
}
