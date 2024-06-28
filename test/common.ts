// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

export class KVStorage {
    kvStorage: Map<string, Uint8Array>
    default_key?: string

    constructor() {
        this.kvStorage = new Map<string, Uint8Array>()
    }

    store(k: string, v: Uint8Array): boolean {
        this.kvStorage.set(k, v)
        return true
    }

    lookup(k: string): false | Uint8Array {
        const v = this.kvStorage.get(k)
        if (v) {
            return v
        }
        return false
    }

    set_default(k: string, v: Uint8Array): boolean {
        const ok = this.store(k, v)
        this.default_key = k
        return ok
    }

    lookup_or_default(k: string): Uint8Array {
        const err_msj = 'no default entry has been set'
        if (!this.default_key) {
            throw new Error(err_msj)
        }

        const v = this.kvStorage.get(k) ?? this.kvStorage.get(this.default_key)
        if (!v) {
            throw new Error(err_msj)
        }

        return v
    }
}

export function fromHexString(x: string): string {
    return Buffer.from(x, 'hex').toString()
}

export function fromHex(x: string): Uint8Array {
    return Uint8Array.from(Buffer.from(x, 'hex'))
}

export function toHex(x: Uint8Array): string {
    return Buffer.from(x).toString('hex')
}

export function notNullHexString(x: unknown): string {
    return typeof x === 'string' ? fromHexString(x) : ''
}

export function notNullHex(x: unknown): Uint8Array {
    return typeof x === 'string' ? fromHex(x) : new Uint8Array(0)
}
