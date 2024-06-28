// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

export function joinAll(a: Uint8Array[]): Uint8Array {
    let size = 0
    for (let i = 0; i < a.length; i++) {
        size += a[i as number].length
    }
    const ret = new Uint8Array(new ArrayBuffer(size))
    for (let i = 0, offset = 0; i < a.length; i++) {
        ret.set(a[i as number], offset)
        offset += a[i as number].length
    }
    return ret
}

export function encode_number(n: number, bits: number): Uint8Array {
    if (!(bits > 0 && bits <= 32)) {
        throw new Error('only supports 32-bit encoding')
    }
    const max = 1 << bits
    if (!(n >= 0 && n < max)) {
        throw new Error(`number out of range [0,2^${bits}-1]`)
    }
    const numBytes = Math.ceil(bits / 8)
    const out = new Uint8Array(numBytes)
    for (let i = 0; i < numBytes; i++) {
        out[(numBytes - 1 - i) as number] = (n >> (8 * i)) & 0xff
    }
    return out
}

function decode_number(a: Uint8Array, bits: number): number {
    if (!(bits > 0 && bits <= 32)) {
        throw new Error('only supports 32-bit encoding')
    }
    const numBytes = Math.ceil(bits / 8)
    if (a.length !== numBytes) {
        throw new Error('array has wrong size')
    }
    let out = 0
    for (let i = 0; i < a.length; i++) {
        out <<= 8
        out += a[i as number]
    }
    return out
}

function encode_vector(a: Uint8Array, bits_header: number): Uint8Array {
    return joinAll([encode_number(a.length, bits_header), a])
}

function decode_vector(
    a: Uint8Array,
    bits_header: number
): {
    payload: Uint8Array
    consumed: number
} {
    if (a.length === 0) {
        throw new Error('empty vector not allowed')
    }
    const numBytes = Math.ceil(bits_header / 8)
    const header = a.subarray(0, numBytes)
    const len = decode_number(header, bits_header)
    const consumed = numBytes + len
    const payload = a.slice(numBytes, consumed)
    return { payload, consumed }
}

export function encode_vector_8(a: Uint8Array): Uint8Array {
    return encode_vector(a, 8)
}

export function encode_vector_16(a: Uint8Array): Uint8Array {
    return encode_vector(a, 16)
}

export function decode_vector_16(a: Uint8Array): {
    payload: Uint8Array
    consumed: number
} {
    return decode_vector(a, 16)
}

export function checked_vector(a: Uint8Array, n: number, str = 'array'): Uint8Array {
    if (a.length < n) {
        throw new Error(`${str} has wrong length of ${a.length} expected ${n}`)
    }
    return a.slice(0, n)
}

export function checked_vector_array(a: number[], n: number, str = 'array'): Uint8Array {
    return checked_vector(Uint8Array.from(a), n, str)
}

export function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
    if (a.length !== b.length || a.length === 0) {
        throw new Error('arrays of different length')
    }
    const n = a.length
    const c = new Uint8Array(n)
    for (let i = 0; i < n; i++) {
        c[i as number] = a[i as number] ^ b[i as number]
    }
    return c
}

export function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length || a.length === 0) {
        throw new Error('arrays of different length')
    }
    const n = a.length
    let c = 0
    for (let i = 0; i < n; i++) {
        c |= a[i as number] ^ b[i as number]
    }
    return c === 0
}
