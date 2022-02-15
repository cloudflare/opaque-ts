// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

// Mocking crypto with @peculiar/webcrypto only for tests.
import { Crypto } from '@peculiar/webcrypto'

if (typeof crypto === 'undefined') {
    global.crypto = new Crypto()
}
