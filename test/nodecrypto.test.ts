import { execFileSync } from 'child_process'

test('WebCrypto works in Node ESM without a global crypto polyfill', () => {
    const moduleUrl = new URL('../src/thecrypto.js', import.meta.url).href
    const result = execFileSync(process.execPath, [
        '--input-type=module',
        '--eval',
        `
        delete globalThis.crypto;
        const { Prng, Hash, Hmac } = await import(${JSON.stringify(moduleUrl)});
        const { createHmac } = await import('crypto');
        const encode = text => new TextEncoder().encode(text);
        const hash = await new Hash(Hash.ID.SHA256).sum(encode('abc'));
        const mac = await new Hmac(Hash.ID.SHA256).with_key(encode('key'));
        const signature = await mac.sign(encode('message'));
        process.stdout.write(JSON.stringify({
            randomLength: new Prng().random(32).length,
            hash: Buffer.from(hash).toString('hex'),
            validMac: Buffer.from(signature).equals(createHmac('sha256', 'key').update('message').digest())
        }));
        `
    ])

    expect(JSON.parse(result.toString())).toEqual({
        randomLength: 32,
        hash: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        validMac: true
    })
})
