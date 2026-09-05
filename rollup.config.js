import commonjs from '@rollup/plugin-commonjs'
import { nodeResolve } from '@rollup/plugin-node-resolve'
import fs from 'fs'

const LICENSE = fs.readFileSync('./LICENSE.txt', { encoding: 'utf8', flag: 'r' })

export default [
    { name: 'client', input: './lib/src/index.js', output: 'dist/full.mjs' },
    { name: 'server', input: './lib/src/opaque_client.js', output: 'dist/client.mjs' },
    { name: 'full', input: './lib/src/opaque_server.js', output: 'dist/server.mjs' }
].map((value) => {
    return {
        input: value.input,
        plugins: [nodeResolve({ browser: true }), commonjs({ ignore: ['crypto'] })],
        output: {
            file: value.output,
            format: 'esm',
            banner:
                '/*\n\n    Cloudflare OPAQUE ' +
                process.env.npm_package_version +
                ' ' +
                value.name +
                '\n\n' +
                LICENSE +
                '\n*/\n'
        },
        context: 'this'
    }
})
