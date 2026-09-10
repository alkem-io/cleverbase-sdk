'use strict'

// The public package deliberately carries one local native binary for each supported target.
// There are no per-platform npm packages to fall back to.
const { join } = require('path')

const { platform, arch } = process
let target = `${platform}-${arch}`

if (platform === 'linux') {
  const report = process.report?.getReport?.()
  if (!report?.header?.glibcVersionRuntime) {
    throw new Error('Unsupported Linux libc: @alkemio/cleverbase-sdk requires glibc')
  }
  target += '-gnu'
}

const nativeFiles = {
  'darwin-arm64': 'cleverbase.darwin-arm64.node',
  'darwin-x64': 'cleverbase.darwin-x64.node',
  'linux-arm64-gnu': 'cleverbase.linux-arm64-gnu.node',
  'linux-x64-gnu': 'cleverbase.linux-x64-gnu.node',
}
const nativeFile = nativeFiles[target]

if (!nativeFile) {
  throw new Error(`Unsupported platform for @alkemio/cleverbase-sdk: ${target}`)
}

module.exports = require(join(__dirname, nativeFile))
