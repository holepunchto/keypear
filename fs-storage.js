const fs = require('fs')
const path = require('path')
const b4a = require('b4a')
const sodium = require('sodium-native')

exports.open = async function open (filename) {
  let seed = null

  try {
    seed = await fs.promises.readFile(filename)
    if (seed.byteLength < 32) throw new Error('seed too short')
    return seed.subarray(0, 32)
  } catch {
    seed = b4a.alloc(32)
    sodium.randombytes_buf(seed)
  }

  await fs.promises.mkdir(path.dirname(filename), { recursive: true })
  await fs.promises.writeFile(filename, seed)

  return seed
}

exports.openSync = function openSync (filename) {
  let seed = null

  try {
    seed = fs.readFileSync(filename)
    if (seed.byteLength < 32) throw new Error('seed too short')
    return seed.subarray(0, 32)
  } catch {
    seed = b4a.alloc(32)
    sodium.randombytes_buf(seed)
  }

  fs.mkdirSync(path.dirname(filename), { recursive: true })
  fs.writeFileSync(filename, seed)

  return seed
}
