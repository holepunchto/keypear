const test = require('brittle')
const Keychain = require('../../')

test('benchmark keychain.get() max', async function (t) {
  const keys = new Keychain()

  benchmark(t, 100000000, () => keys.get())
})

test('benchmark keychain.get() medium', async function (t) {
  const keys = new Keychain()

  benchmark(t, 100000, () => keys.get())
  benchmark(t, 1000000, () => keys.get())
  benchmark(t, 10000000, () => keys.get())
})

test('benchmark keychain.get() all', async function (t) {
  const keys = new Keychain()

  benchmark(t, 1, () => keys.get())
  benchmark(t, 10, () => keys.get())
  benchmark(t, 100, () => keys.get())
  benchmark(t, 1000, () => keys.get())
  benchmark(t, 10000, () => keys.get())
  benchmark(t, 100000, () => keys.get())
  benchmark(t, 1000000, () => keys.get())
  benchmark(t, 10000000, () => keys.get())
  benchmark(t, 100000000, () => keys.get())
})

test('benchmark keychain.get(name) max', async function (t) {
  const keys = new Keychain()

  benchmark(t, 100000, () => keys.get('test'))
})

test('benchmark keychain.get(name) medium', async function (t) {
  const keys = new Keychain()

  benchmark(t, 100, () => keys.get('test'))
  benchmark(t, 1000, () => keys.get('test'))
  benchmark(t, 10000, () => keys.get('test'))
})

test('benchmark keychain.get(name) all', async function (t) {
  const keys = new Keychain()

  benchmark(t, 1, () => keys.get('test'))
  benchmark(t, 10, () => keys.get('test'))
  benchmark(t, 100, () => keys.get('test'))
  benchmark(t, 1000, () => keys.get('test'))
  benchmark(t, 10000, () => keys.get('test'))
  benchmark(t, 100000, () => keys.get('test'))
})

test('benchmark keychain.sub() max', async function (t) {
  const keys = new Keychain()

  benchmark(t, 100000000, () => keys.sub())
})

test('benchmark keychain.sub() medium', async function (t) {
  const keys = new Keychain()

  benchmark(t, 100000, () => keys.sub())
  benchmark(t, 1000000, () => keys.sub())
  benchmark(t, 10000000, () => keys.sub())
})

test('benchmark keychain.sub() all', async function (t) {
  const keys = new Keychain()

  benchmark(t, 1, () => keys.sub())
  benchmark(t, 10, () => keys.sub())
  benchmark(t, 100, () => keys.sub())
  benchmark(t, 1000, () => keys.sub())
  benchmark(t, 10000, () => keys.sub())
  benchmark(t, 100000, () => keys.sub())
  benchmark(t, 1000000, () => keys.sub())
  benchmark(t, 10000000, () => keys.sub())
  benchmark(t, 100000000, () => keys.sub())
})

test('benchmark keychain.sub(name) max', async function (t) {
  const keys = new Keychain()

  benchmark(t, 100000, () => keys.sub('test'))
})

test('benchmark keychain.sub(name) medium', async function (t) {
  const keys = new Keychain()

  benchmark(t, 100, () => keys.sub('test'))
  benchmark(t, 1000, () => keys.sub('test'))
  benchmark(t, 10000, () => keys.sub('test'))
})

test('benchmark keychain.sub(name) all', async function (t) {
  const keys = new Keychain()

  benchmark(t, 1, () => keys.sub('test'))
  benchmark(t, 10, () => keys.sub('test'))
  benchmark(t, 100, () => keys.sub('test'))
  benchmark(t, 1000, () => keys.sub('test'))
  benchmark(t, 10000, () => keys.sub('test'))
  benchmark(t, 100000, () => keys.sub('test'))
})

function benchmark (t, count, fn) {
  const started = Date.now()
  for (let i = 0; i < count; i++) {
    fn()
  }
  t.comment(count.toString().length + ') ' + count + 'x = ' + (Date.now() - started) + ' ms')
}
