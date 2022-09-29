const KeyChain = require('./')

const keys = new KeyChain()

const sub1 = keys.sub('a').sub('b')
const sub2 = keys.sub('b').sub('a')

console.log('sub 1:', sub1)
console.log('sub 2:', sub2)

const c = keys.checkout(sub2.head.publicKey)
console.log('checkout of sub 2:', c)
