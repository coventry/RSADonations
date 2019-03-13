const bigInt = require('big-integer')
const BN = web3.utils.BN

const RSADonations = artifacts.require('RSADonations')

// 256-bit primes, via https://asecuritysite.com/encryption/random3?val=256
const hexToBN = s => new BN(s, 16)
const p = hexToBN('72964a78c96299f5a606066de508495f922f296539090e359a51150185651291')
const q = hexToBN('81bf945d9b7e36061ca12e9fa7f197c10a7ae7520f109dd9cfdc67821e2b6e37')

const rawModulus = p.mul(q)
const modulus = rawModulus.toString(16).match(/.{1,64}/g).map( // As uint256[]
  s => new BN(s, 16)
)
const keySize = 256 * modulus.length
const exponent = new BN(47)
const bNToBI = n => bigInt(n.toString(16), 16)
const bIToBN = n => new BN(n.toString(16), 16)

// Since (ℤ/pqℤ)*≅(Z/(p-1)ℤ)×(Z/(q-1)ℤ), order of every element divides this.
const totient = bIToBN(bigInt.lcm(bNToBI(p).prev(), bNToBI(q).prev()))
const secretKey = exponent.invm(totient)

const rawMessage = [ // random 512-bit RSA modulus as uint256[]. for plaintext
  '102bf2e277b8415469cc0009c30cdfd90461c16d4c4722afbc8ddcb9b0527637',
  '4fbea788819342f733d164d32729993d4bef8f6a388abfa2ace4081bfa3609d1'
]

const messageUint256Array = rawMessage.map(s => new BN(s, 16))
const fullMessage = new BN(rawMessage.join(''), 16)

// Corresponds to RSADonations.sol#publicKeyHash
const keyHash = (m, e, s) => web3.utils.soliditySha3(...[...m, e, s])

const jsHash = keyHash(modulus, exponent, keySize)

// BN doesn't provide an obvious, convenient way to do this
const bigModExp = (b, e, m) => {
  const bIB = bigInt(b.toString(16), 16) // BN => bigInt via string representation
  const bIE = bigInt(e.toString(16), 16)
  const bIM = bigInt(m.toString(16), 16)
  const modPow = bIB.modPow(bIE, bIM)
  return new BN(modPow.toString(16), 16) // bigInt => BN
}

contract('RSADonations', async accounts => {
  const [amount, deadline] = [ 1, (+new Date()) + 3600 ]
  let c
  beforeEach(async () => { c = await RSADonations.deployed() })
  it('Accepts a donation to a new public key, and records it',
    async () => {
      const tx = await c.donateToNewPublicKey(
        amount, deadline, modulus, exponent, keySize)
      const [ rLog, pLog ] = tx.logs
      assert.equal(rLog.event, 'NewKeyRegistered')
      assert.equal(pLog.event, 'DonationToKey')
      var { sender, publicKeyHash } = rLog.args
      assert.equal(sender, accounts[0])
      assert.equal(publicKeyHash, jsHash)
      var { newBalance, newSenderBalance, recoveryDeadline } = pLog.args
      assert.equal(sender, accounts[0])
      assert.equal(publicKeyHash, jsHash)
      assert.equal(newBalance, amount)
      assert.equal(newSenderBalance, amount)
      assert.equal(recoveryDeadline, deadline)
    })
  it('Updates both the donation and the balance amounts, on multiple ' +
     'same-source donations', async () => {
    const cAmount = (await c.balances.call(jsHash)).toNumber()
    const dAmount = (await c.donations.call(accounts[0], jsHash)).amount.toNumber()
    await c.donateToNewPublicKey(
      amount, deadline, modulus, exponent, keySize)
    await c.donateToNewPublicKey(
      amount, deadline, modulus, exponent, keySize)
    assert.equal(await c.balances.call(jsHash), cAmount + 2 * amount)
    assert.equal((await c.donations.call(accounts[0], jsHash)).amount,
      dAmount + amount * 2)
  })
  it('Does not allow recovery of a donation before the deadline', async () => {
    const initialBalance = parseInt(await web3.eth.getBalance(accounts[0]))
    const cAmount = (await c.balances.call(jsHash)).toNumber()
    const dAmount = (await c.donations.call(accounts[0], jsHash)).amount.toNumber()
    const dDeadline = (await c.donations.call(accounts[0], jsHash)).recoveryDeadline.toNumber()
    assert.isAbove(dAmount, 0, 'earlier tests should have deposited value')
    assert.isAbove(dDeadline, (+new Date()) + 10, 'Deadline should be in future')
    const tx = await c.recoverDonation(jsHash)
    assert.equal(tx.logs[0].event, 'DonationRecoveryTooSoon')
    assert.equal((await c.donations.call(accounts[0], jsHash)).amount.toNumber(),
      dAmount, 'balances should be unchanged')
    assert.equal((await c.balances.call(jsHash)).toNumber(), cAmount,
      'balances should be unchanged')
    assert.isBelow(parseInt(await web3.eth.getBalance(accounts[0])),
      initialBalance - tx.receipt.gasUsed, // XXX: Why not exact??
      'there should be no profit from this misbehavior')
  })
  it('Encrypts, given a key and a message', async () => {
    const keyExponent = (await c.publicKeys.call(jsHash)).exponent
    assert(keyExponent.eq(exponent), 'earlier tests should have registered key')
    // message ** exponent % modulus
    const expectedVal = bigModExp(fullMessage, exponent, rawModulus).toString(16)
    const actual = await c.encrypt.call(jsHash, messageUint256Array)
    assert.equal(actual.map(n => n.toString(16)).join(''), expectedVal)
  })
  it('Produces the right challenge message', async () => {
    const [ to, txer, txReward ] = [ accounts[1], accounts[2], 1 ]
    const msg = await c.claimChallengeMessage(jsHash, to, txReward, { from: txer })
    const nonce = (await c.claimNonce.call(jsHash)).toNumber()
    const initialHash = web3.utils.soliditySha3(nonce, to, txReward, txer)
    const expectedMessage = []
    for (let i = 0; i < msg.length; i++) {
      const hash = web3.utils.soliditySha3(i, initialHash)
      assert.equal(hash.slice(0, 2), '0x')
      expectedMessage.push(hash.slice(2))
    }
    assert.equal(msg.map(x => x.toString(16)).join(''),
      expectedMessage.join(''))
  })
  it('Knows a good signature', async () => {
    const keyExponent = (await c.publicKeys.call(jsHash)).exponent
    assert(keyExponent.eq(exponent), 'earlier tests should have registered key')
    const [ to, txer, txReward ] = [ accounts[1], accounts[2], 1 ]
    const callOpts = { from: txer }
    const msg = await c.claimChallengeMessage(jsHash, to, txReward, callOpts)
    const fullmsg = new BN(msg.map(n => n.toString(16)).join(''), 16).mod(rawModulus)
    console.log('exponent', exponent)
    console.log('rawModulus', rawModulus)
    const decrypt = bigModExp(fullmsg, secretKey, rawModulus)
    console.log('decrypt', decrypt)
    assert.equal(bigModExp(decrypt, exponent, rawModulus).toString(16),
      fullmsg.toString(16))
  })
})
