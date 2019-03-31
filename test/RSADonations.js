const bigInt = require('big-integer')
const BN = web3.utils.BN

const RSADonations = artifacts.require('RSADonations')

// 256-bit primes, via https://asecuritysite.com/encryption/random3?val=256
const hexToBN = s => new BN(s, 16)
const p = hexToBN('72964a78c96299f5a606066de508495f922f296539090e359a51150185651291')
const q = hexToBN('81bf945d9b7e36061ca12e9fa7f197c10a7ae7520f109dd9cfdc67821e2b6e37')

const rawModulus = p.mul(q)
const zeroPadTo256Bits = s => '0'.repeat((65536 - s.length) % 64) + s
const bNToUint256Array = n => zeroPadTo256Bits(n.toString(16)).match(/.{1,64}/g)
  .map(s => new BN(s, 16))
const uint256ArrayToBN = a => new BN(
  a.map(n => zeroPadTo256Bits(n.toString(16))).join(''), 16)
const modulus = bNToUint256Array(rawModulus)

const keySize = 256 * modulus.length
const exponent = new BN(65537)
const bNToBI = n => bigInt(n.toString(16), 16)
const bIToBN = n => new BN(n.toString(16), 16)

// Since (ℤ/pqℤ)*≅(Z/(p-1)ℤ)×(Z/(q-1)ℤ), order of every element divides this.
const totient = bIToBN(bigInt.lcm(bNToBI(p).prev(), bNToBI(q).prev()))
// invm does not check this!!
assert(!totient.mod(exponent).eq(new BN(0)), 'exponent must not divide totient')
const secretKey = exponent.invm(totient)
assert(secretKey.mul(exponent).umod(totient).eq(new BN(1)))

const rawMessage = [ // A signature of a challengeMessage
  '4fa0331b7ed0a8e78cd92631e9d459ab3e89aaff38da30298a4a8f9dd9566f4',
  '2cf1e88dfae7e28dd2006f9d26396c0b2a30294d0dc413dccb1f55347d3e2b69'
]

const messageUint256Array = rawMessage.map(s => new BN(s, 16))
const fullMessage = uint256ArrayToBN(messageUint256Array)
assert(uint256ArrayToBN(bNToUint256Array(fullMessage)).eq(fullMessage))

const sleep = (milliseconds) => {
  return new Promise(resolve => setTimeout(resolve, milliseconds))
}

// Corresponds to RSADonations.sol#publicKeyHash
const keyHash = (m, e, s) => web3.utils.soliditySha3(...[...m, e, s])

const jsHash = keyHash(modulus, exponent, keySize)

// BN doesn't provide an obvious, convenient way to do this
const bigModExp = (b, e, m) => {
  const [ bIB, bIE, bIM ] = [b, e, m].map(bNToBI)
  return bIToBN(bIB.modPow(bIE, bIM))
}

contract('RSADonations', async accounts => {
  const [amount, deadline] = [ 1, (+new Date()) + 3600 ]
  let c
  beforeEach(async () => { c = await RSADonations.deployed() })
  it('Accepts a donation to a new public key, and records it',
    async () => {
      const tx = await c.donateToNewPublicKey(
        deadline, modulus, exponent, keySize, { value: amount })
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
      deadline, modulus, exponent, keySize, { value: amount })
    await c.donateToKnownPublicKey(deadline, jsHash, { value: amount })
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
    let expectedMessage = []
    for (let i = 0; i < msg.length; i++) {
      const hash = web3.utils.soliditySha3(i, initialHash)
      assert.equal(hash.slice(0, 2), '0x')
      expectedMessage.push(hash.slice(2))
      assert.equal(expectedMessage[expectedMessage.length - 1].length, 64)
    }
    expectedMessage = bNToUint256Array(uint256ArrayToBN(expectedMessage).mod(rawModulus))
    assert(uint256ArrayToBN(expectedMessage).eq(uint256ArrayToBN(msg)),
      'Claim msg should match JS construction')
  })
  it('Knows a good signature from bad', async () => {
    const keyExponent = (await c.publicKeys.call(jsHash)).exponent
    assert(keyExponent.eq(exponent), 'earlier tests should have registered key')
    const [ to, txer, txReward ] = [ accounts[1], accounts[2], 1 ]
    const callOpts = { from: txer }
    const msg = await c.claimChallengeMessage(jsHash, to, txReward, callOpts)
    const fullmsg = uint256ArrayToBN(msg).mod(rawModulus)
    const sigAsNum = bigModExp(fullmsg, secretKey, rawModulus)
    assert(fullmsg.eq(bigModExp(sigAsNum, exponent, rawModulus)),
      'signature should re-encrypt to message')
    const signature = bNToUint256Array(sigAsNum)
    const reencryption = await c.encrypt(jsHash, signature)
    assert(uint256ArrayToBN(reencryption).eq(uint256ArrayToBN(msg)),
      'Signature should encrypt to msg')
    assert(await c.verify(jsHash, to, txReward, signature, callOpts),
      'Contract should verify a good signature')
    const badSignature = signature.slice()
    badSignature[0] = signature[0].add(new BN(1)) // iadd is not working?
    assert(!signature[0].eq(badSignature[0]), 'Signature should be corrupted')
    assert(!(await c.verify(jsHash, to, txReward, badSignature, callOpts)),
      'Positive control failed')
  })
  it('Allows a valid donation claim, and accounts for it', async () => {
    const keyExponent = (await c.publicKeys.call(jsHash)).exponent
    assert(keyExponent.eq(exponent), 'earlier tests should have registered key')
    const [ _to, txer, txReward ] = [ accounts[1], accounts[2], new BN(1) ]
    const initialToBalance = new BN(await web3.eth.getBalance(_to), 10)
    const initialNonce = await c.claimNonce.call(jsHash)
    const initialLastClaim = await c.lastClaims.call(jsHash)
    const callOpts = { from: txer }
    const msg = await c.claimChallengeMessage(jsHash, _to, txReward, callOpts)
    const fullmsg = uint256ArrayToBN(msg).mod(rawModulus)
    const signature = bNToUint256Array(bigModExp(fullmsg, secretKey, rawModulus))
    const tx = await c.claimDonation(jsHash, _to, 1, signature, callOpts)
    const claimLog = tx.logs[0]
    assert.equal(claimLog.event, 'DonationClaimed')
    const { to, transmitter, transmitterReward, amount } = claimLog.args
    assert.equal(to, _to)
    assert.equal(transmitter, txer)
    assert(transmitterReward.eq(txReward))
    const newBalance = new BN(await web3.eth.getBalance(to), 10)
    const balanceIncrease = newBalance.sub(initialToBalance)
    assert(balanceIncrease.eq(amount.sub(txReward)),
      'Sent value should match balance - txReward')
    assert((new BN(1)).eq((await c.claimNonce.call(jsHash)).sub(initialNonce)),
      'Nonce should be incremented')
    assert(initialLastClaim.lt(await c.lastClaims.call(jsHash)),
      'lastClaim field should be updated')
    assert((new BN(0)).eq(await c.balances.call(jsHash)), 'Balance should be zeroed out')
  })
  it('Refuses recovery on a donation which has already been claimed', async () => {
    const keyExponent = (await c.publicKeys.call(jsHash)).exponent
    assert(keyExponent.eq(exponent), 'earlier tests should have registered key')
    assert((new BN(0)).eq(await c.balances.call(jsHash)),
      'Claim should have been made by previous test')
    await c.resetDonationDeadline(accounts[0], jsHash)
    const tx = await c.recoverDonation(jsHash)
    assert.equal(tx.logs[0].event, 'DonationAlreadyClaimed')
  })
  it('Allows recovery on an unclaimed donation where the deadline has expired', async () => {
    await sleep(1500) // Make sure at least a second has passed since last claim, before donating
    await c.donateToKnownPublicKey(0, jsHash, { value: amount })
    await c.resetDonationDeadline(accounts[0], jsHash)
    const tx = await c.recoverDonation(jsHash)
    assert.equal(tx.logs[1].event, 'DonationRecovered')
  })
})
