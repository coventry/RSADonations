const RSADonations = artifacts.require("RSADonations")

// Corresponds to RSADonations.sol#publicKeyHash
const keyHash = (m, e, s) => web3.utils.soliditySha3(...[...m, e, s])

contract("RSADonations", async accounts => {
  const [amount, deadline, modulus, exponent, keySize] = [
    1, (+new Date()) + 3600, [15], 4, 256
  ]
  const jsHash = keyHash(modulus, exponent, keySize)
  let c
  beforeEach(async () => { c = await RSADonations.deployed() })
  it("Accepts a donation to a new public key, and records it",
     async () => {
       const tx = await c.donateToNewPublicKey(
         amount, deadline, modulus, exponent, keySize)
       const [ rLog, pLog ] = tx.logs
       assert.equal(rLog.event, "NewKeyRegistered")
       assert.equal(pLog.event, "DonationToKey")
       var { sender, publicKeyHash } = rLog.args
       assert.equal(sender, accounts[0])
       assert.equal(publicKeyHash, jsHash)
       var { sender, newBalance, newSenderBalance, recoveryDeadline, publicKeyHash } = pLog.args
       assert.equal(sender, accounts[0])
       assert.equal(publicKeyHash, jsHash)
       assert.equal(newBalance, amount)
       assert.equal(newSenderBalance, amount)
       assert.equal(recoveryDeadline, deadline)
     })
  it("Updates both the donation and the balance amounts, on multiple " +
     "same-source donations", async () => {
       const cAmount = (await c.balances.call(jsHash)).toNumber()
       const dAmount = (await c.donations.call(accounts[0], jsHash)).amount.toNumber()
       const tx = await c.donateToNewPublicKey(
         amount, deadline, modulus, exponent, keySize)
       const ntx = await c.donateToNewPublicKey(
         amount, deadline, modulus, exponent, keySize)
       assert.equal(await c.balances.call(jsHash), cAmount + 2 * amount)
       assert.equal((await c.donations.call(accounts[0], jsHash)).amount,
                    dAmount + amount * 2)
     })
  it("Does not allow recovery of a donation before the deadline", async () => {
    const initialBalance = parseInt(await web3.eth.getBalance(accounts[0]))
    const cAmount = (await c.balances.call(jsHash)).toNumber()
    const dAmount = (await c.donations.call(accounts[0], jsHash)).amount.toNumber()
    const dDeadline = (await c.donations.call(accounts[0], jsHash)).recoveryDeadline.toNumber()
    assert.isAbove(dAmount, 0, "earlier tests should have deposited value")
    assert.isAbove(dDeadline, (+new Date()) + 10, "Deadline should be in future")
    const tx = await c.recoverDonation(jsHash)
    assert.equal(tx.logs[0].event, "DonationRecoveryTooSoon")
    assert.equal((await c.donations.call(accounts[0], jsHash)).amount.toNumber(),
                 dAmount, "balances should be unchanged")
    assert.equal((await c.balances.call(jsHash)).toNumber(), cAmount,
                 "balances should be unchanged")
    assert.isBelow(parseInt(await web3.eth.getBalance(accounts[0])),
                   initialBalance - tx.receipt.gasUsed, // XXX: Why not exact??
                   "there should be no profit from this misbehavior")
  })
  it("Encrypts, given a key and a message", async () => {
    keyExponent = (await c.publicKeys.call(jsHash)).exponent.toNumber()
    assert.equal(keyExponent, exponent, "earlier tests should have registered key")
    const message = 3
    assert.equal((await c.encrypt.call(jsHash, [message])).map(x => x.toNumber()),
                 [(message ** exponent) % modulus])
  })
})
