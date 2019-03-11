const bigInt = require('big-integer')
const BN = web3.utils.BN

const RSADonations = artifacts.require('RSADonations')

// primes, via https://2ton.com.au/getprimes/random/2048
const p = new BN(
  '982a6f23c68382a351119d60a62133e42dde31676b3aab3c6b5dbf33ada2981d' +
  '78108bd90b5dafe73f0cbb93040d1ec38ec59cc8ddb39595c9ce7490ae732a74' +
  '6b621d45edadca0a9431e3c82b8c86b9b7e5b789cd5c67e57fbcd998b6f9209c' +
  '84e8ab812389a053740dcd1f3744ad4a43fe66549704356296d2bd0074a37121' +
  '88089046e25dce0d08f9bd205baee6c0373160b92b0dfacde386df98edc0f9cb' +
  '6c9c716416d5120386a09bf2769331ca885ed127833ddac918574644af953467' +
  'e2226688cdb7e22410db6a1f2cfcf8c7078ac4168ef3dd44ac5f6a73a66f3745' +
  '113ad55017b3bf5b28b0f1f79d5b88d71b7f4cbe4d75d19825b17db7071b2103', 16)

const q = new BN(
  '4c153791e341c151a888ceb0531099f216ef18b3b59d559e35aedf99d6d14c0e' +
  'bc0845ec85aed7f39f865dc982068f61c762ce646ed9cacae4e73a485739953a' +
  '35b10ea2f6d6e5054a18f1e415c6435cdbf2dbc4e6ae33f2bfde6ccc5b7c904e' +
  '427455c091c4d029ba06e68f9ba256a521ff332a4b821ab14b695e803a51b890' +
  'c4044823712ee706847cde902dd773601b98b05c9586fd66f1c36fcc76e07ce5' +
  'b64e38b20b6a8901c3504df93b4998e5442f6893c19eed648c2ba32257ca9a33' +
  'f111334466dbf112086db50f967e7c6383c5620b4779eea2562fb539d3379ba2' +
  '889d6aa80bd9dfad945878fbceadc46b8dbfa65f26bae8cc12d8bedb838d9081', 16)

const rawModulus = p.mul(q)
const modulus = rawModulus.toString(16).match(/.{1,64}/g).map( // As uint256[]
  s => new BN(s, 16)
)
const keySize = 256 * modulus.length
const exponent = new BN(3)
const bNToBI = n => bigInt(n.toString(16), 16)
const bIToBN = n => new BN(n.toString(16), 16)

// Since (ℤ/pqℤ)*≅(Z/(p-1)ℤ)×(Z/(q-1)ℤ), order of every element divides this.
const totient = bIToBN(bigInt.lcm(bNToBI(p).prev(), bNToBI(q).prev()))
const secretKey = exponent.invm(totient)

const rawMessage = [ // Another random RSA modulus, used here as just a plaintext
  'ec2a291784455deb98050c1f7ca2dea1d59acc8f4125eedfc01354f3c5afe2ac',
  'c312bfd5fb6cac4b29afa1cf8f457498c738554e6f9a3852324b3991db266aad',
  'b0502f6087c6709985be338516412737f9661def0368cbc75ef8fa6f06594c1c',
  '4f4f355b572e07a0fd227be0bb6f8e02adfb1c46ce6634280686e32169e291af',
  '281cae1853d02a0f64e028d71a681aa864bf21ea55e80b4f6dac985c843e6769',
  '6724f1f5029096a36ff7c0e94b56a098114f7d8c2d68da07a012d09f6680ace3',
  '78ac902c9efc8813062ed9871dc7de55d7d6947f7efb5907abefa863709e8065',
  '7ccd1784171dd20a4af208e22b823955526b8363ed5e18c17b0db510d076fa9f',
  '7615148bc222aef5cc02860fbe516f50eacd6647a092f76fe009aa79e2d7f156',
  '61895feafdb6562594d7d0e7c7a2ba4c639c2aa737cd1c2919259cc8ed933556',
  'd82817b043e3384cc2df19c28b20939bfcb30ef781b465e3af7c7d37832ca60e',
  '27a79aadab9703d07e913df05db7c70156fd8e2367331a1403437190b4f148d7',
  '940e570c29e81507b270146b8d340d54325f90f52af405a7b6d64c2e421f33b4',
  'b39278fa81484b51b7fbe074a5ab504c08a7bec616b46d03d009684fb3405671',
  'bc5648164f7e440983176cc38ee3ef2aebeb4a3fbf7dac83d5f7d431b84f4032',
  'be668bc20b8ee9052579047115c11caaa935c1b1f6af0c60bd86da88683b7d4f'
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
    assert.equal(keyExponent, exponent, 'earlier tests should have regi&?stered key')
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
    assert.equal(keyExponent, exponent, 'earlier tests should have registered key')
    const [ to, txer, txReward ] = [ accounts[1], accounts[2], 1 ]
    const msg = await c.claimChallengeMessage(jsHash, to, txReward, { from: txer })
    const fullmsg = new BN(msg.map(n => n.toString(16)).join(''), 16)
    console.log('exponent', exponent)
    console.log('rawModulus', rawModulus)
    const decrypt = bigModExp(fullmsg, secretKey, rawModulus)
    console.log('decrypt', decrypt)
    assert.equal(bigModExp(decrypt, exponent, rawModulus).toString(16),
      fullmsg.toString(16))
  })
})
