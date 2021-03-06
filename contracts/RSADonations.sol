pragma solidity 0.5.7;

contract RSADonations {

  struct PublicKey { // Storage for RSA public key.
    uint256 exponent;
    uint256[] modulus; // big-endian representation of public-key modulus.
    uint256 size; // Size of modulus in bits. Must be a multiple of 256.
  }

  mapping(bytes32 /* public key hash */ => PublicKey) public publicKeys;
  mapping(bytes32 /* public key hash */ => uint256) public balances;

  struct Donation {
    uint256 amount; // Total donated to this key, from this address
    uint256 recoveryDeadline;  // Unix time when this donation is recoverable
    uint256 lastUpdate;  // Unix time of when this record was last updated
  }

  mapping(address /* donor */ =>
    mapping(bytes32 /* public key hash */ => Donation)) public donations;
  mapping(bytes32 /* public key hash */ =>
    uint256 /* Unix time when funds last taken */) public lastClaims;
  // Used in challenge message, to prevent replay attacks
  mapping(bytes32 /* public key hash */ => uint256) public claimNonce;

  event NewKeyRegistered(address sender, bytes32 publicKeyHash);
  event DonationToKey(
    address sender,
    uint256 amount,
    uint256 newBalance,
    uint256 newSenderBalance, // Balance in donations[publicKeyHash][sender]
    uint256 recoveryDeadline,
    bytes32 publicKeyHash
  );
  event DonationRecovered( // Fired when donation is recovered by sender
    address sender, bytes32 publicKeyHash, uint256 amount,
    uint256 newBalance // balances[publicKeyHash]
  );
  event DonationClaimed( // Fired when donation is recovered by public key
    address to,
    address transmitter,  // msg.sender for this tx
    uint256 transmitterReward, // How much was sent to transmitter of tx.
    uint256 amount // How much was sent to `to` address
  );
  event DonationBalanceReset( // Fired when donor balance reset to zero
    address donor, bytes32 publicKeyHash);
  event BadModulus(bytes32 publicKeyHash); // Fired when bitsize doesn't match
  event DonationRecoveryTooSoon( // Fired on recovery before recoveryDeadline
    address sender, bytes32 publicKeyHash, uint256 recoveryDeadline);
  event DonationAlreadyClaimed( // Fired on recovery of donation already claimed
    address sender, bytes32 publicKeyHash, uint256 lastClaim, uint256 recoveryTime);
  event BadClaimSignature( // Fired when a claim has a bad signature
    address sender, bytes32 publicKeyHash, bytes32 signatureHash);

  address owner; // Owner of the contract

  constructor() public { owner = msg.sender; }

  function publicKeyHash(uint256[] memory _modulus, uint256 _exponent,
    uint256 _size) public pure returns (bytes32) {
    return keccak256(abi.encodePacked(_modulus, _exponent, _size));
  }

  function donateToNewPublicKey(uint256 _recoveryDeadline,
    uint256[]  memory _keyModulus, uint256 _keyExponent, uint256 _keySize) public payable {
    bytes32 keyHash = publicKeyHash(_keyModulus, _keyExponent, _keySize);
    if (_keyModulus.length * 256 != _keySize) {
      emit BadModulus(keyHash);
      return;
    }
    publicKeys[keyHash].modulus = _keyModulus;
    publicKeys[keyHash].exponent = _keyExponent;
    publicKeys[keyHash].size = _keySize;
    emit NewKeyRegistered(msg.sender, keyHash);
    donateToKnownPublicKey(_recoveryDeadline, keyHash);
  }

  function max(uint256 a, uint256 b) public pure returns(uint256) {
    return a > b ? a : b;
  }

  function donateToKnownPublicKey(uint256 _recoveryDeadline, bytes32 _keyHash)
    public payable {
    // Without this, the donation becomes unrecoverable.
    require(lastClaims[_keyHash] < now, "Must make a donation at least 1s since last claim.");
    Donation memory donation = donations[msg.sender][_keyHash];
    donation.recoveryDeadline = max(donation.recoveryDeadline,
      _recoveryDeadline); // Whichever is later
    if (lastClaims[_keyHash] > donation.lastUpdate) {
      donation.amount = msg.value;
      emit DonationBalanceReset(msg.sender, _keyHash);
    } else {
      donation.amount += msg.value;
    }
    donation.lastUpdate = now;
    donations[msg.sender][_keyHash] = donation; // Copy back to storage
    balances[_keyHash] += msg.value;
    emit DonationToKey(msg.sender, msg.value, balances[_keyHash], donation.amount,
      _recoveryDeadline, _keyHash);
  }

  function recoverDonation(bytes32 _keyHash) public {
    Donation memory donation = donations[msg.sender][_keyHash];
    require(donation.amount > 0, "Can't recover trivial donation.");
    if (donation.recoveryDeadline >= now) {  // After the recovery deadline?
      emit DonationRecoveryTooSoon(msg.sender, _keyHash, donation.recoveryDeadline);
      return;
    }
    if (donation.lastUpdate <= lastClaims[_keyHash]) { // Not already claimed?
      emit DonationAlreadyClaimed(msg.sender, _keyHash, lastClaims[_keyHash], now);
      return;
    }
    delete donations[msg.sender][_keyHash];
    emit DonationBalanceReset(msg.sender, _keyHash);
    balances[_keyHash] -= donation.amount;
    assert(balances[_keyHash] >= 0);
    emit DonationRecovered(
      msg.sender, _keyHash, donation.amount, balances[_keyHash]);
    msg.sender.transfer(donation.amount);
  }

  function resetDonationDeadline(address _from, bytes32 _keyHash) public {
    require(msg.sender == owner, "Only owner can reset deadlines");
    donations[_from][_keyHash].recoveryDeadline = 0;
  }

  function claimDonation(bytes32 _keyHash, address payable _to,
    uint256 _transmitterReward, uint256[] memory _signature) public {
    uint256 balance = balances[_keyHash];
    require(balance >= _transmitterReward, "Transmitter reward unpayable.");
    if (!verify(_keyHash, _to, _transmitterReward, _signature)) {
      emit BadClaimSignature(msg.sender, _keyHash,
        keccak256(abi.encodePacked(_signature)));
      return;
    }
    balances[_keyHash] = 0;
    lastClaims[_keyHash] = now;
    claimNonce[_keyHash] += 1;
    emit DonationClaimed(_to, msg.sender, _transmitterReward, balance);
    if (_transmitterReward > 0) { msg.sender.transfer(_transmitterReward); }
    uint256 remainder = balance - _transmitterReward;
    if (remainder > 0) { _to.transfer(remainder); }
  }

  function verify(bytes32 _keyHash, address payable _to, uint256 _transmitterReward,
    uint256[] memory _signature) public view returns (bool) {
    uint256[] memory challengeMessage = claimChallengeMessage(
      _keyHash, _to, _transmitterReward);
    uint256[] memory cipherText = encrypt(_keyHash, _signature);
    if (cipherText.length != challengeMessage.length) { return false; }
    for (uint256 i = 0; i < cipherText.length; i++) {
      if (cipherText[i] != challengeMessage[i]) {
        return false;
      }
    }
    return true;
  }

  function claimChallengeMessage(
    bytes32 _keyHash, address payable _to, uint256 _transmitterReward)
    public view returns (uint256[] memory) {
    PublicKey memory pk = publicKeys[_keyHash];
    uint256[] memory rv = new uint256[](pk.modulus.length);
    bytes32 initialHash = keccak256(abi.encodePacked(
      claimNonce[_keyHash], _to, _transmitterReward, msg.sender));
    for (uint256 i = 0; i < pk.modulus.length; i++) {
      rv[i] = uint256(keccak256(abi.encodePacked(i, initialHash)));
    }
    if (rv[0] < pk.modulus[0]) { // Try to avoid expensive unnecessary bigmodexp
      return rv;
    }
    return remainder(rv, pk.modulus);
  }

  uint256 constant WORD = 32; // Number of bytes in a 256-bit word

  /* @dev NB: This is "text-book RSA" encryption, used here only for signature
   * verification. Don't use this for serious encryption without random padding,
   * etc.
   */
  function encrypt(bytes32 _keyHash, uint256[] memory _message)
    public view returns (uint256[] memory) {
    PublicKey memory pk = publicKeys[_keyHash];
    require(_message.length <= pk.modulus.length,
      "Can't encrypt more information than the modulus.");
    return bigModExp(_message, pk.exponent, pk.modulus);
  }

  function remainder(uint256[] memory _dividend, uint256[] memory _divisor)
    public view returns(uint256[] memory) {
    return bigModExp(_dividend, 1, _divisor);
  }

  function bigModExp(uint256[] memory _base, uint256 _exponent, uint256[] memory _modulus)
    public view returns (uint256[] memory) {
    uint256 inputSize = 3 + _modulus.length + 1 + _base.length;
    uint256[] memory input = new uint256[](inputSize);
    uint256 cursor = 0;
    // We're operating in words, here, but the bigmodexp API expects bytes.
    input[cursor++] = _base.length * WORD;
    input[cursor++] = WORD;
    input[cursor++] = _modulus.length * WORD;
    for (uint256 i = 0; i < _base.length; i++) {
      input[cursor++] = _base[i];
    }
    input[cursor++] = _exponent;
    for (uint256 i = 0; i < _modulus.length; i++) {
      input[cursor++] = _modulus[i];
    }
    assert(cursor == inputSize);
    uint256 success;
    uint256 outputLength = _modulus.length; // Can't use attributes in assembly
    uint256[] memory output = new uint256[](2*outputLength); // XXX: Avoid memory corruption??
    uint256 word = WORD; // Can't use constants in assembly
    assembly {
      success := staticcall(
        not(0), // Allow arbitrary gas. XXX get this more precise
        0x05, // The bigmodexp precompiled contract address
        // address of inputs is one word past the length value
        // https://solidity.readthedocs.io/en/v0.4.24/miscellaneous.html#layout-of-state-variables-in-storage
        add(input, word),
        mul(inputSize, word), // Size of input, in bytes
        add(output, word), // Same logic as for input
        mul(outputLength, word)) // Size of output, in bytes
    }
    require(success != 0, "bigModExp call failed.");
    uint256[] memory actualOutput = new uint256[](outputLength);
    for (uint256 i = 0; i < outputLength; i++) {
      actualOutput[i] = output[i];
    }
    return actualOutput;
  }
}
