pragma solidity 0.5.2;

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
    address sender, bytes32 publicKeyHash, uint256 lastClaim);
  event BadClaimSignature( // Fired when a claim has a bad signature
    address sender, bytes32 publicKeyHash, bytes32 signatureHash);

  function publicKeyHash(uint256[] memory _modulus, uint256 _exponent,
    uint256 _size) public pure returns (bytes32) {
    return keccak256(abi.encodePacked(_modulus, _exponent, _size));
  }

  function donateToNewPublicKey(
    uint256 _amount, uint256 _recoveryDeadline, uint256[]  memory _keyModulus,
    uint256 _keyExponent, uint256 _keySize) public {
    bytes32 keyHash = publicKeyHash(_keyModulus, _keyExponent, _keySize);
    if (_keyModulus.length * 256 != _keySize) {
      emit BadModulus(keyHash);
      return;
    }
    publicKeys[keyHash].modulus = _keyModulus;
    publicKeys[keyHash].exponent = _keyExponent;
    publicKeys[keyHash].size = _keySize;
    emit NewKeyRegistered(msg.sender, keyHash);
    donateToKnownPublicKey(_amount, _recoveryDeadline, keyHash);
  }

  function max(uint256 a, uint256 b) public pure returns(uint256) {
    return a > b ? a : b;
  }

  function donateToKnownPublicKey(
    uint256 _amount, uint256 _recoveryDeadline, bytes32 _keyHash) public {
    Donation memory donation = donations[msg.sender][_keyHash];
    donation.recoveryDeadline = max(donation.recoveryDeadline,
      _recoveryDeadline); // Whichever is later
    if (lastClaims[_keyHash] > donation.lastUpdate) {
      donation.amount = _amount;
      emit DonationBalanceReset(msg.sender, _keyHash);
    } else {
      donation.amount += _amount;
    }
    donation.lastUpdate = now;
    donations[msg.sender][_keyHash] = donation; // Copy back to storage
    balances[_keyHash] += _amount;
    emit DonationToKey(msg.sender, _amount, balances[_keyHash], donation.amount,
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
      emit DonationAlreadyClaimed(msg.sender, _keyHash, lastClaims[_keyHash]);
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
    msg.sender.transfer(_transmitterReward);
    _to.transfer(balance - _transmitterReward);
  }

  function verify(bytes32 _keyHash, address payable _to, uint256 _transmitterReward,
    uint256[] memory _signature) public view returns (bool) {
    uint256[] memory challengeMessage = claimChallengeMessage(
      _keyHash, _to, _transmitterReward);
    uint256[] memory cipherText; encrypt(_keyHash, challengeMessage);
    for (uint256 i = 0; i < publicKeys[_keyHash].modulus.length; i++) {
      if (cipherText[i] != _signature[i]) {
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
    return rv;
  }

  uint256 constant WORD = 32; // Number of bytes in a 256-bit word

  // NB: This is "text-book RSA" encryption, used here only for signature
  // verification. Don't use this for serious encryption without random padding,
  // etc.
  function encrypt(bytes32 _keyHash, uint256[] memory _message)
    public view returns (uint256[] memory) {
    PublicKey memory pk = publicKeys[_keyHash];
    require(_message.length <= pk.modulus.length,
      "Can't encrypt more information than the modulus.");
    uint256 inputSize = 3 + pk.modulus.length + 1 + _message.length;
    uint256[] memory input = new uint256[](inputSize);
    uint256 cursor = 0;
    // We're operating in words, here, but the bigmodexp API expects bytes.
    input[cursor++] = _message.length * WORD;
    input[cursor++] = WORD;
    input[cursor++] = pk.modulus.length * WORD;
    for (uint256 i = 0; i < _message.length; i++) {
      input[cursor++] = _message[i];
    }
    input[cursor++] = pk.exponent;
    for (uint256 i = 0; i < pk.modulus.length; i++) {
      input[cursor++] = pk.modulus[i];
    }
    assert(cursor == inputSize);
    uint256 success;
    uint256 cipherTextLength = pk.modulus.length;
    uint256[] memory cipherText = new uint256[](cipherTextLength);
    uint256 word = WORD; // Can't use constants in assembly
    assembly {
      success := staticcall(
        not(0), // Allow arbitrary gas. XXX get this more precise
        0x05, // The bigmodexp precompiled contract address
        // address of inputs is one word past the length value
        // https://solidity.readthedocs.io/en/v0.4.24/miscellaneous.html#layout-of-state-variables-in-storage
        add(input, word), mul(inputSize, word),
        add(cipherText, word), // Same logic as for input
        mul(cipherTextLength, word))
    }
    require(success != 0, "bigModExp call failed.");
    return cipherText;
  }
}
