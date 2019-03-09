const RSADonations = artifacts.require("RSADonations")

module.exports = function(deployer) {
    deployer.deploy(RSADonations);
};
