// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./ICoreIdentityCredential.sol";
import "openzeppelin-contracts-upgradeable/contracts/access/AccessControlUpgradeable.sol";
import "openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import "openzeppelin-contracts-upgradeable/contracts/utils/PausableUpgradeable.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol";

/**
 * @title CoreIdentityCredential
 * @notice Core contract for issuing and managing digital identity credentials.
 * @dev Implements role-based access control and stores credential state on-chain.
 * @dev Upgradable contract
 */
contract CoreIdentityCredential is Initializable, AccessControlUpgradeable, PausableUpgradeable, ICoreIdentityCredential {
    /**
     * @notice Maps a credential ID to its corresponding Credential struct.
     */
    mapping(bytes32 => Credential) public credentials;


    /**
     * @dev Role identifier for the authority allowed to issue credentials.
     */
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");

    /**
     * @dev Role identifier for entities authorized to verify credentials.
     */
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    /**
     * @dev Role identifier for citizens holding the credentials.
     */
    bytes32 public constant CITIZEN_ROLE = keccak256("CITIZEN_ROLE");


    /**
     * @notice Emitted when a new credential is issued and registered on chain.
     * @param credentialId The unique identifier of the issued credential.
     * @param citizenHash Zero-Knowledge commitment representing the citizen's identity.
     * @param timestamp The exact time (in Unix epoch seconds) when the credential was issued.
     */
    event CredentialIssued(bytes32 indexed credentialId, bytes32 citizenHash, uint256 timestamp);

    /**
     * @notice Emitted when an existing credential is invalidated.
     * @param credentialId The unique identifier of the revoked credential.
     * @param timestamp The exact time (in Unix epoch seconds) when the credential was revoked.
     */
    event CredentialRevoked(bytes32 indexed credentialId, uint256 timestamp);

    /**
     * @notice Emitted when an existing credential is checked by an authorized verifier.
     * @param credentialId The unique identifier of the credential to verify.
     * @param isValid Boolean indicating whether the verification was successful.
     */
    event CredentialVerified(bytes32 indexed credentialId, bool isValid);


    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the contract and sets the deployer as the default admin (not as the issuer).
     * @dev The default admin can later grant or revoke ISSUER, VERIFIER, and CITIZEN roles.
     */
    function initialize() public initializer {
        __AccessControl_init();
        __Pausable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
     * @notice Issues a new identity credential.
     * @dev Only callable by accounts with the ISSUER_ROLE. Reverts if the credential ID already exists.
     * @param _credentialId The unique identifier of the credential to issue.
     * @param _citizenHash The ZK commitment of the citizen.
     * @param _issuerSignature The digital signature of the issuing authority.
     * @param _expirationTimestamp The Unix timestamp when the credential will expire.
     * @param _credentialType The category of the credential.
     */
    function issueCredential(
        bytes32 _credentialId,
        bytes32 _citizenHash,
        bytes calldata _issuerSignature,
        uint64 _expirationTimestamp,
        CredentialType _credentialType
    ) external onlyRole(ISSUER_ROLE) whenNotPaused {
        require(credentials[_credentialId].credentialId == bytes32(0), "Credential already exists");
        require(_expirationTimestamp > block.timestamp, "Invalid expiration date");

        credentials[_credentialId] = Credential({
            credentialId: _credentialId,
            citizenHash: _citizenHash,
            issuerSignature: _issuerSignature,
            issuanceTimestamp: uint64(block.timestamp),
            expirationTimestamp: _expirationTimestamp,
            credentialType: _credentialType,
            status: CredentialStatus.Active
        });

        emit CredentialIssued(_credentialId, _citizenHash, block.timestamp);
    }

    /**
     * @notice Revokes an active credential.
     * @dev Can be called by an authorized issuer or by the citizen owning the credential.
     * If called by the citizen, they must provide their secret salt to prove ownership of the citizenHash.
     * Issuers can simply pass a zero bytes32 value for the secret.
     * @dev The hash must be computed strictly as `keccak256(abi.encodePacked(citizenAddress, citizenSecret))`
     * @param _credentialId The unique identifier of the credential to revoke.
     * @param _citizenSecret The secret salt used to generate the citizenHash (required only for citizens).
     */
    function revokeCredential(bytes32 _credentialId, bytes32 _citizenSecret) external whenNotPaused {
        require(credentials[_credentialId].credentialId != bytes32(0), "Credential not found");
        require(credentials[_credentialId].status == CredentialStatus.Active, "Credential not active");

        bool isIssuer = hasRole(ISSUER_ROLE, msg.sender);
        if (!isIssuer) {
            bytes32 expectedHash = keccak256(abi.encodePacked(msg.sender, _citizenSecret));
            require(credentials[_credentialId].citizenHash == expectedHash, "Caller is not the owner");
        }

        credentials[_credentialId].status = CredentialStatus.Revoked;
        emit CredentialRevoked(_credentialId, block.timestamp);
    }

    /**
     * @notice Verifies the cryptographic signature of the credential's issuer.
     * @dev Reconstructs the signed data hash and uses ECDSA to recover the signer's address.
     * It assumes the issuer signed the keccak256 hash of the credentialId and the citizenHash.
     * @dev If the contract is in a paused state, this function can still be called, since verification
     * cannot compromise the state as it is an "append" only function.
     * @param _credentialId The unique identifier of the credential to verify.
     * @return bool True if the signature is valid and belongs to an authorized issuer, false otherwise.
     */
    function verifyCredentialSignature(bytes32 _credentialId) external returns (bool) {
        Credential memory cred = credentials[_credentialId];
        require(cred.credentialId != bytes32(0), "Credential not found");

        bytes32 dataHash = keccak256(abi.encodePacked(cred.credentialId, cred.citizenHash));
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(dataHash);
        address signer = ECDSA.recover(ethSignedMessageHash, cred.issuerSignature);
        bool valid = hasRole(ISSUER_ROLE, signer);

        emit CredentialVerified(_credentialId, valid);
        return valid;
    }

    /**
     * @notice Puts the contract in a paused state, stopping credential issuance and revocation.
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpauses the contract.
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}