// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import "openzeppelin-contracts-upgradeable/contracts/access/AccessControlUpgradeable.sol";
import "openzeppelin-contracts-upgradeable/contracts/utils/PausableUpgradeable.sol";

/**
 * @title RevocationRegistry
 * @notice Hybrid revocation registry using Merkle Trees for batch updates and nullifiers for immediate revocation.
 * @dev Designed to interface with Zero-Knowledge Proof validations.
 */
contract RevocationRegistry is Initializable, AccessControlUpgradeable, PausableUpgradeable {
    
    bytes32 public constant REVOKER_ROLE = keccak256("REVOKER_ROLE");

    /**
     * @notice The public root of the off-chain Merkle tree of non-revoked (valid) credentials.
     */
    bytes32 public merkleRoot;

    /**
     * @notice Mapping to store immediate, privacy-preserving revocations (blacklist).
     * @dev Maps a credential's nullifier to a boolean indicating if it is revoked.
     */
    mapping(bytes32 => bool) public immediateRevocations;

    /**
     * @notice Emitted when the Merkle root is updated for batch changes.
     */
    event MerkleRootUpdated(bytes32 indexed oldRoot, bytes32 indexed newRoot);

    /**
     * @notice Emitted when a specific credential nullifier is immediately revoked.
     */
    event CredentialRevokedImmediately(bytes32 indexed nullifier);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the contract with default admin.
     */
    function initialize() public initializer {
        __AccessControl_init();
        __Pausable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
     * @notice Updates the Merkle root representing the valid credentials set, to perform a batch revocation. 
     * @param _newRoot The 32-byte root of the updated Merkle tree.
     */
    function updateMerkleRoot(bytes32 _newRoot) external onlyRole(REVOKER_ROLE) whenNotPaused {
        require(_newRoot != bytes32(0), "Invalid Merkle root");
        
        bytes32 oldRoot = merkleRoot;
        merkleRoot = _newRoot;
        
        emit MerkleRootUpdated(oldRoot, _newRoot);
    }

    /**
     * @notice Immediately revokes a credential via its nullifier, preserving privacy.
     * @param _nullifier The ZK-generated nullifier hash of the credential.
     */
    function revokeImmediately(bytes32 _nullifier) external onlyRole(REVOKER_ROLE) whenNotPaused {
        require(_nullifier != bytes32(0), "Invalid nullifier");
        require(!immediateRevocations[_nullifier], "Nullifier already revoked");

        immediateRevocations[_nullifier] = true;

        emit CredentialRevokedImmediately(_nullifier);
    }

    /**
     * @notice Helper function to check if a specific nullifier has been immediately revoked.
     * @param _nullifier The nullifier to check.
     * @return bool True if the nullifier is explicitly blacklisted.
     */
    function isRevoked(bytes32 _nullifier) external view returns (bool) {
        return immediateRevocations[_nullifier];
    }

    /**
     * @notice Pauses the registry, preventing new revocations or root updates.
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpauses the registry.
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}