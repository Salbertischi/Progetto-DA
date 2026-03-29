// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;


/**
 * @title ICoreIdentityCredential
 * @dev Interface for the core identity credential contract
 */
interface ICoreIdentityCredential {
    /**
     * @notice Represents the current lifecycle state of a credential.
     */
    enum CredentialStatus { Active, Revoked, Expired }

    /**
     * @notice Defines the allowed categories for an identity credential.
     * @dev Implemented as an enum instead of a string to significantly reduce gas costs 
     * during comparisons, ensure strict type safety at compile time and optimize on-chain storage.
     */
    enum CredentialType { Citizenship, AgeVerification, Residency}

    /**
     * @notice Structure defining a national identity credential.
     * @dev Notice that the document suggested using a string for the credential type, but an enum is used for gas optimization and type safety.
     * @dev The hash must be computed strictly as keccak256(abi.encodePacked(citizenAddress, citizenSecret)).
     * @dev uint64 for timestamp to optimize gas costs (storage writing cost).
     * The last 4 members (the two timestamps, credential type and status) should be packed in only 32 bytes.
     * @param credentialId Uniqe identifier for the credential.
     * @param citizenHash Zero-knowledge commitment to the citizen's identity.
     * @param issuerSignature Digital signature provided by the issuer.
     * @param issuanceTimestamp The exact time (in Unix epoch seconds) when the credential was issued.
     * @param expirationTimestamp Unix timestamp of when the credential expires.
     * @param credentialType Type of the credential. 
     * @param status Current status of the credential.
     */
    struct Credential {
        bytes32 credentialId;
        bytes32 citizenHash;
        bytes issuerSignature; 
        uint64 issuanceTimestamp; 
        uint64 expirationTimestamp; 
        CredentialType credentialType; 
        CredentialStatus status;  
    }

    function credentials(bytes32 credentialId) external view returns (
        bytes32 credId,
        bytes32 citizenHash,
        bytes memory issuerSignature, 
        uint64 issuanceTimestamp, 
        uint64 expirationTimestamp, 
        CredentialType credentialType, 
        CredentialStatus status
    );
}