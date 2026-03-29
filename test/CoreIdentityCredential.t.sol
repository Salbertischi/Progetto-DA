// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {CoreIdentityCredential} from "../src/CoreIdentityCredential.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "../src/CoreIdentityCredential.sol";

// Mock V2 contract to test upgradeability
contract CoreIdentityCredentialV2 is CoreIdentityCredential {
    function getVersion() external pure returns (string memory) {
        return "V2";
    }
}

contract CoreIdentityCredentialTest is Test {
    CoreIdentityCredential public identityContract;
    
    uint256 issuerPk = 0xA11CE;
    address issuer = vm.addr(issuerPk);

    uint256 unauthorizedPk = 0xB0B;
    address unauthorized = vm.addr(unauthorizedPk);

    address admin = address(this);
    address citizen = address(0x123);

    bytes32 constant ISSUER_ROLE = keccak256("ISSUER_ROLE");

    event CredentialIssued(bytes32 indexed credentialId, bytes32 citizenHash, uint256 timestamp);
    event CredentialRevoked(bytes32 indexed credentialId, uint256 timestamp);
    event CredentialVerified(bytes32 indexed credentialId, bool isValid);

    function setUp() public {
        address implementation = address(new CoreIdentityCredential());
        bytes memory initData = abi.encodeWithSelector(CoreIdentityCredential.initialize.selector);
        address proxy = address(new ERC1967Proxy(implementation, initData));
        identityContract = CoreIdentityCredential(proxy);
        identityContract.grantRole(ISSUER_ROLE, issuer);
    }

    // CREDENTIAL ISSUANCE

    function test_AuthUserCanIssueCredential() public {
        bytes32 credentialId = keccak256("ID-123");
        bytes32 citizenHash = keccak256("HashSegreto");
        bytes memory signature = new bytes(65);
        uint64 expiration = uint64(block.timestamp + 86400);
        ICoreIdentityCredential.CredentialType credType = ICoreIdentityCredential.CredentialType.Citizenship;

        vm.expectEmit(true, false, false, true);
        emit CredentialIssued(credentialId, citizenHash, block.timestamp);

        vm.prank(issuer);
        identityContract.issueCredential(credentialId, citizenHash, signature, expiration, credType);

        (
            bytes32 storedId,
            bytes32 storedHash,
            bytes memory storedSignature,
            uint64 storedIssueTime,
            uint64 storedExpTime,
            CoreIdentityCredential.CredentialType storedType,
            CoreIdentityCredential.CredentialStatus storedStatus
        ) = identityContract.credentials(credentialId);

        assertEq(storedId, credentialId);
        assertEq(storedHash, citizenHash);
        assertEq(storedSignature, signature);
        assertEq(storedIssueTime, uint64(block.timestamp));
        assertEq(storedExpTime, expiration);
        assertEq(uint(storedType), uint(credType));
        assertEq(uint(storedStatus), uint(ICoreIdentityCredential.CredentialStatus.Active));
    }

    function test_RevertIf_UnauthorizedIssue() public {
        bytes32 credentialId = keccak256("ID-456");
        bytes32 citizenHash = keccak256("HashSegreto");
        bytes memory signature = new bytes(65);
        uint64 expiration = uint64(block.timestamp + 86400);

        bytes4 expectedError = bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)"));
        vm.expectRevert(abi.encodeWithSelector(expectedError, unauthorized, ISSUER_ROLE));
        
        vm.prank(unauthorized);
        identityContract.issueCredential(credentialId, citizenHash, signature, expiration, ICoreIdentityCredential.CredentialType.Citizenship);
    }

    function test_RevertIf_IssueDuplicate() public {
        bytes32 credentialId = keccak256("ID-DUPLICATE");
        bytes32 citizenHash = keccak256("HashSegreto");
        
        vm.prank(issuer);
        identityContract.issueCredential(credentialId, citizenHash, new bytes(65), uint64(block.timestamp + 86400), ICoreIdentityCredential.CredentialType.Citizenship);

        vm.expectRevert("Credential already exists");
        
        vm.prank(issuer);
        identityContract.issueCredential(credentialId, citizenHash, new bytes(65), uint64(block.timestamp + 86400), ICoreIdentityCredential.CredentialType.Citizenship);
    }

    function test_RevertIf_PastExpirationDate() public {
        vm.warp(100000);

        bytes32 credentialId = keccak256("ID-456");
        bytes32 citizenHash = keccak256("HashSegreto");
        bytes memory signature = new bytes(65);
        uint64 expiration = uint64(block.timestamp - 86400);

        vm.prank(issuer);
        vm.expectRevert("Invalid expiration date");
        identityContract.issueCredential(credentialId, citizenHash, signature, expiration, ICoreIdentityCredential.CredentialType.Citizenship);
    }

    // CREDENTIAL REVOCATION

    function test_IssuerCanRevokeActiveCredential() public {
        bytes32 credentialId = keccak256("ID-REVOKE-1");
        bytes32 citizenHash = keccak256("HashSegreto");
        
        vm.prank(issuer);
        identityContract.issueCredential(credentialId, citizenHash, new bytes(65), uint64(block.timestamp + 86400), ICoreIdentityCredential.CredentialType.Citizenship);

        vm.expectEmit(true, false, false, true);
        emit CredentialRevoked(credentialId, block.timestamp);

        vm.prank(issuer);
        identityContract.revokeCredential(credentialId, bytes32(0));

        (,,,,,, ICoreIdentityCredential.CredentialStatus storedStatus) = identityContract.credentials(credentialId);
        assertEq(uint(storedStatus), uint(ICoreIdentityCredential.CredentialStatus.Revoked));
    }

    function test_CitizenCanRevokeOwnCredential() public {
        bytes32 credentialId = keccak256("ID-REVOKE-2");
        bytes32 citizenSecret = keccak256("MioSegreto");
        
        bytes32 citizenHash = keccak256(abi.encodePacked(citizen, citizenSecret));
        
        vm.prank(issuer);
        identityContract.issueCredential(credentialId, citizenHash, new bytes(65), uint64(block.timestamp + 86400), ICoreIdentityCredential.CredentialType.Citizenship);

        vm.prank(citizen);
        identityContract.revokeCredential(credentialId, citizenSecret);

        (,,,,,, ICoreIdentityCredential.CredentialStatus storedStatus) = identityContract.credentials(credentialId);
        assertEq(uint(storedStatus), uint(ICoreIdentityCredential.CredentialStatus.Revoked));
    }

    function test_RevertIf_UnauthorizedCitizenTriesToRevoke() public {
        bytes32 credentialId = keccak256("ID-REVOKE-3");
        bytes32 citizenSecret = keccak256("MioSegreto");
        bytes32 wrongSecret = keccak256("SegretoSbagliato");
        bytes32 citizenHash = keccak256(abi.encodePacked(citizen, citizenSecret));

        vm.prank(issuer);
        identityContract.issueCredential(credentialId, citizenHash, new bytes(65), uint64(block.timestamp + 86400), ICoreIdentityCredential.CredentialType.Citizenship);
        
        vm.expectRevert("Caller is not the owner");
        vm.prank(citizen);
        identityContract.revokeCredential(credentialId, wrongSecret);
    }

    function test_RevertIf_RevokeNonExistentCredential() public {
        bytes32 nonExistentId = keccak256("NON-ESISTE");

        vm.expectRevert("Credential not found");
        
        vm.prank(issuer);
        identityContract.revokeCredential(nonExistentId, bytes32(0));
    }

    function test_RevertIf_RevokeAlreadyRevokedCredential() public {
        bytes32 credentialId = keccak256("ID-REVOKE-4");
        bytes32 citizenHash = keccak256("HashSegreto");

        vm.prank(issuer);
        identityContract.issueCredential(credentialId, citizenHash, new bytes(65), uint64(block.timestamp + 86400), ICoreIdentityCredential.CredentialType.Citizenship);

        vm.prank(issuer);
        identityContract.revokeCredential(credentialId, bytes32(0));

        vm.expectRevert("Credential not active");
        vm.prank(issuer);
        identityContract.revokeCredential(credentialId, bytes32(0));
    }

    function test_RevertIf_CorrectSecretWrongSender() public {
        bytes32 credentialId = keccak256("ID-REVOKE-5");
        bytes32 citizenSecret = keccak256("MioSegreto");
        bytes32 citizenHash = keccak256(abi.encodePacked(citizen, citizenSecret));

        vm.prank(issuer);
        identityContract.issueCredential(credentialId, citizenHash, new bytes(65), uint64(block.timestamp + 86400), ICoreIdentityCredential.CredentialType.Citizenship);

        vm.expectRevert("Caller is not the owner");
        vm.prank(unauthorized);
        identityContract.revokeCredential(credentialId, citizenSecret);
    }

    // --- CREDENTIAL VERIFICATION ---

    function _generateSignature(uint256 privateKey, bytes32 credId, bytes32 citHash) internal pure returns (bytes memory) {
        bytes32 dataHash = keccak256(abi.encodePacked(credId, citHash));
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(dataHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethSignedMessageHash);
        return abi.encodePacked(r, s, v);
    }

    function test_VerifySignature_Valid() public {
        bytes32 credentialId = keccak256("ID-VERIFY-1");
        bytes32 citizenHash = keccak256("HashSegreto");

        bytes memory signature = _generateSignature(issuerPk, credentialId, citizenHash);

        vm.prank(issuer);
        identityContract.issueCredential(credentialId, citizenHash, signature, uint64(block.timestamp + 86400), ICoreIdentityCredential.CredentialType.Citizenship);

        vm.expectEmit(true, false, false, true);
        emit CredentialVerified(credentialId, true);
        bool isValid = identityContract.verifyCredentialSignature(credentialId);
        assertTrue(isValid);
    }

    function test_VerifySignature_TamperedDataOrInvalid() public {
        bytes32 credentialId = keccak256("ID-VERIFY-2");
        bytes32 citizenHash = keccak256("HashSegreto");

        bytes memory invalidSignature = _generateSignature(unauthorizedPk, credentialId, citizenHash);

        vm.prank(issuer);
        identityContract.issueCredential(credentialId, citizenHash, invalidSignature, uint64(block.timestamp + 86400), ICoreIdentityCredential.CredentialType.Citizenship);

        vm.expectEmit(true, false, false, true);
        emit CredentialVerified(credentialId, false);
        bool isValid = identityContract.verifyCredentialSignature(credentialId);
        assertFalse(isValid);
    }

    function test_VerifySignature_ReusedSignature() public {
        bytes32 credentialId1 = keccak256("ID-VERIFY-3A");
        bytes32 credentialId2 = keccak256("ID-VERIFY-3B");
        bytes32 citizenHash = keccak256("HashSegreto");

        bytes memory signature1 = _generateSignature(issuerPk, credentialId1, citizenHash);

        vm.prank(issuer);
        identityContract.issueCredential(credentialId2, citizenHash, signature1, uint64(block.timestamp + 86400), ICoreIdentityCredential.CredentialType.Citizenship);

        vm.expectEmit(true, false, false, true);
        emit CredentialVerified(credentialId2, false);
        bool isValid = identityContract.verifyCredentialSignature(credentialId2);
        assertFalse(isValid);
    }

    function test_RevertIf_VerifyNonExistent() public {
        bytes32 nonExistentId = keccak256("NON-ESISTE");
        vm.expectRevert("Credential not found");
        identityContract.verifyCredentialSignature(nonExistentId);
    }

    function test_RevertIf_VerifyWrongLength() public {
        bytes32 credentialId = keccak256("ID-VERIFY-4");
        bytes32 citizenHash = keccak256("HashSegreto");
        bytes memory invalidLengthSig = new bytes(64); 

        vm.prank(issuer);
        identityContract.issueCredential(credentialId, citizenHash, invalidLengthSig, uint64(block.timestamp + 86400), ICoreIdentityCredential.CredentialType.Citizenship);

        vm.expectRevert(); 
        identityContract.verifyCredentialSignature(credentialId);
    }

    // --- UPGRADEABILITY ---

    function test_UpgradeabilityToV2() public {
        CoreIdentityCredentialV2 newImplementation = new CoreIdentityCredentialV2();

        // bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
        bytes32 implSlot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        vm.store(address(identityContract), implSlot, bytes32(uint256(uint160(address(newImplementation)))));

        CoreIdentityCredentialV2 upgradedContract = CoreIdentityCredentialV2(address(identityContract));
        string memory version = upgradedContract.getVersion();
        assertEq(version, "V2");
    }

    // Pausable testing

    function testPauseAndUnpauseSuccess() public {
        vm.startPrank(admin);
        
        identityContract.pause();
        assertTrue(identityContract.paused());

        identityContract.unpause();
        assertFalse(identityContract.paused());
        
        vm.stopPrank();
    }

    function testPauseUnauthorizedReverts() public {
        vm.prank(unauthorized);
        vm.expectRevert();
        identityContract.pause();
    }

    function testUnpauseUnauthorizedReverts() public {
        vm.prank(admin);
        identityContract.pause();

        vm.prank(unauthorized);
        vm.expectRevert();
        identityContract.unpause();
    }
}