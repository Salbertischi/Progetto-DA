// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/CoreIdentityCredential.sol";
import "../src/ZKPVerification.sol";
import "../src/ICoreIdentityCredential.sol";
import "../src/AgeVerifier.sol";
import "../src/RevocationRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";


/**
 * @title ZKPVerificationHarness.
 * @dev contract to expose internal functions to perform testing
 */
contract ZKPVerificationHarness is ZKPVerification {
    function exposeCheckCredentialIsActive(bytes32 credentialId, uint[5] calldata _pubSignals) external view {
        _checkCredentialIsActive(credentialId, _pubSignals);
    }

    function exposeVerifyZKProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[5] calldata _pubSignals,
        ICoreIdentityCredential.CredentialType _proofType
    ) external view returns (bool) {
        return verifyZKProof(_pA, _pB, _pC, _pubSignals, _proofType);
    }

    function exposeVerifySelectiveDisclosure(
        bytes32 _credentialId,
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[5] calldata _pubSignals,
        ICoreIdentityCredential.CredentialType _claimType
    ) external view returns (bool) {
        return verifySelectiveDisclosure(_credentialId, _pA, _pB, _pC, _pubSignals, _claimType);
    }
}

// Upgradeability mock contract
contract ZKPVerificationV2 is ZKPVerificationHarness {
    function getVersion() external pure returns (string memory) {
        return "V2";
    }
}


contract ZKPVerificationTest is Test {
    CoreIdentityCredential public core;
    ZKPVerificationHarness public zkp;
    RevocationRegistry public registry;

    address public admin = address(0x123);
    address public issuer = address(0x456);
    address public authorizedHospital = address(0x789);
    address public unauthorizedEntity = address(0x999);
    
    bytes32 public validCredentialId = keccak256("CRED_1");
    bytes32 public expiredCredentialId = keccak256("CRED_EXPIRED");
    bytes32 public revokedCredentialId = keccak256("CRED_REVOKED");
    bytes32 public citizenHash = 0x1ea19089387fdbdbdf29dfe1976a263f143065170cf95eb910962660d22498ed;

    // Valid proof data
    // Current timestamp used: "1767268800"
    uint[2] public pA = [
        0x1ad78ae8af1f7d55627454412743474e61ebbb020e8300676c2e80482a4e7d25, 
        0x103334a296deda554162fcf42c3006b06b16be4a470529d2211d19a3e7e24fe6
    ];

    uint[2][2] public pB = [
        [0x2e53936d125af9520e73a7b60baf56f0270e1c45fa11fdb50dfd4c68d9a19f21, 0x1891957556f6d36ff90beb73aff8b085b45c16d02d85b43fdc50a32e61672e06],
        [0x0345ad2e0a0b931e1bc96c3874e9df7ff25d091123c5696153e4d2d03762bfc9, 0x10e414100749c4a9b6b789fadb7762c6bd0779047872cd476a07f30107e38de8]
    ];

    uint[2] public pC = [
        0x2a6764748f672f6476688e85364403bd5732876da8d6ba06c37c1acffdbc2595, 
        0x082af0de4f5e23a6eca18456fb208e9a8dfc64bb06e90fa48210e96706105d37
    ];

    // pubSignals order: [citizenHashHigh, citizenHashLow, currentTimestamp, root, nullifier]
    uint[5] public pubSignals = [
        0x000000000000000000000000000000001ea19089387fdbdbdf29dfe1976a263f,
        0x00000000000000000000000000000000143065170cf95eb910962660d22498ed,
        0x00000000000000000000000000000000000000000000000000000000695661c0,
        0x0880a59bf7ef743965421972846cfbcfdec48b8070343e2b244f7e61a60f920d,
        0x0fb849f7cf35865c838cef48782e803b2c38263e2f467799c87eff168eb4d897
    ];

    function setUp() public {
        // Setup in the "past"
        uint256 timeInThePast = 1767268800 - 10 days;
        vm.warp(timeInThePast);
        vm.startPrank(admin);

        // Deploy core (Proxy)
        CoreIdentityCredential coreImpl = new CoreIdentityCredential();
        ERC1967Proxy coreProxy = new ERC1967Proxy(address(coreImpl), abi.encodeWithSelector(CoreIdentityCredential.initialize.selector));
        core = CoreIdentityCredential(address(coreProxy));
        core.grantRole(core.ISSUER_ROLE(), issuer);

        // Deploy Revocation Registry ---
        RevocationRegistry registryImpl = new RevocationRegistry();
        ERC1967Proxy registryProxy = new ERC1967Proxy(address(registryImpl), abi.encodeWithSelector(RevocationRegistry.initialize.selector));
        registry = RevocationRegistry(address(registryProxy));
        registry.grantRole(registry.REVOKER_ROLE(), issuer);
        vm.startPrank(issuer);
        registry.updateMerkleRoot(bytes32(pubSignals[3]));
        vm.stopPrank();

        // Deploy harness (Proxy)
        vm.startPrank(admin);
        ZKPVerificationHarness zkpImpl = new ZKPVerificationHarness();
        ERC1967Proxy zkpProxy = new ERC1967Proxy(address(zkpImpl), abi.encodeWithSelector(ZKPVerification.initialize.selector, address(core), address(registry)));
        zkp = ZKPVerificationHarness(address(zkpProxy));
        zkp.grantRole(zkp.AGE_PROVIDER_ROLE(), authorizedHospital);

        // Deploy verifier
        AgeGroth16Verifier verifier = new AgeGroth16Verifier();
        zkp.setVerifier(ICoreIdentityCredential.CredentialType.AgeVerification, address(verifier));

        vm.stopPrank();

        // Credentials setup
        vm.startPrank(issuer);
        
        // Valid credential
        core.issueCredential(validCredentialId, citizenHash, "0x", uint64(block.timestamp + 365 days), ICoreIdentityCredential.CredentialType.AgeVerification);

        // Expired credential (expires in 1 day)
        core.issueCredential(expiredCredentialId, citizenHash, "0x", uint64(block.timestamp + 1 days), ICoreIdentityCredential.CredentialType.AgeVerification);

        // Revoked credential
        core.issueCredential(revokedCredentialId, citizenHash, "0x", uint64(block.timestamp + 365 days), ICoreIdentityCredential.CredentialType.AgeVerification);
        core.revokeCredential(revokedCredentialId, bytes32(0));

        vm.stopPrank();

        // Warp to ZKP used timestamp
        vm.warp(1767268800);
    }

    // Initialization and role testing

    function testInitialization() public {
        assertTrue(zkp.hasRole(zkp.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(zkp.hasRole(zkp.ADMIN_ROLE(), admin));
        assertEq(address(zkp.coreIdentityContract()), address(core));
    }

    function testSetVerifierSuccess() public {
        vm.prank(admin);
        zkp.setVerifier(ICoreIdentityCredential.CredentialType.Citizenship, address(0x123));
        assertEq(address(zkp.verifiers(ICoreIdentityCredential.CredentialType.Citizenship)), address(0x123));
    }

    function testSetVerifierNotAdminReverts() public {
        vm.prank(address(99)); // Random user, not admin
        vm.expectRevert();
        zkp.setVerifier(ICoreIdentityCredential.CredentialType.Citizenship, address(0x123));
    }

    function testSetVerifierZeroAddressReverts() public {
        vm.prank(admin);
        vm.expectRevert("Invalid verifier address");
        zkp.setVerifier(ICoreIdentityCredential.CredentialType.Citizenship, address(0));
    }

    // Credential testing

    function testCheckCredentialIsActiveSuccess() public {
        zkp.exposeCheckCredentialIsActive(validCredentialId, pubSignals); 
    }

    function testCheckCredentialIsActiveExpiredReverts() public {
        vm.expectRevert("Credential expired");
        zkp.exposeCheckCredentialIsActive(expiredCredentialId, pubSignals);
    }

    function testCheckCredentialIsActiveRevokedReverts() public {
        vm.expectRevert("Credential is not active");
        zkp.exposeCheckCredentialIsActive(revokedCredentialId, pubSignals);
    }

    function testCheckCredentialIsActiveRevokedNullifierReverts() public {
        // Immidiate revocation using nullifier
        vm.prank(issuer);
        registry.revokeImmediately(bytes32(pubSignals[4]));

        vm.expectRevert("Credential immediately revoked");
        zkp.exposeCheckCredentialIsActive(validCredentialId, pubSignals);
    }

    function testCheckCredentialIsActiveInvalidRootReverts() public {
        // Issuer updates the root (simulating a batch revocation)
        vm.prank(issuer);
        registry.updateMerkleRoot(bytes32(uint256(99999))); // fictional root

        vm.expectRevert("Merkle root is not up-to-date");
        zkp.exposeCheckCredentialIsActive(validCredentialId, pubSignals);
    }

    function testSetRevocationRegistrySuccess() public {
        vm.prank(admin);
        zkp.setRevocationRegistry(address(0xABC));
        assertEq(address(zkp.revocationRegistry()), address(0xABC));
    }

    // ZKP testing 

    function testVerifyZKProofSuccess() public {
        bool result = zkp.exposeVerifyZKProof(pA, pB, pC, pubSignals, ICoreIdentityCredential.CredentialType.AgeVerification);
        assertTrue(result);
    }

    function testVerifyZKProofUnsetVerifierReverts() public {
        vm.expectRevert("Unset verifier for this type");
        zkp.exposeVerifyZKProof(pA, pB, pC, pubSignals, ICoreIdentityCredential.CredentialType.Citizenship);
    }

    // Selective disclosure testing

    function testSelectiveDisclosureAgeSuccess() public {
        vm.warp(1767268800); // Just to be safe, set time to ZKP used timestamp
        bool result = zkp.exposeVerifySelectiveDisclosure(validCredentialId, pA, pB, pC, pubSignals, ICoreIdentityCredential.CredentialType.AgeVerification);
        assertTrue(result);
    }

    function testSelectiveDisclosureAgeFutureTimestampReverts() public {
        vm.warp(1767268800 + 301); // Old proof
        vm.expectRevert("Proof's currentTimestamp is not actual current time");
        zkp.exposeVerifySelectiveDisclosure(validCredentialId, pA, pB, pC, pubSignals, ICoreIdentityCredential.CredentialType.AgeVerification);
    }

    function testSelectiveDisclosureAgePastTimestampReverts() public {
        vm.warp(1767268800 - 301); // Proof with future timestamp
        vm.expectRevert("Proof's currentTimestamp is not actual current time");
        zkp.exposeVerifySelectiveDisclosure(validCredentialId, pA, pB, pC, pubSignals, ICoreIdentityCredential.CredentialType.AgeVerification);
    }

    function testSelectiveDisclosureMathInvalidReverts() public {
        uint[2] memory invalidPA = pA;
        invalidPA[0] = pA[0] - 1;
        
        vm.expectRevert("Invalid Proof");
        zkp.exposeVerifySelectiveDisclosure(validCredentialId, invalidPA, pB, pC, pubSignals, ICoreIdentityCredential.CredentialType.AgeVerification);
    }

    function testSelectiveDisclosureAgeProofStealingReverts() public {
        vm.warp(1767268800);
        
        // User B credential setup
        bytes32 citizenHashB = keccak256("CITIZEN_HASH_B");
        bytes32 credentialIdB = keccak256("CRED_B");
        vm.prank(issuer);
        core.issueCredential(credentialIdB, citizenHashB, "0x", uint64(block.timestamp + 365 days), ICoreIdentityCredential.CredentialType.AgeVerification);

        // User B tries to use user A's proof
        vm.expectRevert("Proof not bound to this credential");
        zkp.exposeVerifySelectiveDisclosure(credentialIdB, pA, pB, pC, pubSignals, ICoreIdentityCredential.CredentialType.AgeVerification);
    }

    // Selective disclosure testig

    event DisclosureRecorded(
        address indexed requester,
        bytes32 indexed credentialId,
        ICoreIdentityCredential.CredentialType indexed claimType,
        uint256 timestamp
    );

    function testValidateDisclosureRequestSuccess() public {
        bool isAuthorized = zkp.validateDisclosureRequest(authorizedHospital, ICoreIdentityCredential.CredentialType.AgeVerification);
        assertTrue(isAuthorized);
    }

    function testValidateDisclosureRequestWrongScope() public {
        bool isAuthorized = zkp.validateDisclosureRequest(authorizedHospital, ICoreIdentityCredential.CredentialType.Citizenship);
        assertFalse(isAuthorized);
    }

    function testValidateDisclosureRequestUnauthorized() public {
        bool isAuthorized = zkp.validateDisclosureRequest(unauthorizedEntity, ICoreIdentityCredential.CredentialType.AgeVerification);
        assertFalse(isAuthorized);
    }

    function testValidateDisclosureRequestCitizenshipScope() public {
        address citizenshipProvider = address(0x888);
        vm.startPrank(admin);
        zkp.grantRole(zkp.CITIZENSHIP_PROVIDER_ROLE(), citizenshipProvider);

        bool isAuthorized = zkp.validateDisclosureRequest(citizenshipProvider, ICoreIdentityCredential.CredentialType.Citizenship);
        assertTrue(isAuthorized);

        bool isAuthorizedForAge = zkp.validateDisclosureRequest(citizenshipProvider, ICoreIdentityCredential.CredentialType.AgeVerification);
        assertFalse(isAuthorizedForAge);
    }

    function testValidateDisclosureRequestResidencyScope() public {
        address residencyProvider = address(0x777);
        vm.startPrank(admin);
        zkp.grantRole(zkp.RESIDENCY_PROVIDER_ROLE(), residencyProvider);

        bool isAuthorized = zkp.validateDisclosureRequest(residencyProvider, ICoreIdentityCredential.CredentialType.Residency);
        assertTrue(isAuthorized);
    }

    function testRequestDisclosureSuccessAndEventEmit() public {
        vm.expectEmit(true, true, true, false);
        emit DisclosureRecorded(authorizedHospital, validCredentialId, ICoreIdentityCredential.CredentialType.AgeVerification, 1767268800);

        vm.prank(authorizedHospital);
        bool success = zkp.requestDisclosure(validCredentialId, pA, pB, pC, pubSignals, ICoreIdentityCredential.CredentialType.AgeVerification);
        assertTrue(success);
    }

    function testRequestDisclosureUnauthorizedReverts() public {
        vm.prank(unauthorizedEntity);
        vm.expectRevert(); 
        zkp.requestDisclosure(validCredentialId, pA, pB, pC, pubSignals, ICoreIdentityCredential.CredentialType.AgeVerification);
    }

    function testRequestDisclosureWhenPausedReverts() public {
        // Admin pauses the contract
        vm.prank(admin);
        zkp.pause();

        vm.prank(authorizedHospital);
        vm.expectRevert();
        zkp.requestDisclosure(validCredentialId, pA, pB, pC, pubSignals, ICoreIdentityCredential.CredentialType.AgeVerification);
    }

    // Upgradeability testing

    function test_UpgradeabilityToV2() public {
        ZKPVerificationV2 newImplementation = new ZKPVerificationV2();

        // bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
        bytes32 implSlot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        vm.store(address(zkp), implSlot, bytes32(uint256(uint160(address(newImplementation)))));

        ZKPVerificationV2 upgradedContract = ZKPVerificationV2(address(zkp));
        string memory version = upgradedContract.getVersion();
        assertEq(version, "V2");
    }
    
}