// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/RevocationRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

contract RevocationRegistryTest is Test {
    RevocationRegistry public registry;

    address public admin = address(0x111);
    address public revoker = address(0x222);
    address public unauthorized = address(0x333);

    bytes32 public constant REVOKER_ROLE = keccak256("REVOKER_ROLE");
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    event MerkleRootUpdated(bytes32 indexed oldRoot, bytes32 indexed newRoot);
    event CredentialRevokedImmediately(bytes32 indexed nullifier);

    function setUp() public {
        RevocationRegistry registryImpl = new RevocationRegistry();
        vm.startPrank(admin);

        ERC1967Proxy proxy = new ERC1967Proxy(
            address(registryImpl),
            abi.encodeWithSelector(RevocationRegistry.initialize.selector, admin)
        );

        registry = RevocationRegistry(address(proxy));
        registry.grantRole(REVOKER_ROLE, revoker);
        vm.stopPrank();
    }

    // Initialization testing 

    function testInitialization() public {
        assertTrue(registry.hasRole(DEFAULT_ADMIN_ROLE, admin));
        assertTrue(registry.hasRole(REVOKER_ROLE, revoker));
        assertFalse(registry.paused());
        assertEq(registry.merkleRoot(), bytes32(0));
    }

    // Merkle root update testing

    function testUpdateMerkleRootSuccess() public {
        bytes32 newRoot = bytes32(uint256(12345));

        vm.expectEmit(true, true, false, false);
        emit MerkleRootUpdated(bytes32(0), newRoot);

        vm.prank(revoker);
        registry.updateMerkleRoot(newRoot);

        assertEq(registry.merkleRoot(), newRoot);
    }

    function testUpdateMerkleRootUnauthorizedReverts() public {
        bytes32 newRoot = bytes32(uint256(12345));

        vm.prank(unauthorized);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                unauthorized,
                REVOKER_ROLE
            )
        );
        registry.updateMerkleRoot(newRoot);
    }

    function testUpdateMerkleRootZeroReverts() public {
        vm.prank(revoker);
        vm.expectRevert("Invalid Merkle root");
        registry.updateMerkleRoot(bytes32(0));
    }

    // Immidiate revocation testing

    function testRevokeImmediatelySuccess() public {
        bytes32 nullifier = bytes32(uint256(999));

        vm.expectEmit(true, false, false, false);
        emit CredentialRevokedImmediately(nullifier);

        vm.prank(revoker);
        registry.revokeImmediately(nullifier);

        assertTrue(registry.immediateRevocations(nullifier));
        assertTrue(registry.isRevoked(nullifier));
    }

    function testRevokeImmediatelyUnauthorizedReverts() public {
        bytes32 nullifier = bytes32(uint256(999));

        vm.prank(unauthorized);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                unauthorized,
                REVOKER_ROLE
            )
        );
        registry.revokeImmediately(nullifier);
    }

    function testRevokeImmediatelyZeroNullifierReverts() public {
        vm.prank(revoker);
        vm.expectRevert("Invalid nullifier");
        registry.revokeImmediately(bytes32(0));
    }

    function testRevokeImmediatelyAlreadyRevokedReverts() public {
        bytes32 nullifier = bytes32(uint256(999));

        vm.startPrank(revoker);
        registry.revokeImmediately(nullifier);

        // Tentativo di revocare nuovamente lo stesso nullifier
        vm.expectRevert("Nullifier already revoked");
        registry.revokeImmediately(nullifier);
        vm.stopPrank();
    }

    // Pausable testing

    function testPauseAndUnpauseSuccess() public {
        vm.startPrank(admin);
        
        registry.pause();
        assertTrue(registry.paused());

        registry.unpause();
        assertFalse(registry.paused());
        
        vm.stopPrank();
    }

    function testPauseUnauthorizedReverts() public {
        vm.prank(unauthorized);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                unauthorized,
                DEFAULT_ADMIN_ROLE
            )
        );
        registry.pause();
    }

    function testUpdateMerkleRootWhenPausedReverts() public {
        vm.prank(admin);
        registry.pause();

        vm.prank(revoker);
        vm.expectRevert("EnforcedPause()");
        registry.updateMerkleRoot(bytes32(uint256(12345)));
    }

    function testRevokeImmediatelyWhenPausedReverts() public {
        vm.prank(admin);
        registry.pause();

        vm.prank(revoker);
        vm.expectRevert("EnforcedPause()");
        registry.revokeImmediately(bytes32(uint256(999)));
    }
}