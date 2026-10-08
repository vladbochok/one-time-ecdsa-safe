// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.21;

import {Safe} from "@safe-global/safe-smart-account/contracts/Safe.sol";
import {SafeL2} from "@safe-global/safe-smart-account/contracts/SafeL2.sol";
import {IFallbackManager} from "@safe-global/safe-smart-account/contracts/interfaces/IFallbackManager.sol";
import {IGuardManager} from "@safe-global/safe-smart-account/contracts/interfaces/IGuardManager.sol";
import {IOwnerManager} from "@safe-global/safe-smart-account/contracts/interfaces/IOwnerManager.sol";
import {ISafe} from "@safe-global/safe-smart-account/contracts/interfaces/ISafe.sol";
import {Enum} from "@safe-global/safe-smart-account/contracts/libraries/Enum.sol";
import {MultiSend} from "@safe-global/safe-smart-account/contracts/libraries/MultiSend.sol";
import {SignMessageLib} from "@safe-global/safe-smart-account/contracts/libraries/SignMessageLib.sol";
import {OneTimeSignerFallbackHandler} from "../src/OneTimeSignerFallbackHandler.sol";
import {OneTimeSignerGuard} from "../src/OneTimeSignerGuard.sol";
import {OneTimeSignerVault} from "../src/OneTimeSignerVault.sol";
import {KeyPool, OneTimeSigner, OneTimeSignerTestBase, SafeSignature, SafeTx} from "./utils/OneTimeSignerTestBase.sol";

contract OneTimeSignerTest is OneTimeSignerTestBase {
    bytes4 internal constant EIP1271_MAGIC_VALUE = 0x1626ba7e;
    string internal constant BAD_ENCODING = "Signatures must encode exactly threshold vault signatures";

    address internal recipient = makeAddr("recipient");
    OneTimeSignerVault internal aliceVault;
    OneTimeSignerVault internal bobVault;
    OneTimeSignerVault internal carolVault;
    Safe internal safe;

    function setUp() public override {
        super.setUp();
        aliceVault = newSigner("alice", 8).vault;
        bobVault = newSigner("bob", 8).vault;
        // Odd pool size: the last leaf has no sibling.
        carolVault = newSigner("carol", 5).vault;
        safe = createOneTimeSignerSafe(owners(alice(), bob(), carol()), 2);
        vm.deal(address(safe), 1 ether);
    }

    function alice() internal view returns (OneTimeSigner memory) {
        return OneTimeSigner(newPool("alice", 8), aliceVault);
    }

    function bob() internal view returns (OneTimeSigner memory) {
        return OneTimeSigner(newPool("bob", 8), bobVault);
    }

    function carol() internal view returns (OneTimeSigner memory) {
        return OneTimeSigner(newPool("carol", 5), carolVault);
    }

    function transfer() internal view returns (SafeTx memory) {
        return callTx(safe, recipient, 1, "");
    }

    function previousOwner(Safe target, address owner) internal view returns (address) {
        address[] memory list = target.getOwners();
        for (uint256 i = 0; i < list.length; ++i) {
            if (list[i] == owner) return i == 0 ? SENTINEL_OWNERS : list[i - 1];
        }
        revert("Not an owner");
    }

    // --- Setup ---

    function test_setup_EnablesGuardAndFallbackHandler() public view {
        assertEq(readSlot(safe, GUARD_STORAGE_SLOT), address(guard));
        assertEq(readSlot(safe, FALLBACK_HANDLER_STORAGE_SLOT), address(handler));
        assertEq(safe.getOwners(), owners(alice(), bob(), carol()));
        assertEq(safe.getThreshold(), 2);
    }

    function test_setup_RevertsWhen_NotDelegatecalled() public {
        vm.expectRevert(bytes("Must be delegatecalled"));
        setupHelper.enableGuard(address(guard));
    }

    // --- execTransaction ---

    function test_exec_BurnsSigningKeys() public {
        SafeTx memory safeTx = transfer();
        bytes32 hash = hashOf(safe, safeTx);
        address aliceKey = alice().pool.keys[0];
        address bobKey = bob().pool.keys[0];
        SafeSignature[] memory signatures = sigs(signWithKey(alice(), 0, hash), signWithKey(bob(), 0, hash));

        // The guard processes signatures in owner order.
        bool aliceFirst = address(aliceVault) < address(bobVault);
        vm.expectEmit(address(guard));
        emit OneTimeSignerGuard.KeyUsed(address(safe), aliceFirst ? address(aliceVault) : address(bobVault), aliceFirst ? aliceKey : bobKey);
        vm.expectEmit(address(guard));
        emit OneTimeSignerGuard.KeyUsed(address(safe), aliceFirst ? address(bobVault) : address(aliceVault), aliceFirst ? bobKey : aliceKey);
        exec(safe, safeTx, signatures);

        assertEq(recipient.balance, 1);
        assertTrue(guard.isKeyUsed(address(safe), aliceKey));
        assertTrue(guard.isKeyUsed(address(safe), bobKey));
        assertFalse(guard.isKeyUsed(address(safe), alice().pool.keys[1]));
    }

    function test_exec_RevertsWhen_KeyAlreadyUsed() public {
        SafeTx memory first = transfer();
        bytes32 firstHash = hashOf(safe, first);
        exec(safe, first, sigs(signWithKey(alice(), 0, firstHash), signWithKey(bob(), 0, firstHash)));

        SafeTx memory second = transfer();
        bytes32 secondHash = hashOf(safe, second);
        SafeSignature[] memory signatures = sigs(signWithKey(alice(), 0, secondHash), signWithKey(bob(), 1, secondHash));
        vm.expectRevert(bytes("Key already used"));
        exec(safe, second, signatures);
    }

    function testFuzz_exec_KeysSignOnlyOnce(uint256 aliceIndex, uint256 bobIndex) public {
        aliceIndex = bound(aliceIndex, 0, 7);
        bobIndex = bound(bobIndex, 0, 7);
        SafeTx memory first = transfer();
        bytes32 firstHash = hashOf(safe, first);
        exec(safe, first, sigs(signWithKey(alice(), aliceIndex, firstHash), signWithKey(bob(), bobIndex, firstHash)));
        assertTrue(guard.isKeyUsed(address(safe), alice().pool.keys[aliceIndex]));
        assertTrue(guard.isKeyUsed(address(safe), bob().pool.keys[bobIndex]));

        SafeTx memory second = transfer();
        bytes32 secondHash = hashOf(safe, second);
        SafeSignature[] memory signatures = sigs(signWithKey(alice(), aliceIndex, secondHash), signWithKey(carol(), 0, secondHash));
        vm.expectRevert(bytes("Key already used"));
        exec(safe, second, signatures);
    }

    function test_exec_RevertsWhen_KeySharedByTwoVaults() public {
        OneTimeSigner memory sharedPool = OneTimeSigner(alice().pool, new OneTimeSignerVault(aliceVault.KEYS_ROOT(), guard));
        Safe sharedSafe = createOneTimeSignerSafe(addrs(address(aliceVault), address(sharedPool.vault)), 2);
        SafeTx memory safeTx = callTx(sharedSafe, recipient, 0, "");
        bytes32 hash = hashOf(sharedSafe, safeTx);
        SafeSignature[] memory signatures = sigs(signWithKey(alice(), 0, hash), signWithKey(sharedPool, 0, hash));

        vm.expectRevert(bytes("Key already used"));
        exec(sharedSafe, safeTx, signatures);
    }

    function test_exec_RevertsWhen_KeyNotInPool() public {
        SafeTx memory safeTx = transfer();
        bytes32 hash = hashOf(safe, safeTx);
        // A key from Carol's pool presented by Alice's vault.
        SafeSignature memory foreign = signWithKey(OneTimeSigner(carol().pool, aliceVault), 0, hash);
        SafeSignature[] memory signatures = sigs(foreign, signWithKey(bob(), 0, hash));

        vm.expectRevert(bytes("Key not in pool"));
        exec(safe, safeTx, signatures);
    }

    function test_exec_RevertsWhen_SignatureNotFromDeclaredKey() public {
        SafeTx memory safeTx = transfer();
        bytes32 hash = hashOf(safe, safeTx);
        KeyPool memory pool = alice().pool;
        (uint8 v, bytes32 r, bytes32 s) = signDigest(pool.privateKeys[2], hash);
        bytes memory data = encodeKeySignature(pool.keys[1], v, r, s, proof(pool, 1));
        SafeSignature[] memory signatures = sigs(SafeSignature(address(aliceVault), data, true), signWithKey(bob(), 0, hash));

        vm.expectRevert(bytes("Invalid key signature"));
        exec(safe, safeTx, signatures);
    }

    function test_exec_RevertsWhen_SignatureIsMalleable() public {
        SafeTx memory safeTx = transfer();
        bytes32 hash = hashOf(safe, safeTx);
        KeyPool memory pool = alice().pool;
        (uint8 v, bytes32 r, bytes32 s) = signDigest(pool.privateKeys[0], hash);
        // (r, n - s) with the flipped v recovers the same key.
        bytes32 highS = bytes32(SECP256K1_N - uint256(s));
        uint8 flippedV = v == 27 ? 28 : 27;
        assertEq(ecrecover(hash, flippedV, r, highS), pool.keys[0]);
        bytes memory data = encodeKeySignature(pool.keys[0], flippedV, r, highS, proof(pool, 0));
        SafeSignature[] memory signatures = sigs(SafeSignature(address(aliceVault), data, true), signWithKey(bob(), 0, hash));

        vm.expectRevert(bytes("Invalid signature s value"));
        exec(safe, safeTx, signatures);
    }

    function test_exec_AcceptsEthSignSignatures() public {
        SafeTx memory safeTx = transfer();
        bytes32 hash = hashOf(safe, safeTx);
        KeyPool memory pool = carol().pool;
        bytes32 ethSignDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        (uint8 v, bytes32 r, bytes32 s) = signDigest(pool.privateKeys[4], ethSignDigest);
        bytes memory data = encodeKeySignature(pool.keys[4], v + 4, r, s, proof(pool, 4));

        exec(safe, safeTx, sigs(signWithKey(alice(), 0, hash), SafeSignature(address(carolVault), data, true)));
        assertTrue(guard.isKeyUsed(address(safe), pool.keys[4]));
    }

    function test_exec_RevertsWhen_MoreSignaturesThanThreshold() public {
        SafeTx memory safeTx = transfer();
        bytes32 hash = hashOf(safe, safeTx);
        SafeSignature[] memory signatures = sigs(signWithKey(alice(), 0, hash), signWithKey(bob(), 0, hash), signWithKey(carol(), 0, hash));

        vm.expectRevert(bytes(BAD_ENCODING));
        exec(safe, safeTx, signatures);
        assertFalse(guard.isKeyUsed(address(safe), alice().pool.keys[0]));
        assertFalse(guard.isKeyUsed(address(safe), bob().pool.keys[0]));
        assertFalse(guard.isKeyUsed(address(safe), carol().pool.keys[0]));
    }

    /// @dev The Safe ignores trailing bytes, which could carry extra, unburned signatures.
    function testFuzz_exec_RevertsWhen_SignatureDataAppended(bytes memory extra) public {
        vm.assume(extra.length > 0);
        SafeTx memory safeTx = transfer();
        bytes32 hash = hashOf(safe, safeTx);
        bytes memory signatures = bytes.concat(encodeSignatures(sigs(signWithKey(alice(), 0, hash), signWithKey(bob(), 0, hash))), extra);

        vm.expectRevert(bytes(BAD_ENCODING));
        execRaw(safe, safeTx, signatures);
    }

    function test_exec_RevertsWhen_OwnerIsNotAVault() public {
        (address eoa, uint256 eoaKey) = makeAddrAndKey("eoa");
        Safe mixedSafe = createOneTimeSignerSafe(addrs(address(aliceVault), eoa), 2);
        SafeTx memory safeTx = callTx(mixedSafe, recipient, 0, "");
        bytes32 hash = hashOf(mixedSafe, safeTx);
        SafeSignature[] memory signatures = sigs(signWithKey(alice(), 0, hash), signWithEoa(eoa, eoaKey, hash));

        vm.expectRevert(bytes("Only vault signatures are allowed"));
        exec(mixedSafe, safeTx, signatures);
    }

    function test_exec_RevertsWhen_SafeHasNoGuard() public {
        Safe unguarded = createSafe(owners(alice(), bob(), carol()), 2, false);
        SafeTx memory safeTx = callTx(unguarded, recipient, 0, "");
        bytes32 hash = hashOf(unguarded, safeTx);
        SafeSignature[] memory signatures = sigs(signWithKey(alice(), 0, hash), signWithKey(bob(), 0, hash));

        vm.expectRevert(bytes("Safe must use the one-time signer guard"));
        exec(unguarded, safeTx, signatures);
    }

    function test_exec_SignsQueuedTransactionsInParallel() public {
        uint256 nonce = safe.nonce();
        SafeTx memory first = transfer();
        SafeTx memory second = SafeTx(recipient, 1, "", Enum.Operation.Call, nonce + 1);
        bytes32 firstHash = hashOf(safe, first);
        bytes32 secondHash = hashOf(safe, second);
        // Both signed before either executes, with different keys.
        SafeSignature[] memory firstSignatures = sigs(signWithKey(alice(), 0, firstHash), signWithKey(bob(), 0, firstHash));
        SafeSignature[] memory secondSignatures = sigs(signWithKey(alice(), 1, secondHash), signWithKey(carol(), 0, secondHash));

        exec(safe, first, firstSignatures);
        exec(safe, second, secondSignatures);
        assertEq(safe.nonce(), nonce + 2);
        assertEq(recipient.balance, 2);
    }

    // --- revokeKeys ---

    function test_revokeKeys_BurnsKeysOfAbandonedTransaction() public {
        address[] memory abandonedKeys = addrs(alice().pool.keys[0], bob().pool.keys[0]);
        // Replaces the abandoned transaction (same nonce).
        SafeTx memory revokeTx = callTx(safe, address(guard), 0, abi.encodeCall(OneTimeSignerGuard.revokeKeys, (abandonedKeys)));
        bytes32 revokeHash = hashOf(safe, revokeTx);
        SafeSignature[] memory revokeSignatures = sigs(signWithKey(alice(), 1, revokeHash), signWithKey(bob(), 1, revokeHash));

        vm.expectEmit(address(guard));
        emit OneTimeSignerGuard.KeyRevoked(address(safe), abandonedKeys[0]);
        vm.expectEmit(address(guard));
        emit OneTimeSignerGuard.KeyRevoked(address(safe), abandonedKeys[1]);
        exec(safe, revokeTx, revokeSignatures);

        SafeTx memory next = transfer();
        bytes32 nextHash = hashOf(safe, next);
        SafeSignature[] memory signatures = sigs(signWithKey(alice(), 0, nextHash), signWithKey(carol(), 0, nextHash));
        vm.expectRevert(bytes("Key already used"));
        exec(safe, next, signatures);
    }

    function test_revokeKeys_OnlyAffectsCaller() public {
        address key = alice().pool.keys[0];
        address caller = makeAddr("caller");

        vm.prank(caller);
        guard.revokeKeys(addrs(key));

        assertTrue(guard.isKeyUsed(caller, key));
        assertFalse(guard.isKeyUsed(address(safe), key));
    }

    // --- checkTransaction ---

    function test_checkTransaction_OnlyBurnsKeysOfCaller() public {
        SafeTx memory pending = transfer();
        bytes32 pendingHash = hashOf(safe, pending);
        SafeSignature memory aliceSignature = signWithKey(alice(), 0, pendingHash);
        SafeSignature memory bobSignature = signWithKey(bob(), 0, pendingHash);

        // Another Safe replays a pending signature into the guard.
        (address attacker, uint256 attackerKey) = makeAddrAndKey("attacker");
        Safe otherSafe = createSafe(addrs(attacker), 1, false);
        bytes memory replay = encodeCheckTransaction(pending, encodeSignatures(sigs(aliceSignature)), attacker);
        SafeTx memory replayTx = callTx(otherSafe, address(guard), 0, replay);
        exec(otherSafe, replayTx, sigs(signWithEoa(attacker, attackerKey, hashOf(otherSafe, replayTx))));

        assertTrue(guard.isKeyUsed(address(otherSafe), alice().pool.keys[0]));
        assertFalse(guard.isKeyUsed(address(safe), alice().pool.keys[0]));
        exec(safe, pending, sigs(aliceSignature, bobSignature));
    }

    // --- Rotation and migration ---

    function test_rotation_ReplacesVaultWithNewPool() public {
        OneTimeSigner memory newAlice = newSigner("alice-2", 4);
        bytes memory swap = abi.encodeCall(
            IOwnerManager.swapOwner, (previousOwner(safe, address(aliceVault)), address(aliceVault), address(newAlice.vault))
        );
        SafeTx memory swapTx = callTx(safe, address(safe), 0, swap);
        bytes32 swapHash = hashOf(safe, swapTx);
        exec(safe, swapTx, sigs(signWithKey(alice(), 0, swapHash), signWithKey(bob(), 0, swapHash)));
        assertTrue(safe.isOwner(address(newAlice.vault)));
        assertFalse(safe.isOwner(address(aliceVault)));

        SafeTx memory next = transfer();
        bytes32 nextHash = hashOf(safe, next);
        SafeSignature[] memory oldVaultSignatures = sigs(signWithKey(alice(), 1, nextHash), signWithKey(bob(), 1, nextHash));
        vm.expectRevert(bytes("GS026"));
        exec(safe, next, oldVaultSignatures);

        exec(safe, next, sigs(signWithKey(newAlice, 0, nextHash), signWithKey(bob(), 1, nextHash)));
    }

    function test_migration_MovesExistingSafeToVaults() public {
        Account[3] memory eoaOwners = [makeAccount("owner0"), makeAccount("owner1"), makeAccount("owner2")];
        Safe legacy = createSafe(addrs(eoaOwners[0].addr, eoaOwners[1].addr, eoaOwners[2].addr), 2, false);
        OneTimeSigner[3] memory vaultOwners = [newSigner("dave", 4), newSigner("erin", 4), newSigner("frank", 4)];

        // The current owners enable the guard and handler and swap themselves for vaults in one transaction.
        SafeTx memory migration = SafeTx(
            address(multiSend),
            0,
            abi.encodeCall(MultiSend.multiSend, (migrationBatch(legacy, eoaOwners, vaultOwners))),
            Enum.Operation.DelegateCall,
            legacy.nonce()
        );
        exec(legacy, migration, signWithEoas(eoaOwners, hashOf(legacy, migration)));

        assertEq(readSlot(legacy, GUARD_STORAGE_SLOT), address(guard));
        assertEq(readSlot(legacy, FALLBACK_HANDLER_STORAGE_SLOT), address(handler));
        assertEq(legacy.getOwners(), owners(vaultOwners[0], vaultOwners[1], vaultOwners[2]));

        vm.deal(address(legacy), 1);
        SafeTx memory next = callTx(legacy, recipient, 1, "");
        bytes32 nextHash = hashOf(legacy, next);
        SafeSignature[] memory oldOwnerSignatures = signWithEoas(eoaOwners, nextHash);
        vm.expectRevert(bytes("GS026"));
        exec(legacy, next, oldOwnerSignatures);

        exec(legacy, next, sigs(signWithKey(vaultOwners[0], 0, nextHash), signWithKey(vaultOwners[1], 0, nextHash)));
        assertTrue(guard.isKeyUsed(address(legacy), vaultOwners[0].pool.keys[0]));
        assertEq(recipient.balance, 1);
    }

    function migrationBatch(Safe legacy, Account[3] memory eoaOwners, OneTimeSigner[3] memory vaultOwners)
        internal
        view
        returns (bytes memory batch)
    {
        batch = bytes.concat(
            encodeMultiSendCall(address(legacy), abi.encodeCall(IGuardManager.setGuard, (address(guard)))),
            encodeMultiSendCall(address(legacy), abi.encodeCall(IFallbackManager.setFallbackHandler, (address(handler))))
        );
        // `swapOwner` keeps list positions, so each vault precedes the next swap.
        address prevOwner = SENTINEL_OWNERS;
        for (uint256 i = 0; i < 3; ++i) {
            address vault = address(vaultOwners[i].vault);
            bytes memory swap = abi.encodeCall(IOwnerManager.swapOwner, (prevOwner, eoaOwners[i].addr, vault));
            batch = bytes.concat(batch, encodeMultiSendCall(address(legacy), swap));
            prevOwner = vault;
        }
    }

    /// @dev Signs with two of the three EOA owners.
    function signWithEoas(Account[3] memory eoaOwners, bytes32 hash) internal pure returns (SafeSignature[] memory) {
        return sigs(signWithEoa(eoaOwners[0].addr, eoaOwners[0].key, hash), signWithEoa(eoaOwners[1].addr, eoaOwners[1].key, hash));
    }

    // --- Messages ---

    function test_messages_RevertsWhen_SignedOffChain() public {
        bytes32 dataHash = keccak256("0xbaddad");
        bytes32 messageHash = handler.getMessageHashForSafe(ISafe(payable(address(safe))), abi.encode(dataHash));
        bytes memory signatures = encodeSignatures(sigs(signWithKey(alice(), 0, messageHash), signWithKey(bob(), 0, messageHash)));

        // Valid for the Safe, but the handler only accepts on-chain signed messages.
        safe.checkSignatures(address(0), messageHash, signatures);
        vm.expectRevert(bytes("Only on-chain signed messages are supported"));
        OneTimeSignerFallbackHandler(address(safe)).isValidSignature(dataHash, signatures);
    }

    function test_messages_RevertsWhen_NotSigned() public {
        vm.expectRevert(bytes("Hash not approved"));
        OneTimeSignerFallbackHandler(address(safe)).isValidSignature(keccak256("0xbaddad"), "");
    }

    function test_messages_AcceptsMessagesSignedOnChain() public {
        bytes32 dataHash = keccak256("0xbaddad");
        bytes memory signMessage = abi.encodeCall(SignMessageLib.signMessage, (abi.encode(dataHash)));
        SafeTx memory signTx = SafeTx(address(signMessageLib), 0, signMessage, Enum.Operation.DelegateCall, safe.nonce());
        bytes32 hash = hashOf(safe, signTx);

        exec(safe, signTx, sigs(signWithKey(alice(), 0, hash), signWithKey(bob(), 0, hash)));

        bytes4 magicValue = OneTimeSignerFallbackHandler(address(safe)).isValidSignature(dataHash, "");
        assertEq(bytes32(magicValue), bytes32(EIP1271_MAGIC_VALUE));
        assertTrue(guard.isKeyUsed(address(safe), alice().pool.keys[0]));
        assertTrue(guard.isKeyUsed(address(safe), bob().pool.keys[0]));
    }

    // --- OneTimeSignerVault ---

    function test_vault_RevertsWhen_DeployedWithoutRootOrGuard() public {
        bytes32 keysRoot = aliceVault.KEYS_ROOT();
        vm.expectRevert(bytes("Invalid keys root"));
        new OneTimeSignerVault(bytes32(0), guard);
        vm.expectRevert(bytes("Invalid guard"));
        new OneTimeSignerVault(keysRoot, OneTimeSignerGuard(address(0)));
    }

    function test_vault_RevertsWhen_NotCalledBySafe() public {
        bytes32 hash = keccak256("0xbaddad");
        bytes memory data = signWithKey(alice(), 0, hash).data;

        vm.expectRevert();
        aliceVault.isValidSignature(hash, data);
    }

    function testFuzz_vault_ChecksPoolMembership(uint256 seed, uint256 size, uint256 index, uint256 outsiderKey) public {
        size = bound(size, 1, 64);
        index = bound(index, 0, size - 1);
        outsiderKey = bound(outsiderKey, 1, SECP256K1_N - 1);
        KeyPool memory pool = newPool(vm.toString(seed), size);
        address outsider = vm.addr(outsiderKey);
        vm.assume(outsider != pool.keys[index]);
        OneTimeSignerVault vault = new OneTimeSignerVault(root(pool), guard);
        bytes32[] memory keyProof = proof(pool, index);

        assertTrue(vault.isKeyInPool(pool.keys[index], keyProof));
        assertFalse(vault.isKeyInPool(outsider, keyProof));
    }
}

/// @dev Runs every test against `SafeL2`.
contract OneTimeSignerL2Test is OneTimeSignerTest {
    function deploySingleton() internal override returns (Safe) {
        return new SafeL2();
    }
}
