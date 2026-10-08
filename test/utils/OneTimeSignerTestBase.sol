// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {Safe} from "@safe-global/safe-smart-account/contracts/Safe.sol";
import {ISafe} from "@safe-global/safe-smart-account/contracts/interfaces/ISafe.sol";
import {Enum} from "@safe-global/safe-smart-account/contracts/libraries/Enum.sol";
import {MultiSend} from "@safe-global/safe-smart-account/contracts/libraries/MultiSend.sol";
import {SignMessageLib} from "@safe-global/safe-smart-account/contracts/libraries/SignMessageLib.sol";
import {SafeProxyFactory} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {OneTimeSignerFallbackHandler} from "../../src/OneTimeSignerFallbackHandler.sol";
import {OneTimeSignerGuard} from "../../src/OneTimeSignerGuard.sol";
import {OneTimeSignerSetup} from "../../src/OneTimeSignerSetup.sol";
import {OneTimeSignerVault} from "../../src/OneTimeSignerVault.sol";

/// @dev One-time keys and the Merkle tree over their addresses.
struct KeyPool {
    uint256[] privateKeys;
    address[] keys;
    bytes32[][] layers;
}

/// @dev One human signer: their key pool and the vault that is the Safe owner.
struct OneTimeSigner {
    KeyPool pool;
    OneTimeSignerVault vault;
}

/// @dev A Safe signature; `dynamic` (contract) signatures put their data in the dynamic part.
struct SafeSignature {
    address signer;
    bytes data;
    bool dynamic;
}

/// @dev A Safe transaction without gas refund parameters.
struct SafeTx {
    address to;
    uint256 value;
    bytes data;
    Enum.Operation operation;
    uint256 nonce;
}

abstract contract OneTimeSignerTestBase is Test {
    uint256 internal constant SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
    // keccak256("guard_manager.guard.address")
    uint256 internal constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    // keccak256("fallback_manager.handler.address")
    uint256 internal constant FALLBACK_HANDLER_STORAGE_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    address internal constant SENTINEL_OWNERS = address(0x1);

    Safe internal singleton;
    SafeProxyFactory internal factory;
    MultiSend internal multiSend;
    SignMessageLib internal signMessageLib;
    OneTimeSignerGuard internal guard;
    OneTimeSignerFallbackHandler internal handler;
    OneTimeSignerSetup internal setupHelper;
    uint256 private saltNonce;

    function setUp() public virtual {
        singleton = deploySingleton();
        factory = new SafeProxyFactory();
        multiSend = new MultiSend();
        signMessageLib = new SignMessageLib();
        guard = new OneTimeSignerGuard();
        handler = new OneTimeSignerFallbackHandler();
        setupHelper = new OneTimeSignerSetup();
    }

    /// @dev Overridden to run the same tests against `SafeL2`.
    function deploySingleton() internal virtual returns (Safe) {
        return new Safe();
    }

    // --- Key pools ---

    function newPool(string memory seed, uint256 size) internal pure returns (KeyPool memory pool) {
        pool.privateKeys = new uint256[](size);
        pool.keys = new address[](size);
        bytes32[] memory leaves = new bytes32[](size);
        for (uint256 i = 0; i < size; ++i) {
            pool.privateKeys[i] = (uint256(keccak256(abi.encode(seed, i))) % (SECP256K1_N - 1)) + 1;
            pool.keys[i] = vm.addr(pool.privateKeys[i]);
            leaves[i] = hashLeaf(pool.keys[i]);
        }

        uint256 depth = 1;
        for (uint256 width = size; width > 1; width = (width + 1) / 2) {
            ++depth;
        }
        pool.layers = new bytes32[][](depth);
        pool.layers[0] = leaves;
        for (uint256 d = 1; d < depth; ++d) {
            bytes32[] memory below = pool.layers[d - 1];
            bytes32[] memory layer = new bytes32[]((below.length + 1) / 2);
            for (uint256 i = 0; i < below.length; i += 2) {
                // An odd node is promoted to the next layer unchanged.
                layer[i / 2] = i + 1 < below.length ? hashPair(below[i], below[i + 1]) : below[i];
            }
            pool.layers[d] = layer;
        }
    }

    /// @dev Leaf encoding of OpenZeppelin's `StandardMerkleTree` for `["address"]` leaves.
    function hashLeaf(address key) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(key))));
    }

    function hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function root(KeyPool memory pool) internal pure returns (bytes32) {
        return pool.layers[pool.layers.length - 1][0];
    }

    function proof(KeyPool memory pool, uint256 index) internal pure returns (bytes32[] memory keyProof) {
        keyProof = new bytes32[](pool.layers.length - 1);
        uint256 length = 0;
        for (uint256 d = 0; d + 1 < pool.layers.length; ++d) {
            uint256 sibling = index ^ 1;
            if (sibling < pool.layers[d].length) keyProof[length++] = pool.layers[d][sibling];
            index >>= 1;
        }
        assembly ("memory-safe") {
            mstore(keyProof, length)
        }
    }

    function newSigner(string memory seed, uint256 size) internal returns (OneTimeSigner memory signer) {
        signer.pool = newPool(seed, size);
        signer.vault = new OneTimeSignerVault(root(signer.pool), guard);
    }

    // --- Signatures ---

    /// @dev Normalizes `s` to the lower half, like wallets do.
    function signDigest(uint256 privateKey, bytes32 digest) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        (v, r, s) = vm.sign(privateKey, digest);
        if (uint256(s) > SECP256K1_N / 2) {
            s = bytes32(SECP256K1_N - uint256(s));
            v = v == 27 ? 28 : 27;
        }
    }

    function encodeKeySignature(address key, uint8 v, bytes32 r, bytes32 s, bytes32[] memory keyProof)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(key, r, s, v, keyProof);
    }

    function signWithKey(OneTimeSigner memory signer, uint256 keyIndex, bytes32 hash) internal pure returns (SafeSignature memory) {
        (uint8 v, bytes32 r, bytes32 s) = signDigest(signer.pool.privateKeys[keyIndex], hash);
        bytes memory data = encodeKeySignature(signer.pool.keys[keyIndex], v, r, s, proof(signer.pool, keyIndex));
        return SafeSignature(address(signer.vault), data, true);
    }

    function signWithEoa(address signer, uint256 privateKey, bytes32 hash) internal pure returns (SafeSignature memory) {
        (uint8 v, bytes32 r, bytes32 s) = signDigest(privateKey, hash);
        return SafeSignature(signer, abi.encodePacked(r, s, v), false);
    }

    function sigs(SafeSignature memory a) internal pure returns (SafeSignature[] memory list) {
        list = new SafeSignature[](1);
        list[0] = a;
    }

    function sigs(SafeSignature memory a, SafeSignature memory b) internal pure returns (SafeSignature[] memory list) {
        list = new SafeSignature[](2);
        list[0] = a;
        list[1] = b;
    }

    function sigs(SafeSignature memory a, SafeSignature memory b, SafeSignature memory c)
        internal
        pure
        returns (SafeSignature[] memory list)
    {
        list = new SafeSignature[](3);
        list[0] = a;
        list[1] = b;
        list[2] = c;
    }

    /// @dev Same layout as Safe's `buildSignatureBytes`: sorted by signer, static parts, then dynamic parts.
    function encodeSignatures(SafeSignature[] memory signatures) internal pure returns (bytes memory) {
        for (uint256 i = 1; i < signatures.length; ++i) {
            for (uint256 j = i; j > 0 && signatures[j - 1].signer > signatures[j].signer; --j) {
                (signatures[j - 1], signatures[j]) = (signatures[j], signatures[j - 1]);
            }
        }
        bytes memory staticPart;
        bytes memory dynamicPart;
        for (uint256 i = 0; i < signatures.length; ++i) {
            SafeSignature memory signature = signatures[i];
            if (signature.dynamic) {
                uint256 offset = signatures.length * 65 + dynamicPart.length;
                staticPart = abi.encodePacked(staticPart, uint256(uint160(signature.signer)), offset, uint8(0));
                dynamicPart = abi.encodePacked(dynamicPart, signature.data.length, signature.data);
            } else {
                staticPart = abi.encodePacked(staticPart, signature.data);
            }
        }
        return abi.encodePacked(staticPart, dynamicPart);
    }

    // --- Safes ---

    function owners(OneTimeSigner memory a, OneTimeSigner memory b, OneTimeSigner memory c) internal pure returns (address[] memory) {
        return addrs(address(a.vault), address(b.vault), address(c.vault));
    }

    function addrs(address a) internal pure returns (address[] memory list) {
        list = new address[](1);
        list[0] = a;
    }

    function addrs(address a, address b) internal pure returns (address[] memory list) {
        list = new address[](2);
        list[0] = a;
        list[1] = b;
    }

    function addrs(address a, address b, address c) internal pure returns (address[] memory list) {
        list = new address[](3);
        list[0] = a;
        list[1] = b;
        list[2] = c;
    }

    /// @dev Deploys a Safe in one factory call, optionally with the guard.
    function createSafe(address[] memory safeOwners, uint256 threshold, bool withGuard) internal returns (Safe) {
        address to = withGuard ? address(setupHelper) : address(0);
        bytes memory data = withGuard ? abi.encodeCall(OneTimeSignerSetup.enableGuard, (address(guard))) : bytes("");
        address fallbackHandler = withGuard ? address(handler) : address(0);
        bytes memory initializer =
            abi.encodeCall(ISafe.setup, (safeOwners, threshold, to, data, fallbackHandler, address(0), 0, payable(address(0))));
        return Safe(payable(address(factory.createProxyWithNonce(address(singleton), initializer, saltNonce++))));
    }

    function createOneTimeSignerSafe(address[] memory safeOwners, uint256 threshold) internal returns (Safe) {
        return createSafe(safeOwners, threshold, true);
    }

    function callTx(Safe safe, address to, uint256 value, bytes memory data) internal view returns (SafeTx memory) {
        return SafeTx(to, value, data, Enum.Operation.Call, safe.nonce());
    }

    function hashOf(Safe safe, SafeTx memory safeTx) internal view returns (bytes32) {
        return
            safe.getTransactionHash(safeTx.to, safeTx.value, safeTx.data, safeTx.operation, 0, 0, 0, address(0), address(0), safeTx.nonce);
    }

    /// @dev Makes exactly one external call, so it can directly follow `vm.expectRevert`.
    function exec(Safe safe, SafeTx memory safeTx, SafeSignature[] memory signatures) internal returns (bool) {
        return execRaw(safe, safeTx, encodeSignatures(signatures));
    }

    function execRaw(Safe safe, SafeTx memory safeTx, bytes memory signatures) internal returns (bool) {
        return
            safe.execTransaction(
                safeTx.to, safeTx.value, safeTx.data, safeTx.operation, 0, 0, 0, address(0), payable(address(0)), signatures
            );
    }

    function readSlot(Safe safe, uint256 slot) internal view returns (address) {
        return abi.decode(safe.getStorageAt(slot, 1), (address));
    }

    function encodeMultiSendCall(address to, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(Enum.Operation.Call), to, uint256(0), data.length, data);
    }

    function encodeCheckTransaction(SafeTx memory safeTx, bytes memory signatures, address msgSender) internal pure returns (bytes memory) {
        return abi.encodeCall(
            OneTimeSignerGuard.checkTransaction,
            (safeTx.to, safeTx.value, safeTx.data, safeTx.operation, 0, 0, 0, address(0), payable(address(0)), signatures, msgSender)
        );
    }
}
