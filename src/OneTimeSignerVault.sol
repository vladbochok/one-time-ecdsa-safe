// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import {ISafe} from "@safe-global/safe-smart-account/contracts/interfaces/ISafe.sol";
import {ISignatureValidator} from "@safe-global/safe-smart-account/contracts/interfaces/ISignatureValidator.sol";
import {OneTimeSignerGuard} from "./OneTimeSignerGuard.sol";

/**
 * @title OneTimeSignerVault - Safe owner backed by a Merkle-committed pool of one-time ECDSA keys.
 * @notice One vault per human signer. Each key reveals its public key with its single signature, then {OneTimeSignerGuard}
 *         burns it. Immutable: rotate pools by swapping in a new vault.
 * @dev Signature data: `abi.encode(address key, bytes32 r, bytes32 s, uint8 v, bytes32[] proof)`. `key` comes first because
 *      the guard reads it; `v` is 31/32 for `eth_sign`. Leaves and pair hashing match OpenZeppelin's `StandardMerkleTree`.
 */
contract OneTimeSignerVault is ISignatureValidator {
    // keccak256("guard_manager.guard.address")
    bytes32 internal constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    // secp256k1n / 2
    uint256 internal constant SECP256K1N_HALF = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    bytes32 public immutable KEYS_ROOT;
    OneTimeSignerGuard public immutable GUARD;

    constructor(bytes32 keysRoot, OneTimeSignerGuard guard) {
        require(keysRoot != bytes32(0), "Invalid keys root");
        require(address(guard) != address(0), "Invalid guard");
        KEYS_ROOT = keysRoot;
        GUARD = guard;
    }

    /// @dev Reverts on invalid signatures, and for Safes without {GUARD}, which would not burn keys.
    function isValidSignature(bytes32 _hash, bytes memory _signature) external view override returns (bytes4) {
        ISafe safe = ISafe(payable(msg.sender));
        address safeGuard = abi.decode(safe.getStorageAt(uint256(GUARD_STORAGE_SLOT), 1), (address));
        require(safeGuard == address(GUARD), "Safe must use the one-time signer guard");

        (address key, bytes32 r, bytes32 s, uint8 v, bytes32[] memory proof) =
            abi.decode(_signature, (address, bytes32, bytes32, uint8, bytes32[]));
        require(uint256(s) <= SECP256K1N_HALF, "Invalid signature s value");
        bytes32 digest = _hash;
        if (v > 30) {
            digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _hash));
            v -= 4;
        }
        require(key != address(0) && ecrecover(digest, v, r, s) == key, "Invalid key signature");
        require(isKeyInPool(key, proof), "Key not in pool");
        require(!GUARD.isKeyUsed(msg.sender, key), "Key already used");
        return EIP1271_MAGIC_VALUE;
    }

    /// @notice Returns whether `key` is in the pool, given its Merkle proof.
    function isKeyInPool(address key, bytes32[] memory proof) public view returns (bool) {
        bytes32 computedHash = keccak256(abi.encodePacked(keccak256(abi.encode(key))));
        for (uint256 i = 0; i < proof.length; ++i) {
            bytes32 proofElement = proof[i];
            computedHash = computedHash < proofElement
                ? keccak256(abi.encodePacked(computedHash, proofElement))
                : keccak256(abi.encodePacked(proofElement, computedHash));
        }
        return computedHash == KEYS_ROOT;
    }
}
