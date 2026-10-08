// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import {ISafe} from "@safe-global/safe-smart-account/contracts/interfaces/ISafe.sol";
import {ISignatureValidator} from "@safe-global/safe-smart-account/contracts/interfaces/ISignatureValidator.sol";
import {OneTimeSignerGuard} from "./OneTimeSignerGuard.sol";

/**
 * @title OneTimeSignerVault - A Safe owner backed by a pool of one-time ECDSA keys.
 * @notice One vault represents one human signer and is added to the Safe as an owner, so the Safe threshold keeps counting
 *         humans. The vault commits to its pool of keys with a Merkle root: before a key is used only its address (a hash of
 *         its public key) is known, and its public key is revealed by the single signature it ever produces.
 *         {OneTimeSignerGuard} burns each key as soon as it signs a Safe transaction.
 * @dev The vault is immutable. To move to a new pool, deploy a new vault and replace the old one with `swapOwner`.
 *      Signature data (the dynamic part of a Safe contract signature):
 *          `abi.encode(address key, bytes32 r, bytes32 s, uint8 v, bytes32[] proof)`
 *      - `key` must stay the first word: {OneTimeSignerGuard} reads it from there.
 *      - `v` is 27/28 for a signature over the hash itself, or 31/32 for an `eth_sign` signature (same convention as the Safe).
 *      - Leaves are `keccak256(bytes.concat(keccak256(abi.encode(key))))` and inner nodes hash sorted pairs, which matches
 *        OpenZeppelin's `StandardMerkleTree` for the `["address"]` leaf encoding.
 *      Keys must be unique per Safe and per chain, and a vault must be an owner of a single Safe: used keys are tracked per Safe.
 */
contract OneTimeSignerVault is ISignatureValidator {
    // keccak256("guard_manager.guard.address")
    bytes32 internal constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    // Half of the secp256k1 curve order, upper bound for non-malleable `s` values.
    uint256 internal constant SECP256K1N_HALF = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    bytes32 public immutable KEYS_ROOT;
    OneTimeSignerGuard public immutable GUARD;

    /**
     * @param keysRoot Merkle root of the one-time key addresses.
     * @param guard Guard that burns the keys. The vault only signs for Safes that use it.
     */
    constructor(bytes32 keysRoot, OneTimeSignerGuard guard) {
        require(keysRoot != bytes32(0), "Invalid keys root");
        require(address(guard) != address(0), "Invalid guard");
        KEYS_ROOT = keysRoot;
        GUARD = guard;
    }

    /**
     * @notice Validates a signature of `_hash` by an unused one-time key from the pool, on behalf of the calling Safe.
     * @dev Reverts instead of returning a non-magic value, so the reason surfaces in the Safe transaction.
     *      Refuses to sign for a Safe that does not use {GUARD}: without it, keys would not be burned.
     * @param _hash Hash signed by the one-time key, usually a Safe transaction hash.
     * @param _signature Signature data, see the contract documentation for the encoding.
     * @return The EIP-1271 magic value.
     */
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

    /**
     * @notice Returns whether `key` is part of the vault's pool.
     * @param key One-time key address.
     * @param proof Merkle proof of the key's leaf.
     */
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
