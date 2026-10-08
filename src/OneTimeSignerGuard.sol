// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import {BaseTransactionGuard} from "@safe-global/safe-smart-account/contracts/base/GuardManager.sol";
import {SignatureDecoder} from "@safe-global/safe-smart-account/contracts/common/SignatureDecoder.sol";
import {SafeMath} from "@safe-global/safe-smart-account/contracts/external/SafeMath.sol";
import {ISafe} from "@safe-global/safe-smart-account/contracts/interfaces/ISafe.sol";
import {Enum} from "@safe-global/safe-smart-account/contracts/libraries/Enum.sol";

/**
 * @title OneTimeSignerGuard - Burns every one-time key that signs a Safe transaction.
 * @notice Intended for Safes whose owners are all {OneTimeSignerVault}s. Before execution, the guard reads the one-time key
 *         behind each vault signature and marks it as used for the calling Safe, so that key can never sign for it again.
 *         It also rejects signature bytes that carry anything beyond exactly `threshold` vault signatures: any extra
 *         signature would expose a key on-chain without burning it.
 * @dev The used-key registry is namespaced by `msg.sender`. Calling `checkTransaction` or `revokeKeys` directly only writes
 *      to the caller's own namespace, so pending signatures cannot be used to burn another Safe's keys.
 *      Unlike the other example guards, this guard has no fallback function: if a future Safe version calls a different
 *      hook, transactions revert instead of silently skipping key burning.
 */
contract OneTimeSignerGuard is BaseTransactionGuard, SignatureDecoder {
    using SafeMath for uint256;

    // Safe => one-time key => used
    mapping(address => mapping(address => bool)) public isKeyUsed;

    event KeyUsed(address indexed safe, address indexed vault, address indexed key);
    event KeyRevoked(address indexed safe, address indexed key);

    /**
     * @notice Called by the Safe contract before a transaction is executed, after its signatures were verified.
     * @dev Requires the signatures to be encoded canonically: `threshold` contract signatures (v = 0) followed by their
     *      dynamic parts in the same order, without gaps or trailing bytes. This is the encoding the Safe tooling produces.
     *      As the Safe already verified each dynamic part with its vault, the key declared in it is authentic.
     * @param signatures Signature data of the Safe transaction.
     */
    function checkTransaction(
        address,
        uint256,
        bytes memory,
        Enum.Operation,
        uint256,
        uint256,
        uint256,
        address,
        // solhint-disable-next-line no-unused-vars
        address payable,
        bytes memory signatures,
        address
    ) external override {
        uint256 threshold = ISafe(payable(msg.sender)).getThreshold();
        uint256 dynamicPartOffset = threshold.mul(65);
        require(signatures.length >= dynamicPartOffset, "Signatures must encode exactly threshold vault signatures");
        for (uint256 i = 0; i < threshold; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = signatureSplit(signatures, i);
            require(v == 0, "Only vault signatures are allowed");
            require(uint256(s) == dynamicPartOffset, "Signatures must encode exactly threshold vault signatures");
            (uint256 length, address key) = readDynamicPart(signatures, dynamicPartOffset);
            useKey(address(uint160(uint256(r))), key);
            dynamicPartOffset = dynamicPartOffset.add(32).add(length);
        }
        require(dynamicPartOffset == signatures.length, "Signatures must encode exactly threshold vault signatures");
    }

    /**
     * @notice Called by the Safe contract after a transaction is executed.
     * @dev No-op: keys are burned before execution.
     */
    function checkAfterExecution(bytes32, bool) external view override {}

    /**
     * @notice Marks one-time keys of the calling Safe as used without them signing a transaction.
     * @dev Meant to be called by the Safe itself, through a Safe transaction, for keys whose signatures were shared for a
     *      transaction that never got executed.
     * @param keys One-time keys to revoke.
     */
    function revokeKeys(address[] calldata keys) external {
        for (uint256 i = 0; i < keys.length; ++i) {
            isKeyUsed[msg.sender][keys[i]] = true;
            emit KeyRevoked(msg.sender, keys[i]);
        }
    }

    /**
     * @dev Reads the dynamic part of a contract signature starting at `offset`.
     *      The one-time key is the first word of the signature data, see {OneTimeSignerVault}.
     * @return length Length of the signature data.
     * @return key One-time key declared in the signature data.
     */
    function readDynamicPart(bytes memory signatures, uint256 offset) private pure returns (uint256 length, address key) {
        require(offset.add(64) <= signatures.length, "Signatures must encode exactly threshold vault signatures");
        uint256 keyWord;
        /* solhint-disable no-inline-assembly */
        /// @solidity memory-safe-assembly
        assembly {
            length := mload(add(add(signatures, offset), 0x20))
            keyWord := mload(add(add(signatures, offset), 0x40))
        }
        /* solhint-enable no-inline-assembly */
        require(length >= 32, "Signatures must encode exactly threshold vault signatures");
        // The vault decodes the same word as an address: ABI coder v2 rejects dirty upper bits, v1 drops them like this cast.
        // forge-lint: disable-next-line(unsafe-typecast)
        key = address(uint160(keyWord));
    }

    function useKey(address vault, address key) private {
        require(!isKeyUsed[msg.sender][key], "Key already used");
        isKeyUsed[msg.sender][key] = true;
        emit KeyUsed(msg.sender, vault, key);
    }
}
