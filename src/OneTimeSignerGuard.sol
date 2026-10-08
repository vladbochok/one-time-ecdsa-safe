// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import {BaseTransactionGuard, ITransactionGuard} from "@safe-global/safe-smart-account/contracts/base/GuardManager.sol";
import {BaseModuleGuard, IModuleGuard} from "@safe-global/safe-smart-account/contracts/base/ModuleManager.sol";
import {SignatureDecoder} from "@safe-global/safe-smart-account/contracts/common/SignatureDecoder.sol";
import {SafeMath} from "@safe-global/safe-smart-account/contracts/external/SafeMath.sol";
import {IERC165} from "@safe-global/safe-smart-account/contracts/interfaces/IERC165.sol";
import {ISafe} from "@safe-global/safe-smart-account/contracts/interfaces/ISafe.sol";
import {Enum} from "@safe-global/safe-smart-account/contracts/libraries/Enum.sol";

/**
 * @title OneTimeSignerGuard - Burns every one-time key that signs a Safe transaction.
 * @notice For Safes owned by {OneTimeSignerVault}s. Rejects anything but exactly `threshold` vault signatures, since an extra
 *         signature would expose a key without burning it. As module guard, rejects module transactions, which need no
 *         owner signature at all.
 * @dev Used keys are tracked per caller, so direct calls only burn the caller's own keys. No fallback: fails closed.
 */
contract OneTimeSignerGuard is BaseTransactionGuard, BaseModuleGuard, SignatureDecoder {
    using SafeMath for uint256;

    // Safe => one-time key => used
    mapping(address => mapping(address => bool)) public isKeyUsed;

    event KeyUsed(address indexed safe, address indexed vault, address indexed key);
    event KeyRevoked(address indexed safe, address indexed key);

    function supportsInterface(bytes4 interfaceId) external view virtual override(BaseTransactionGuard, BaseModuleGuard) returns (bool) {
        return interfaceId == type(ITransactionGuard).interfaceId || interfaceId == type(IModuleGuard).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }

    /**
     * @dev Expects `threshold` contract signatures followed by their dynamic parts in order, with nothing after.
     *      The Safe has already verified each vault signature, so the key it declares is authentic.
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

    function checkAfterExecution(bytes32, bool) external view override {}

    function checkModuleTransaction(address, uint256, bytes memory, Enum.Operation, address) external pure override returns (bytes32) {
        revert("Module transactions are disabled");
    }

    function checkAfterModuleExecution(bytes32, bool) external view override {}

    /// @notice Burns keys of the calling Safe, e.g. keys whose signatures were shared but never executed.
    function revokeKeys(address[] calldata keys) external {
        for (uint256 i = 0; i < keys.length; ++i) {
            isKeyUsed[msg.sender][keys[i]] = true;
            emit KeyRevoked(msg.sender, keys[i]);
        }
    }

    /// @dev Returns the length of the dynamic part at `offset` and the key in its first word.
    function readDynamicPart(bytes memory signatures, uint256 offset) private pure returns (uint256 length, address key) {
        require(offset.add(64) <= signatures.length, "Signatures must encode exactly threshold vault signatures");
        uint256 keyWord;
        /// @solidity memory-safe-assembly
        assembly {
            length := mload(add(add(signatures, offset), 0x20))
            keyWord := mload(add(add(signatures, offset), 0x40))
        }
        require(length >= 32, "Signatures must encode exactly threshold vault signatures");
        // Matches how the vault decodes this word.
        // forge-lint: disable-next-line(unsafe-typecast)
        key = address(uint160(keyWord));
    }

    function useKey(address vault, address key) private {
        require(!isKeyUsed[msg.sender][key], "Key already used");
        isKeyUsed[msg.sender][key] = true;
        emit KeyUsed(msg.sender, vault, key);
    }
}
