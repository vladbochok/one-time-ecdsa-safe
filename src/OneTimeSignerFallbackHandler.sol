// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import {TokenCallbackHandler} from "@safe-global/safe-smart-account/contracts/handler/TokenCallbackHandler.sol";
import {ISafe} from "@safe-global/safe-smart-account/contracts/interfaces/ISafe.sol";
import {ISignatureValidator} from "@safe-global/safe-smart-account/contracts/interfaces/ISignatureValidator.sol";

/**
 * @title OneTimeSignerFallbackHandler - Fallback handler that only accepts messages signed on-chain.
 * @notice The default fallback handlers also accept owner signatures in `isValidSignature`. That check is a view call, so a
 *         one-time key used there would be exposed without ever being burned. This handler only accepts messages marked as
 *         signed by {SignMessageLib}, which runs as a Safe transaction and therefore goes through {OneTimeSignerGuard}.
 * @dev Unlike {CompatibilityFallbackHandler}, it does not provide `simulate` or the legacy encoding helpers.
 */
contract OneTimeSignerFallbackHandler is TokenCallbackHandler, ISignatureValidator {
    // keccak256("SafeMessage(bytes message)")
    bytes32 private constant SAFE_MSG_TYPEHASH = 0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca;

    /**
     * @notice Implementation of the EIP-1271 signature validation method for the calling Safe.
     * @dev Only the empty signature is accepted, meaning the message must have been signed on-chain.
     * @param _dataHash Hash of the data signed.
     * @param _signature Signature data, must be empty.
     * @return The EIP-1271 magic value if the message was signed on-chain, reverts otherwise.
     */
    function isValidSignature(bytes32 _dataHash, bytes calldata _signature) external view override returns (bytes4) {
        require(_signature.length == 0, "Only on-chain signed messages are supported");
        // Caller should be a Safe.
        ISafe safe = ISafe(payable(msg.sender));
        require(safe.signedMessages(getMessageHashForSafe(safe, abi.encode(_dataHash))) != 0, "Hash not approved");
        return EIP1271_MAGIC_VALUE;
    }

    /**
     * @dev Returns the hash of a message for a Safe, as computed by {SignMessageLib}.
     * @param safe Safe to which the message is targeted.
     * @param message Message that should be hashed.
     * @return Message hash.
     */
    function getMessageHashForSafe(ISafe safe, bytes memory message) public view returns (bytes32) {
        bytes32 safeMessageHash = keccak256(abi.encode(SAFE_MSG_TYPEHASH, keccak256(message)));
        return keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), safe.domainSeparator(), safeMessageHash));
    }
}
