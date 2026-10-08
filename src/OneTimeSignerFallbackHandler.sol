// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import {TokenCallbackHandler} from "@safe-global/safe-smart-account/contracts/handler/TokenCallbackHandler.sol";
import {ISafe} from "@safe-global/safe-smart-account/contracts/interfaces/ISafe.sol";
import {ISignatureValidator} from "@safe-global/safe-smart-account/contracts/interfaces/ISignatureValidator.sol";

/**
 * @title OneTimeSignerFallbackHandler - Fallback handler accepting only messages signed on-chain.
 * @notice Off-chain owner signatures are checked in a view call, where keys can't be burned. Messages signed with
 *         {SignMessageLib} go through a Safe transaction, and therefore through {OneTimeSignerGuard}.
 */
contract OneTimeSignerFallbackHandler is TokenCallbackHandler, ISignatureValidator {
    // keccak256("SafeMessage(bytes message)")
    bytes32 private constant SAFE_MSG_TYPEHASH = 0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca;

    /// @notice EIP-1271 check for the calling Safe. Only the empty signature, meaning signed on-chain, is accepted.
    function isValidSignature(bytes32 _dataHash, bytes calldata _signature) external view override returns (bytes4) {
        require(_signature.length == 0, "Only on-chain signed messages are supported");
        ISafe safe = ISafe(payable(msg.sender));
        require(safe.signedMessages(getMessageHashForSafe(safe, abi.encode(_dataHash))) != 0, "Hash not approved");
        return EIP1271_MAGIC_VALUE;
    }

    /// @dev Message hash as computed by {SignMessageLib}.
    function getMessageHashForSafe(ISafe safe, bytes memory message) public view returns (bytes32) {
        bytes32 safeMessageHash = keccak256(abi.encode(SAFE_MSG_TYPEHASH, keccak256(message)));
        return keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), safe.domainSeparator(), safeMessageHash));
    }
}
