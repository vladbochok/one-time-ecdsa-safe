// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import {ISafe} from "@safe-global/safe-smart-account/contracts/interfaces/ISafe.sol";

/**
 * @title OneTimeSignerSetup - Enables {OneTimeSignerGuard} while a Safe is being set up.
 * @notice {OneTimeSignerVault}s refuse to sign for a Safe without the guard, so a Safe owned by vaults must have the guard
 *         from the start. Pass this contract as `to` and `enableGuard(guard)` as `data` to `Safe.setup`.
 * @dev The Safe delegatecalls `enableGuard` during setup, which then calls `setGuard` on the Safe itself. Using
 *      `address(this)` avoids having to know the Safe address when building the setup data, which would be circular when
 *      the Safe is deployed through `SafeProxyFactory` with an initializer.
 */
contract OneTimeSignerSetup {
    address private immutable SELF;

    constructor() {
        SELF = address(this);
    }

    /**
     * @notice Enables `guard` on the calling Safe. Must be delegatecalled by the Safe, typically from `Safe.setup`.
     * @param guard Address of the {OneTimeSignerGuard}.
     */
    function enableGuard(address guard) external {
        require(address(this) != SELF, "Must be delegatecalled");
        ISafe(payable(address(this))).setGuard(guard);
    }
}
