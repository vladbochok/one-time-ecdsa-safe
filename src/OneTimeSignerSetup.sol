// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import {ISafe} from "@safe-global/safe-smart-account/contracts/interfaces/ISafe.sol";

/**
 * @title OneTimeSignerSetup - Enables {OneTimeSignerGuard} during `Safe.setup`.
 * @notice Pass as `to` with `enableGuard(guard)` as `data`. Vaults only sign for Safes with the guard, so it is set from the start.
 * @dev Calls `setGuard` on `address(this)`, so the setup data doesn't need the not yet known Safe address.
 */
contract OneTimeSignerSetup {
    address private immutable SELF;

    constructor() {
        SELF = address(this);
    }

    /// @notice Enables `guard` on the calling Safe. Must be delegatecalled.
    function enableGuard(address guard) external {
        require(address(this) != SELF, "Must be delegatecalled");
        ISafe(payable(address(this))).setGuard(guard);
    }
}
