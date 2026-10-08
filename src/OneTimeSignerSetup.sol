// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import {ISafe} from "@safe-global/safe-smart-account/contracts/interfaces/ISafe.sol";
import {OneTimeSignerFallbackHandler} from "./OneTimeSignerFallbackHandler.sol";
import {OneTimeSignerGuard} from "./OneTimeSignerGuard.sol";

/**
 * @title OneTimeSignerSetup - Configures a Safe for one-time signers, at setup or in a migration transaction.
 * @notice Disables every module, sets {GUARD} as transaction and module guard, and sets {FALLBACK_HANDLER}. Doing it in one step
 *         means setup or migration can't skip one of them.
 * @dev Delegatecall `configure()`, e.g. as `to`/`data` of `Safe.setup`. It calls the Safe through `address(this)`, so the setup
 *      data doesn't need the not yet known Safe address.
 */
contract OneTimeSignerSetup {
    address internal constant SENTINEL_MODULES = address(0x1);

    address private immutable SELF;
    OneTimeSignerGuard public immutable GUARD;
    OneTimeSignerFallbackHandler public immutable FALLBACK_HANDLER;

    constructor(OneTimeSignerGuard guard, OneTimeSignerFallbackHandler fallbackHandler) {
        require(address(guard) != address(0), "Invalid guard");
        require(address(fallbackHandler) != address(0), "Invalid fallback handler");
        SELF = address(this);
        GUARD = guard;
        FALLBACK_HANDLER = fallbackHandler;
    }

    /// @notice Configures the calling Safe. Must be delegatecalled.
    function configure() external {
        require(address(this) != SELF, "Must be delegatecalled");
        ISafe safe = ISafe(payable(address(this)));
        (address[] memory modules,) = safe.getModulesPaginated(SENTINEL_MODULES, 1);
        while (modules.length != 0) {
            safe.disableModule(SENTINEL_MODULES, modules[0]);
            (modules,) = safe.getModulesPaginated(SENTINEL_MODULES, 1);
        }
        safe.setGuard(address(GUARD));
        safe.setModuleGuard(address(GUARD));
        safe.setFallbackHandler(address(FALLBACK_HANDLER));
    }
}
