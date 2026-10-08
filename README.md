# pq-ready-safe

One-time signer keys for [Safe](https://github.com/safe-global/safe-smart-account) multisigs. Every owner key signs exactly one
transaction or message and is then burned. Until that single use, only the key's address is public, never its public key.

> [!WARNING]
> Unaudited research code. Do not use it to secure real funds.

## What "PQ-ready" means here

An Ethereum address is a hash of a public key, and every ECDSA signature reveals the public key it was made with. A quantum
attacker running Shor's algorithm needs that public key to recover the private key. A regular Safe owner reuses one key for
years, so its public key is on-chain from its first signature onwards.

Here, each key signs once and is burned in the same transaction. Before its use, only a hash commits to it.

This is **not** post-quantum cryptography yet:

- A signature exposes its key as soon as it is shared: in a transaction service, in the mempool, or in a reverted transaction.
  The key is only burned when the transaction executes. An attacker able to break ECDSA within that window, for `threshold`
  keys, could still sign something else. Collect and submit signatures privately to keep the window short.
- The vault verifies ECDSA leaves today. Replacing them with hash-based one-time signatures (e.g. WOTS+) is what would make the
  scheme post-quantum. The guard only needs a key identifier from each signature, so that change mainly affects the vault's
  verification.

## How it works

| Contract | Role |
|---|---|
| [`OneTimeSignerVault`](src/OneTimeSignerVault.sol) | One per human signer, set as a Safe owner, so the threshold keeps counting humans. Immutable. Commits to a pool of one-time key addresses with a Merkle root and validates a key signature plus a Merkle proof. Refuses to sign for a Safe that does not use the guard. |
| [`OneTimeSignerGuard`](src/OneTimeSignerGuard.sol) | Shared Safe transaction guard. Before execution, burns the key behind each vault signature for the calling Safe, and rejects anything but exactly `threshold` vault signatures. `revokeKeys` burns keys whose signatures were shared but never executed. |
| [`OneTimeSignerFallbackHandler`](src/OneTimeSignerFallbackHandler.sol) | Answers EIP-1271 `isValidSignature` only for messages signed on-chain, since off-chain owner signatures could not be burned. |
| [`OneTimeSignerSetup`](src/OneTimeSignerSetup.sol) | Enables the guard during `Safe.setup`, so the Safe is protected from its first transaction. |

1. Each signer derives a pool of keys, builds a Merkle tree of their addresses, and deploys a vault with its root.
2. The Safe is deployed with the vaults as owners, the guard enabled during setup, and the fallback handler.
3. To sign a Safe transaction, a signer picks an unused key, signs the Safe transaction hash with it, and attaches the key address
   and its Merkle proof.
4. The Safe checks every vault signature, then the guard burns every key that signed, before the transaction executes.

There is no module and no change to the Safe contracts.

### Signature format

A vault signature is a regular Safe contract signature (`v = 0`) whose data is:

```solidity
abi.encode(address key, bytes32 r, bytes32 s, uint8 v, bytes32[] proof)
```

- `v` is 27/28 for a signature of the Safe transaction hash (EIP-712), or 31/32 for an `eth_sign` signature, as in Safe.
- `s` must be in the lower half of the curve.
- Leaves are `keccak256(bytes.concat(keccak256(abi.encode(key))))` and inner nodes hash sorted pairs, which is the encoding of
  OpenZeppelin's [`StandardMerkleTree`](https://github.com/OpenZeppelin/merkle-tree) with `["address"]` leaves.
- The signatures of a transaction must be exactly `threshold` vault signatures in the layout the Safe tooling produces: static
  parts sorted by owner, then the dynamic parts in the same order, without trailing bytes.

### Deploying a Safe

```solidity
bytes memory initializer = abi.encodeCall(
    ISafe.setup,
    (
        vaults,
        threshold,
        address(oneTimeSignerSetup),
        abi.encodeCall(OneTimeSignerSetup.enableGuard, (address(guard))),
        address(fallbackHandler),
        address(0),
        0,
        payable(address(0))
    )
);
factory.createProxyWithNonce(safeSingleton, initializer, saltNonce);
```

An existing Safe can migrate in one transaction signed by its current owners: a MultiSend batch calling `setGuard`,
`setFallbackHandler`, and `swapOwner` for each owner. See `test_migration_MovesExistingSafeToVaults`.

### Day-to-day operations

- **New pool:** deploy a new vault and replace the old one with `swapOwner`.
- **Abandoned signatures:** call `guard.revokeKeys(keys)` through a Safe transaction.
- **Messages:** sign them on-chain with `SignMessageLib` (delegatecall). The Safe then accepts `isValidSignature(hash, "")`.
- **Monitoring:** `KeyUsed(safe, vault, key)` and `KeyRevoked(safe, key)` give the remaining keys per vault. The owner set only
  changes on rotation, so owner-change alerts stay meaningful.

### Operational requirements

- Derive every one-time key on a hardened path and never export the extended public key of that branch. With non-hardened
  derivation, one recovered child key plus the chain code reveals every sibling key.
- Use unique keys per Safe and per chain, and one vault per Safe: used keys are tracked per Safe.
- Never send an Ethereum transaction from a one-time key, and do not use the public Safe Transaction Service, which publishes
  collected signatures.
- Re-root before a pool runs out: the rotation transaction itself needs keys.

## Limitations

- Removing the guard disables every vault. A transaction that removes it must also swap the vaults out.
- The guard has no fallback function, unlike Safe's example guards. If a future Safe version calls a different guard hook,
  transactions revert until the guard is replaced, which the upgrade transaction must do.
- The fallback handler provides `isValidSignature` and token callbacks only. It drops `simulate`, which Safe tooling uses for
  gas estimation.
- A contract calling `safe.checkSignatures` directly performs a read-only check that cannot burn keys. Signers should only ever
  sign Safe transactions.
- Not tested on ZKsync (EraVM).

## Gas

| | Gas |
|---|---|
| `execTransaction`, 2-of-3 with vaults (256-key pools) | 148,159 |
| `execTransaction`, 2-of-3 with EOA owners | 44,699 |
| Vault deployment | 615,006 |
| Guard deployment (once per chain) | 551,827 |

Execution gas only, without the 21,000 base cost and calldata. Measured with solc 0.8.30 and 200 optimizer runs. With 256-key
pools, the two vault signatures add 1,090 bytes of calldata.

## Development

```shell
git clone --recursive https://github.com/vladbochok/pq-ready-safe.git
cd pq-ready-safe
forge build
forge test
# Same compiler as Safe v1.5.0
forge build --use 0.7.6 --out out-0.7.6 --cache-path cache-0.7.6 src
```

The tests run every case against both `Safe` and `SafeL2` v1.5.0, pinned in `lib/safe-smart-account`.

## License

[LGPL-3.0](LICENSE), like the Safe smart account contracts it builds on.
