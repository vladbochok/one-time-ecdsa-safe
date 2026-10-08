# pq-ready-safe

One-time signer keys for [Safe](https://github.com/safe-global/safe-smart-account) multisigs, so a Safe keeps operating if
ECDSA gets broken, whether by a quantum computer or by a new classical algorithm.

> [!WARNING]
> Unaudited research code.

## The problem

Safe owners sign with ECDSA. Every signature reveals the signer's public key, and a regular owner reuses the same key for
years, so their public key sits on-chain long before anyone can attack it.

If quantum computers, or an algorithm found by a superintelligent AI, ever break ECDSA, an attacker could derive the owners' keys
from those public keys and drain a multisig holding millions of dollars.

## The approach

The complete fix is a different signature scheme, such as post-quantum signatures, but verifying those on the EVM is still very
expensive. This project uses one-time ECDSA keys instead:

- Each signer derives a pool of addresses from their seed. An address is only a hash of a public key, so before a key signs there
  is nothing to attack.
- The Safe accepts each address only once. As soon as a key signs, it is marked as used, and the Safe never accepts another
  signature from that address.
- Breaking a key takes time once its public key is exposed. By then the signed transaction is already on-chain and the key is
  dead. So the Safe keeps operating even if ECDSA keys can be broken in days or hours.

It's not a complete solution, but it lets a critical multisig be prepared for the day ECDSA breaks.

## Rules for signers

These matter as much as the contracts:

- Use the addresses **only for this multisig**: never send a transaction from them, and never reuse them on another Safe or chain.
- Derive them on hardened paths and never share the extended public key (xpub) of that branch.
- Collect signatures privately and execute them quickly: a key is exposed from the moment its signature is shared until the
  transaction executes. An attacker would have to break `threshold` keys within that window.

## Design

Each signer has a vault, a Safe owner that commits to their pool of addresses with a Merkle root. A guard burns every key that
signs, in the same transaction. There is no module and no change to Safe.

| Contract | Role |
|---|---|
| `OneTimeSignerVault` | Safe owner (EIP-1271). Accepts a signature from an unused key in its pool. One per signer, so the threshold still counts people. |
| `OneTimeSignerGuard` | Transaction guard. Burns each signing key and rejects extra signatures, which would expose keys without burning them. |
| `OneTimeSignerFallbackHandler` | Accepts only messages signed on-chain, because off-chain signatures can't burn keys. |
| `OneTimeSignerSetup` | Enables the guard during `Safe.setup`. |

To rotate a pool, swap in a new vault with `swapOwner`. Replacing the ECDSA keys with hash-based one-time keys (e.g. WOTS+) would
remove the dependency on ECDSA entirely.

## Usage

```shell
git clone --recursive https://github.com/vladbochok/pq-ready-safe.git && cd pq-ready-safe
forge test
```

LGPL-3.0, like Safe.
