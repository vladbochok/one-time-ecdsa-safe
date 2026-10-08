# pq-ready-safe

One-time signer keys for [Safe](https://github.com/safe-global/safe-smart-account) multisigs. Every owner key signs exactly once,
so its public key is never exposed long-term: until its single use, only its address (a hash) is public.

> [!WARNING]
> Unaudited research code.

## Design

Each signer has a **vault**, a Safe owner that commits to a pool of one-time ECDSA keys with a Merkle root. To sign, the signer
uses an unused key and attaches its Merkle proof. A **guard** burns every key that signs, in the same transaction.

| Contract | Role |
|---|---|
| `OneTimeSignerVault` | Safe owner (EIP-1271). Accepts a signature from an unused key in its pool. One per signer, so the threshold still counts people. |
| `OneTimeSignerGuard` | Transaction guard. Burns each signing key and rejects extra signatures, which would expose keys without burning them. |
| `OneTimeSignerFallbackHandler` | Accepts only messages signed on-chain, because off-chain signatures can't burn keys. |
| `OneTimeSignerSetup` | Enables the guard during `Safe.setup`. |

No module and no Safe changes. To rotate a pool, swap in a new vault with `swapOwner`.

It is not post-quantum yet: a key is exposed from the moment its signature is shared until execution burns it, and the keys are
ECDSA. Hash-based one-time keys (e.g. WOTS+) would remove both limits.

## Usage

```shell
git clone --recursive https://github.com/vladbochok/pq-ready-safe.git && cd pq-ready-safe
forge test
```

LGPL-3.0, like Safe.
