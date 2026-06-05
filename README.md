# ternary-secret-share

**Secret sharing over Z₃: split a ternary secret into shares, reconstruct from a threshold.**

Shamir's secret sharing scheme works over any finite field. Over GF(3), the arithmetic is trivially simple — all operations fit in one byte, no bignum needed. A (K, N) scheme splits a secret into N shares, and any K shares can reconstruct it. Fewer than K shares reveal *nothing*.

---

## The Mathematics

A (K, N) Shamir scheme over GF(3):
1. Choose a random polynomial `f(x) = a₀ + a₁x + a₂x² + ... + aₖ₋₁xᵏ⁻¹` over GF(3)
2. The secret is `a₀ = f(0)`
3. Share i is `(i, f(i) mod 3)` for i = 1, 2, ..., N
4. Reconstruct using Lagrange interpolation: `f(0) = Σ f(iⱼ) · Π (0-iₘ)/(iⱼ-iₘ) mod 3`

The reconstruction works because a degree-(K-1) polynomial is uniquely determined by K points. Any fewer than K points are consistent with any secret value.

---

## Architecture

- **`ShamirZ3`** — (K, N) Shamir secret sharing over GF(3)
- **`AdditiveZ3`** — Split secret into additive shares: sum of shares mod 3 = secret
- **`Commitment`** — Hash-based commitments for share verification
- **`VerifiableZ3`** — Verifiable secret sharing with consistency checks

---

## Quick Start

```rust
use ternary_secret_share::{ShamirZ3, AdditiveZ3};

// Shamir (3, 5): any 3 of 5 shares reconstruct
let secret = 1; // ∈ {0, 1, 2}
let shares = ShamirZ3::split(secret, 3, 5, 42);

// Reconstruct from any 3 shares
let reconstructed = ShamirZ3::reconstruct(&[shares[0], shares[2], shares[4]]);
assert_eq!(reconstructed, secret);

// Additive: 3 shares summing to secret mod 3
let (s1, s2, s3) = AdditiveZ3::split(1);
assert_eq!(((s1 + s2 + s3) % 3 + 3) % 3, 1);
```

---

## Ecosystem

- **ternary-zkp** — ZK proofs on GF(3) fields
- **ternary-blockchain** — Ternary blockchain primitives
- **ternary-hash** — Ternary hash functions
- **ternary-crypto** — Cryptographic primitives for ternary

## License

MIT
