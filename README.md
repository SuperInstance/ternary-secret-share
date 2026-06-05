# ternary-secret-share

> Secret sharing schemes over the prime field $\mathbb{Z}/3\mathbb{Z}$ (GF(3)).

---

## What problem does this solve?

Secret sharing allows a sensitive value to be distributed among $n$ parties so that no coalition smaller than a threshold $k$ can reconstruct it.  This crate provides **threshold** and **additive** sharing schemes over the prime field $\mathbb{Z}/3\mathbb{Z}$ (GF(3)).  The cryptographic motivation is pedagogical: by working over the smallest non-trivial field, students can trace every arithmetic step by hand, verify Lagrange interpolation in a three-element universe, and understand how verifiable commitments protect against malicious dealers.  The schemes are fully functional for toy parameters (e.g. $(2,2)$ sharing) and serve as a reference implementation before scaling to larger prime fields.

---

## Mathematical foundations

### $\mathbb{Z}/3\mathbb{Z}$ (GF(3))

The ring of integers modulo 3 is a field because 3 is prime.  Its elements are $\{0,1,2\}$.

- **Addition / subtraction**: performed modulo 3.
- **Multiplication**: ordinary integer product modulo 3.
- **Inverses**: $1^{-1} = 1$ and $2^{-1} = 2$ because $2 \cdot 2 = 4 \equiv 1 \pmod 3$.

Every non-zero element is its own inverse, which simplifies manual verification.

### Shamir secret sharing

A secret $s \in \mathbb{Z}/3\mathbb{Z}$ is encoded as the constant term of a random degree-$(k-1)$ polynomial

$$f(x) = s + a_1 x + a_2 x^2 + \dots + a_{k-1} x^{k-1}.$$

Share $i$ is the pair $(x_i, f(x_i))$ where $x_i$ is a non-zero field element.  Because $\mathbb{Z}/3\mathbb{Z}$ contains only two non-zero points ($1$ and $2$), the crate natively supports $(2,2)$ and $(1,2)$ thresholds.

**Recovery** uses **Lagrange interpolation** at $x = 0$:

$$s = f(0) = \sum_{i} y_i \cdot \lambda_i, \qquad
\lambda_i = \prod_{j \neq i} \frac{0 - x_j}{x_i - x_j}.$$

All divisions are multiplications by the modular inverse in $\mathbb{Z}/3\mathbb{Z}$.

### Additive sharing

An **$n$-out-of-$n$** scheme where the secret is the sum modulo 3 of $n$ random shares:

$$s = \sum_{i=1}^{n} \text{share}_i \pmod 3.$$

Any $n-1$ shares are uniformly random and information-theoretically independent of $s$.  Reconstruction simply adds all shares.

### Verifiable secret sharing (VSS)

Each share is accompanied by a **commitment tag**.  Before reconstruction the dealer (or the parties) verify that every share matches its tag; a tampered share aborts recovery.  The toy commitment used here is deterministic and designed for correctness testing—production code should replace it with a cryptographically secure hash or Pedersen commitment.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Z/3Z Arithmetic Layer                      │
│  z3_add | z3_sub | z3_mul | z3_inv | z3_div                │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌─────────────────┐    ┌─────────────┐
│   ShamirZ3    │    │   AdditiveZ3    │    │ VerifiableZ3│
│ (k,n) threshold│   │  n-out-of-n sum │    │ Additive +  │
│ split(secret) │    │ split(secret)   │    │ Commitments │
│ recover(shares)│   │ recover(shares) │    │ verify + rec│
└───────────────┘    └─────────────────┘    └─────────────┘
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌─────────────────┐    ┌─────────────┐
│ poly_eval     │    │  sum mod 3      │    │  Commitment │
│ lagrange_at_0 │    │                 │    │  tag check  │
└───────────────┘    └─────────────────┘    └─────────────┘
```

---

## Getting Started

Add to `Cargo.toml`:

```toml
[dependencies]
ternary-secret-share = { path = "." }
```

```rust
use ternary_secret_share::*;

fn main() {
    // 1. Shamir (2,2) over Z/3Z
    let shamir = ShamirZ3::new(2, 2);
    let shares = shamir.split(1, &[2]); // secret=1, random coeff=2
    let recovered = shamir.recover(&shares);
    assert_eq!(recovered, 1);
    println!("Shamir secret recovered: {}", recovered);

    // 2. Additive 3-out-of-3
    let add = AdditiveZ3::new(3);
    let shares = add.split(2, &[1, 0]); // randoms for shares 1 and 2
    assert_eq!(add.recover(&shares), 2);
    println!("Additive secret recovered: {}", add.recover(&shares));

    // 3. Verifiable sharing
    let vss = VerifiableZ3::new(3);
    let (shares, comms) = vss.split(2, &[1, 0]);
    assert_eq!(vss.recover(&shares, &comms), Some(2));
    println!("VSS recovery succeeded.");
}
```

Run it:

```bash
cargo run --example demo
```

---

## Running the Tests

The crate contains **14 tests**.  Each test demonstrates a specific algebraic or security invariant:

| Test | What it proves |
|------|----------------|
| `z3_arithmetic` | Correctness of addition, subtraction, multiplication, inversion, and division modulo 3. |
| `poly_eval_constant` | A degree-0 polynomial evaluates to its constant term for every $x \in \{0,1,2\}$. |
| `poly_eval_linear` | A line evaluates correctly at the non-zero points used for share generation. |
| `shamir_2_2_roundtrip_secret_0` | Shamir splitting and reconstruction succeeds for secret $0$. |
| `shamir_2_2_roundtrip_secret_1` | Shamir splitting and reconstruction succeeds for secret $1$. |
| `shamir_2_2_roundtrip_secret_2` | Shamir splitting and reconstruction succeeds for secret $2$. |
| `shamir_1_2_trivial_threshold` | With threshold $1$ the polynomial is constant, so any single share reveals the secret. |
| `additive_3_party_secret_0` | Three-party additive sharing correctly reconstructs secret $0$. |
| `additive_3_party_secret_1` | Three-party additive sharing correctly reconstructs secret $1$. |
| `additive_2_party_all_secrets` | Exhaustive check over all secrets and random masks for $n=2$. |
| `additive_shares_sum_to_secret` | The vector of shares sums (mod 3) to the original secret. |
| `verifiable_split_recover` | Verifiable sharing splits, commits, and recovers without tampering. |
| `verifiable_tampered_share_rejected` | Flipping one share causes commitment verification to fail and recovery returns `None`. |
| `verifiable_verify_each_share` | Individual share/commitment pairs pass the tag check. |

Execute:

```bash
cargo test
```

---

## Related crates

- [ternary-blockchain](https://github.com/SuperInstance/ternary-blockchain) — Trit-based blockchain primitives
- [ternary-zkp](https://github.com/SuperInstance/ternary-zkp) — Zero-knowledge proofs over GF(3)
- [ternary-field](https://github.com/SuperInstance/ternary-field) — General ternary field utilities
- [ternary-proof](https://github.com/SuperInstance/ternary-proof) — Proof systems for ternary circuits

---

## License

MIT
