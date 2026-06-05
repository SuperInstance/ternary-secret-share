# ternary-secret-share

Secret sharing schemes over GF(3) / Z/3Z.

## Schemes
- `ShamirZ3` — (k, n) threshold Shamir sharing using polynomial interpolation over Z/3Z
- `AdditiveZ3` — n-out-of-n additive sharing (sum mod 3)
- `VerifiableZ3` — additive sharing with per-share commitments for tamper detection

## Usage
```rust
// 2-of-2 Shamir over Z/3Z
let s = ShamirZ3::new(2, 2);
let shares = s.split(1, &[2]); // secret=1, random coeff=2
assert_eq!(s.recover(&shares), 1);

// Additive with verification
let v = VerifiableZ3::new(3);
let (shares, comms) = v.split(2, &[1, 0]);
assert_eq!(v.recover(&shares, &comms), Some(2));
```
