//! Secret sharing schemes over GF(3) (Z/3Z) and related fields.
//!
//! * `ShamirZ3`       — Shamir (k,n) threshold sharing over Z/3Z (prime 3)
//! * `AdditiveZ3`     — n-out-of-n additive XOR-style sharing over Z/3Z
//! * `VerifiableZ3`   — Additive shares with hash commitments for verification

use std::collections::HashMap;

// ── Z/3Z arithmetic ──────────────────────────────────────────────────────────

/// Element of Z/3Z: 0, 1, or 2.
pub type Z3 = u8;

fn z3_add(a: Z3, b: Z3) -> Z3 { (a + b) % 3 }
fn z3_sub(a: Z3, b: Z3) -> Z3 { (3 + a - b) % 3 }
fn z3_mul(a: Z3, b: Z3) -> Z3 { (a * b) % 3 }

/// Multiplicative inverse in Z/3Z (panics for 0).
fn z3_inv(a: Z3) -> Z3 {
    match a {
        1 => 1,
        2 => 2,
        _ => panic!("no inverse for 0 in Z3"),
    }
}

fn z3_div(a: Z3, b: Z3) -> Z3 { z3_mul(a, z3_inv(b)) }

// ── Polynomial evaluation over Z/3Z ─────────────────────────────────────────

/// Evaluate polynomial with `coeffs[0]` as constant term at `x`.
fn poly_eval(coeffs: &[Z3], x: Z3) -> Z3 {
    let mut result = 0u8;
    let mut power = 1u8;
    for &c in coeffs {
        result = z3_add(result, z3_mul(c, power));
        power = z3_mul(power, x);
    }
    result
}

// ── Lagrange interpolation over Z/3Z ─────────────────────────────────────────

/// Recover f(0) given `shares` = [(x_i, y_i)] using Lagrange interpolation in Z/3Z.
fn lagrange_at_zero(shares: &[(Z3, Z3)]) -> Z3 {
    let mut result = 0u8;
    for (i, &(xi, yi)) in shares.iter().enumerate() {
        let mut num = 1u8;
        let mut den = 1u8;
        for (j, &(xj, _)) in shares.iter().enumerate() {
            if i != j {
                // numerator: product of (0 - xj) = (-xj) = (3 - xj) % 3
                num = z3_mul(num, z3_sub(0, xj));
                den = z3_mul(den, z3_sub(xi, xj));
            }
        }
        let term = z3_mul(yi, z3_div(num, den));
        result = z3_add(result, term);
    }
    result
}

// ── Shamir Secret Sharing over Z/3Z ──────────────────────────────────────────

/// (k, n) Shamir threshold secret sharing over Z/3Z.
/// The secret must be in {0, 1, 2}. Shares are at points x = 1..=n.
pub struct ShamirZ3 {
    pub threshold: usize,
    pub total: usize,
}

impl ShamirZ3 {
    pub fn new(threshold: usize, total: usize) -> Self {
        assert!(threshold >= 1 && threshold <= total, "invalid (k,n)");
        assert!(total <= 2, "Z/3Z only has non-zero points 1,2 — total≤2");
        ShamirZ3 { threshold, total }
    }

    /// Split `secret` (in 0..3) into `total` shares using a degree-(k-1) polynomial.
    pub fn split(&self, secret: Z3, coeffs: &[Z3]) -> Vec<(Z3, Z3)> {
        assert_eq!(coeffs.len(), self.threshold - 1, "need k-1 extra coefficients");
        assert!(secret < 3);
        let mut poly = vec![secret];
        poly.extend_from_slice(coeffs);
        (1..=(self.total as u8))
            .map(|x| (x, poly_eval(&poly, x)))
            .collect()
    }

    /// Recover secret from any `threshold` shares.
    pub fn recover(&self, shares: &[(Z3, Z3)]) -> Z3 {
        assert!(shares.len() >= self.threshold, "not enough shares");
        lagrange_at_zero(&shares[..self.threshold])
    }
}

// ── Additive Secret Sharing over Z/3Z ────────────────────────────────────────

/// n-out-of-n additive sharing: secret = sum(shares) mod 3.
pub struct AdditiveZ3 {
    pub n: usize,
}

impl AdditiveZ3 {
    pub fn new(n: usize) -> Self {
        assert!(n >= 2);
        AdditiveZ3 { n }
    }

    /// Split secret into n shares that sum to secret mod 3.
    /// `randoms` must have length n-1, each in 0..3.
    pub fn split(&self, secret: Z3, randoms: &[Z3]) -> Vec<Z3> {
        assert_eq!(randoms.len(), self.n - 1);
        let mut shares: Vec<Z3> = randoms.to_vec();
        let sum: Z3 = randoms.iter().fold(0u8, |a, &b| z3_add(a, b));
        shares.push(z3_sub(secret, sum));
        shares
    }

    /// Recover secret: sum all n shares mod 3.
    pub fn recover(&self, shares: &[Z3]) -> Z3 {
        assert_eq!(shares.len(), self.n);
        shares.iter().fold(0u8, |a, &b| z3_add(a, b))
    }
}

// ── Verifiable Secret Sharing over Z/3Z ──────────────────────────────────────

/// Commitment to a Z3 value using a simple hash (index + value).
/// In production this would be a cryptographic commitment; here we use a
/// deterministic tag for testing correctness logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    pub tag: u64,
}

impl Commitment {
    fn new(index: usize, value: Z3) -> Self {
        // Toy commitment: deterministic, NOT cryptographically secure
        Commitment { tag: (index as u64) * 100 + value as u64 }
    }

    pub fn verify(&self, index: usize, value: Z3) -> bool {
        self.tag == (index as u64) * 100 + value as u64
    }
}

/// Additive sharing with per-share commitments for verification.
pub struct VerifiableZ3 {
    inner: AdditiveZ3,
}

impl VerifiableZ3 {
    pub fn new(n: usize) -> Self {
        VerifiableZ3 { inner: AdditiveZ3::new(n) }
    }

    pub fn split(&self, secret: Z3, randoms: &[Z3]) -> (Vec<Z3>, Vec<Commitment>) {
        let shares = self.inner.split(secret, randoms);
        let commitments = shares
            .iter()
            .enumerate()
            .map(|(i, &s)| Commitment::new(i, s))
            .collect();
        (shares, commitments)
    }

    pub fn verify_share(&self, index: usize, value: Z3, commitment: &Commitment) -> bool {
        commitment.verify(index, value)
    }

    pub fn recover(&self, shares: &[Z3], commitments: &[Commitment]) -> Option<Z3> {
        // Verify all shares before recovering
        for (i, (&s, c)) in shares.iter().zip(commitments.iter()).enumerate() {
            if !c.verify(i, s) {
                return None;
            }
        }
        Some(self.inner.recover(shares))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Z/3Z arithmetic ──

    #[test]
    fn z3_arithmetic() {
        assert_eq!(z3_add(1, 2), 0);
        assert_eq!(z3_add(2, 2), 1);
        assert_eq!(z3_sub(0, 1), 2);
        assert_eq!(z3_mul(2, 2), 1);
        assert_eq!(z3_inv(1), 1);
        assert_eq!(z3_inv(2), 2);
        assert_eq!(z3_div(2, 2), 1);
    }

    #[test]
    fn poly_eval_constant() {
        // f(x) = 1  →  f(0) = f(1) = f(2) = 1
        assert_eq!(poly_eval(&[1], 0), 1);
        assert_eq!(poly_eval(&[1], 1), 1);
        assert_eq!(poly_eval(&[1], 2), 1);
    }

    #[test]
    fn poly_eval_linear() {
        // f(x) = 2 + x  →  f(1) = 0, f(2) = 1 (mod 3)
        assert_eq!(poly_eval(&[2, 1], 1), 0);
        assert_eq!(poly_eval(&[2, 1], 2), 1);
    }

    // ── Shamir (2,2) over Z/3Z ──

    #[test]
    fn shamir_2_2_roundtrip_secret_0() {
        let s = ShamirZ3::new(2, 2);
        let shares = s.split(0, &[1]);
        let recovered = s.recover(&shares);
        assert_eq!(recovered, 0);
    }

    #[test]
    fn shamir_2_2_roundtrip_secret_1() {
        let s = ShamirZ3::new(2, 2);
        let shares = s.split(1, &[2]);
        let recovered = s.recover(&shares);
        assert_eq!(recovered, 1);
    }

    #[test]
    fn shamir_2_2_roundtrip_secret_2() {
        let s = ShamirZ3::new(2, 2);
        let shares = s.split(2, &[0]);
        let recovered = s.recover(&shares);
        assert_eq!(recovered, 2);
    }

    #[test]
    fn shamir_1_2_trivial_threshold() {
        // threshold=1: secret is directly the constant, any single share suffices
        let s = ShamirZ3::new(1, 2);
        let shares = s.split(2, &[]);
        assert_eq!(s.recover(&shares[0..1]), 2);
        assert_eq!(s.recover(&shares[1..2]), 2);
    }

    // ── Additive sharing ──

    #[test]
    fn additive_3_party_secret_0() {
        let a = AdditiveZ3::new(3);
        let shares = a.split(0, &[1, 2]);
        assert_eq!(a.recover(&shares), 0);
    }

    #[test]
    fn additive_3_party_secret_1() {
        let a = AdditiveZ3::new(3);
        let shares = a.split(1, &[0, 1]);
        assert_eq!(a.recover(&shares), 1);
    }

    #[test]
    fn additive_2_party_all_secrets() {
        let a = AdditiveZ3::new(2);
        for secret in 0u8..3 {
            for r in 0u8..3 {
                let shares = a.split(secret, &[r]);
                assert_eq!(a.recover(&shares), secret, "failed for secret={secret} r={r}");
            }
        }
    }

    #[test]
    fn additive_shares_sum_to_secret() {
        let a = AdditiveZ3::new(4);
        let secret = 2u8;
        let randoms = [1u8, 0, 2];
        let shares = a.split(secret, &randoms);
        let sum = shares.iter().fold(0u8, |acc, &s| z3_add(acc, s));
        assert_eq!(sum, secret);
    }

    // ── Verifiable sharing ──

    #[test]
    fn verifiable_split_recover() {
        let v = VerifiableZ3::new(3);
        let (shares, comms) = v.split(2, &[1, 0]);
        let recovered = v.recover(&shares, &comms);
        assert_eq!(recovered, Some(2));
    }

    #[test]
    fn verifiable_tampered_share_rejected() {
        let v = VerifiableZ3::new(3);
        let (mut shares, comms) = v.split(1, &[2, 1]);
        shares[0] = (shares[0] + 1) % 3; // tamper
        assert_eq!(v.recover(&shares, &comms), None);
    }

    #[test]
    fn verifiable_verify_each_share() {
        let v = VerifiableZ3::new(2);
        let (shares, comms) = v.split(0, &[1]);
        for (i, (&s, c)) in shares.iter().zip(comms.iter()).enumerate() {
            assert!(v.verify_share(i, s, c));
        }
    }
}
