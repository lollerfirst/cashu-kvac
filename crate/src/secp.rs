use bitcoin::hashes::serde::Serialize;
use bitcoin::secp256k1::constants::CURVE_ORDER;
use bitcoin::secp256k1::{rand, All, PublicKey, Scalar as SecpScalar, Secp256k1, SecretKey};
use once_cell::sync::Lazy;
use rug::ops::RemRounding;
use rug::Integer;
use serde::Deserialize;
use std::cmp::PartialEq;

pub const SCALAR_ZERO: [u8; 32] = [0; 32];
pub const SCALAR_ONE: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];
pub const GROUP_ELEMENT_ZERO: [u8; 33] = [0; 33];

/// Secp256k1 global context
pub static SECP256K1: Lazy<Secp256k1<All>> = Lazy::new(|| {
    let mut ctx = Secp256k1::new();
    let mut rng = rand::thread_rng();
    ctx.randomize(&mut rng);
    ctx
});

#[derive(Clone, Serialize, Deserialize)]
pub struct Scalar {
    inner: Option<SecretKey>,
    is_zero: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GroupElement {
    inner: Option<PublicKey>,
    is_zero: bool,
}

fn div2(m: &Integer, mut x: Integer) -> Integer {
    if x.is_odd() {
        x += m;
    }
    x >> 1
}

fn modinv(m: &Integer, x: &Integer) -> Integer {
    assert!(m.is_odd(), "M must be odd");
    let mut delta = 1;
    let mut f = m.clone();
    let mut g = x.clone();
    let mut d = Integer::from(0);
    let mut e = Integer::from(1);

    while !g.is_zero() {
        if delta > 0 && g.is_odd() {
            let tmp_g = g.clone();
            g = (g - &f) >> 1;
            f = tmp_g;
            let tmp_e = e.clone();
            e = div2(m, e - &d);
            d = tmp_e;
            delta = 1 - delta;
        } else if g.is_odd() {
            g = (g + &f) >> 1;
            e = div2(m, e + &d);
            delta = 1 + delta;
        } else {
            g >>= 1;
            e = div2(m, e);
            delta = 1 + delta;
        }
    }

    // Result: (d * f) % m
    (d * f).rem_euc(m)
}

impl Scalar {
    pub fn new(data: &[u8; 32]) -> Self {
        if *data == SCALAR_ZERO {
            Scalar {
                inner: None,
                is_zero: true,
            }
        } else {
            let inner = SecretKey::from_slice(data).expect("Could not instantiate Scalar");
            Scalar {
                inner: Some(inner),
                is_zero: false,
            }
        }
    }

    pub fn random() -> Self {
        let inner = SecretKey::new(&mut rand::thread_rng());
        Scalar {
            inner: Some(inner),
            is_zero: false,
        }
    }

    pub fn clone(&self) -> Self {
        if !self.is_zero {
            Scalar {
                inner: Some(self.inner.unwrap().clone()),
                is_zero: self.is_zero,
            }
        } else {
            Scalar {
                inner: None,
                is_zero: self.is_zero,
            }
        }
        
    }

    pub fn tweak_mul(&mut self, other: &Scalar) -> &Self {
        if other.is_zero || self.is_zero {
            self.is_zero = true;
            self.inner = None;
            return self;
        }
        let b = SecpScalar::from_be_bytes(other.inner.unwrap().secret_bytes()).unwrap();
        let result = self
            .inner
            .unwrap()
            .mul_tweak(&b)
            .expect("Could not multiply Scalars");
        self.inner = Some(result);
        self
    }

    pub fn tweak_add(&mut self, other: &Scalar) -> &Self {
        if other.is_zero {
            self
        } else if self.is_zero {
            self.inner = Some(other.inner.unwrap().clone());
            self.is_zero = false;
            self
        } else {
            let b = SecpScalar::from_be_bytes(other.inner.unwrap().secret_bytes()).unwrap();
            let result_key = self
                .inner
                .unwrap()
                .add_tweak(&b)
                .expect("Could not add to Scalar");
            self.inner = Some(result_key);
            self
        }
    }

    pub fn tweak_neg(&mut self) -> &Self {
        if self.is_zero {
            self
        } else {
            let result = self.inner.unwrap().negate();
            self.inner = Some(result);
            self
        }
    }

    pub fn invert(self) -> Self {
        if self.is_zero {
            panic!("Scalar 0 doesn't have an inverse")
        } else {
            let x = Integer::from_digits(
                &self.inner.unwrap().secret_bytes(),
                rug::integer::Order::Msf,
            );
            let q = Integer::from_digits(&CURVE_ORDER, rug::integer::Order::Msf);
            let x_inv = modinv(&q, &x);
            //let x_inv = x.clone().invert(&q).unwrap();
            let mut vec: Vec<u8> = x_inv.to_digits(rug::integer::Order::Lsf);
            if vec.len() < 32 {
                vec.extend(vec![0; 32 - vec.len()]);
            }
            vec.reverse();
            let inner = SecretKey::from_slice(&vec).expect("Could not instantiate Scalar");
            Scalar { inner: Some(inner), is_zero: false }
        }
    }
}

impl GroupElement {
    pub fn new(data: &[u8; 33]) -> Self {
        if *data == GROUP_ELEMENT_ZERO {
            GroupElement {
                inner: None,
                is_zero: true,
            }
        } else {
            let inner = PublicKey::from_slice(data).expect("Cannot create GroupElement");
            GroupElement {
                inner: Some(inner),
                is_zero: false,
            }
        }
    }

    pub fn clone(&self) -> Self {
        if self.is_zero {
            GroupElement {
                inner: None,
                is_zero: true,
            }
        } else {
            GroupElement {
                inner: Some(self.inner.unwrap().clone()),
                is_zero: self.is_zero,
            }
        }
    }

    pub fn combine_add(&mut self, other: &GroupElement) -> &Self {
        if other.is_zero {
            self
        } else if self.is_zero {
            self.inner = other.inner.clone();
            self.is_zero = other.is_zero;
            self
        } else {
            let result = self
                .inner
                .unwrap()
                .combine(&other.inner.unwrap())
                .expect("Error combining GroupElements");
            self.inner = Some(result);
            self
        }
    }

    pub fn multiply(&mut self, scalar: &Scalar) -> &Self {
        if scalar.is_zero || self.is_zero {
            self.is_zero = true;
            self.inner = None;
            self
        } else {
            let b = bitcoin::secp256k1::Scalar::from_be_bytes(scalar.inner.unwrap().secret_bytes())
                .unwrap();
            let result = self
                .inner
                .unwrap()
                .mul_tweak(&SECP256K1, &b)
                .expect("Could not multiply Scalar to GroupElement");
            self.inner = Some(result);
            self
        }
    }

    pub fn negate(&mut self) -> &Self {
        if self.is_zero {
            self
        } else {
            let result = self.inner.unwrap().negate(&SECP256K1);
            self.inner = Some(result);
            self
        }
    }
}

impl std::ops::Add<&Scalar> for Scalar {
    type Output = Scalar;

    fn add(mut self, other: &Scalar) -> Scalar {
        self.tweak_add(&other);
        self
    }
}

impl std::ops::Neg for Scalar {
    type Output = Scalar;

    fn neg(mut self) -> Scalar {
        self.tweak_neg();
        self
    }
}

impl std::ops::Sub<&Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, other: &Scalar) -> Scalar {
        if other.is_zero {
            self
        } else if self.is_zero {
            -(other.clone())
        } else {
            let other_neg = -(other.clone());
            self + &other_neg
        }
    }
}

impl std::ops::Mul<&Scalar> for Scalar {
    type Output = Scalar;

    fn mul(mut self, other: &Scalar) -> Scalar {
        if other.is_zero || self.is_zero {
            self.inner = None;
            self.is_zero = true;
            self
        } else {
            // Multiplication is masked with random `r`
            let mut r = Scalar::random();
            self.tweak_add(&r);
            self.tweak_mul(&other);
            r.tweak_mul(&other);
            self - &r
        }
    }
}

impl Into<Vec<u8>> for Scalar {
    fn into(self) -> Vec<u8> {
        if self.is_zero {
            SCALAR_ZERO.to_vec()
        } else {
            self.inner.unwrap().secret_bytes().to_vec()
        }
    }
}

impl Into<[u8; 32]> for &Scalar {
    fn into(self) -> [u8; 32] {
        if self.is_zero {
            SCALAR_ZERO
        } else {
            self.inner.as_ref().expect("Expected inner Scalar").secret_bytes()
        }
    }
}

impl Into<u64> for &Scalar {
    fn into(self) -> u64 {
        if self.is_zero {
            0
        } else {
            let bytes: [u8; 32] = self.into();
            let mut result: u64 = 0;
            for i in 0..8 {
                result <<= 8;
                result |= bytes[24+i] as u64;
            }
            result
        }
    }
}

impl Into<String> for &Scalar {
    fn into(self) -> String {
        if self.is_zero {
            hex::encode(SCALAR_ZERO)
        } else {
            hex::encode(self.inner.unwrap().secret_bytes())
        }
    }
}

impl From<u64> for Scalar {
    fn from(value: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[24] = (value >> 56) as u8;
        bytes[25] = (value >> 48) as u8;
        bytes[26] = (value >> 40) as u8;
        bytes[27] = (value >> 32) as u8;
        bytes[28] = (value >> 24) as u8;
        bytes[29] = (value >> 16) as u8;
        bytes[30] = (value >> 8) as u8;
        bytes[31] = value as u8;
        Scalar::new(&bytes)
    }
}

impl From<&str> for Scalar {
    fn from(hex_string: &str) -> Self {
        let bytes = hex::decode(hex_string).expect("Invalid hex string");
        if bytes.len() > 32 {
            panic!("Hex string is too long");
        }
        let mut padded_bytes = [0u8; 32];
        padded_bytes[32 - bytes.len()..32].copy_from_slice(&bytes);
        Scalar::new(&padded_bytes)
    }
}

impl AsRef<Scalar> for Scalar {
    fn as_ref(&self) -> &Scalar {
        self
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        if self.is_zero && other.is_zero {
            return true;
        }
        if self.is_zero || other.is_zero {
            return false;
        }
        let mut b = 0u8;
        for (x, y) in self
            .inner
            .as_ref()
            .unwrap()
            .secret_bytes()
            .iter()
            .zip(other.inner.as_ref().unwrap().secret_bytes().iter())
        {
            b |= x ^ y;
        }
        b == 0
    }
}

impl std::ops::Add<&GroupElement> for GroupElement {
    type Output = GroupElement;

    fn add(mut self, other: &GroupElement) -> GroupElement {
        self.combine_add(other);
        self
    }
}

impl std::ops::Neg for GroupElement {
    type Output = GroupElement;

    fn neg(mut self) -> GroupElement {
        self.negate();
        self
    }
}

impl std::ops::Sub<&GroupElement> for GroupElement {
    type Output = GroupElement;

    fn sub(self, other: &GroupElement) -> GroupElement {
        if other.is_zero {
            self
        } else if self.is_zero {
            -(other.clone())
        } else {
            let other_neg = -(other.clone());
            self + &other_neg
        }
    }
}

impl std::ops::Mul<&Scalar> for GroupElement {
    type Output = GroupElement;

    fn mul(mut self, other: &Scalar) -> GroupElement {
        if self.is_zero || other.is_zero {
            self.is_zero = true;
            self.inner = None;
            self
        } else {
            // Multiplication is masked with random `r`
            let r = Scalar::random();
            let r_copy = r.clone();
            let mut self_copy = self.clone();
            self.multiply(&(r + other));
            self_copy.multiply(&r_copy);
            self - &self_copy
        }
    }
}

impl PartialEq for GroupElement {
    fn eq(&self, other: &Self) -> bool {
        if self.is_zero && other.is_zero {
            return true;
        }
        if self.is_zero || other.is_zero {
            return false;
        } else {
            self.inner.unwrap().eq(&other.inner.unwrap())
        }
    }
}

impl From<&str> for GroupElement {
    fn from(hex_string: &str) -> Self {
        let bytes = hex::decode(hex_string).expect("Invalid hex string");
        if bytes.len() > 33 {
            panic!("Hex string is too long");
        }
        let mut padded_bytes = [0u8; 33];
        padded_bytes[33 - bytes.len()..33].copy_from_slice(&bytes);
        GroupElement::new(&padded_bytes)
    }
}

impl Into<[u8; 33]> for &GroupElement {
    fn into(self) -> [u8; 33] {
        if self.is_zero {
            GROUP_ELEMENT_ZERO
        } else {
            self.inner
                .as_ref()
                .expect("Expected inner PublicKey")
                .serialize()
        }
    }
}

impl Into<String> for &GroupElement {
    fn into(self) -> String {
        if self.is_zero {
            hex::encode(GROUP_ELEMENT_ZERO)
        } else {
            hex::encode(self.inner
                .as_ref()
                .expect("Expected inner PublicKey")
                .serialize()
            )
        }
    }
}

impl AsRef<GroupElement> for GroupElement {
    fn as_ref(&self) -> &GroupElement {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_scalar() {
        let data = [1u8; 32];
        let scalar = Scalar::new(&data);
        assert!(!scalar.is_zero);
    }

    #[test]
    fn test_new_zero_scalar() {
        let scalar = Scalar::new(&SCALAR_ZERO);
        assert!(scalar.is_zero);
    }

    #[test]
    fn test_random_scalar() {
        let scalar = Scalar::random();
        assert!(!scalar.is_zero);
    }

    #[test]
    fn test_clone_scalar() {
        let scalar = Scalar::random();
        let cloned_scalar = scalar.clone();
        assert_eq!(scalar.inner, cloned_scalar.inner);
        assert_eq!(scalar.is_zero, cloned_scalar.is_zero);
    }

    #[test]
    fn test_scalar_tweak_mul() {
        let mut scalar1 = Scalar::from("02");
        let scalar2 = Scalar::from("03");
        let result = Scalar::from("06");
        let result_ = scalar1.tweak_mul(&scalar2);
        assert!(*result_ == result);
    }

    #[test]
    fn test_scalar_tweak_add() {
        let mut scalar1 = Scalar::from("02");
        let scalar2 = Scalar::from("03");
        let result = Scalar::from("05");
        let result_ = scalar1.tweak_add(&scalar2);
        assert!(result == *result_);
    }

    #[test]
    fn test_scalar_add() {
        let scalar1 = Scalar::from("02");
        let scalar2 = Scalar::from("03");
        let result = Scalar::from("05");
        let result_ = scalar1 + &scalar2;
        assert!(result_ == result);
    }

    #[test]
    fn test_scalar_sub() {
        let scalar1 = Scalar::from("10");
        let scalar2 = Scalar::from("02");
        let result = Scalar::from("0e");
        let result_ = scalar1 - &scalar2;
        assert!(result == result_);
    }

    #[test]
    fn test_scalar_mul() {
        let scalar1 = Scalar::from("02");
        let scalar2 = Scalar::from("03");
        let result = Scalar::from("06");
        let result_ = scalar1 * &scalar2;
        assert!(result_ == result);
    }

    #[test]
    fn test_scalar_mul_zero() {
        let scalar1 = Scalar::random();
        let scalar2 = Scalar::new(&SCALAR_ZERO);
        let result = scalar1 * &scalar2;
        assert!(result.is_zero);
    }

    #[test]
    fn test_scalar_mul_by_zero() {
        let scalar1 = Scalar::new(&SCALAR_ZERO);
        let scalar2 = Scalar::random();
        let result = scalar1 * &scalar2;
        assert!(result.is_zero);
    }

    #[test]
    fn test_mul_cmp() {
        let a = Scalar::random();
        let b = Scalar::random();
        let mut a_clone = a.clone();
        let c = a_clone.tweak_mul(&b);
        let c_ = a * &b;
        assert!(*c == c_);
    }

    #[test]
    fn test_scalar_into_vec() {
        let scalar = Scalar::random();
        let bytes: Vec<u8> = scalar.clone().into();
        assert_eq!(bytes.len(), 32);
        assert!(bytes.iter().any(|&b| b != 0)); // Ensure it's not all zeros
    }

    #[test]
    fn test_zero_scalar_into_vec() {
        let scalar = Scalar::new(&SCALAR_ZERO);
        let bytes: Vec<u8> = scalar.into();
        assert_eq!(bytes, SCALAR_ZERO.to_vec());
    }

    #[test]
    fn test_scalar_into_string() {
        let scalar = Scalar::random();
        let hex_str: String = scalar.as_ref().into();
        assert_eq!(hex_str.len(), 64);
        assert!(hex::decode(&hex_str).is_ok());
    }

    #[test]
    fn test_zero_scalar_into_string() {
        let scalar = Scalar::new(&SCALAR_ZERO);
        let hex_str: String = scalar.as_ref().into();
        assert_eq!(hex_str, hex::encode(SCALAR_ZERO));
    }

    #[test]
    fn test_div2_even() {
        let m = Integer::from(29);
        let x = Integer::from(20);
        assert_eq!(div2(&m, x), Integer::from(10));
    }

    #[test]
    fn test_div2_odd() {
        let m = Integer::from(29);
        let x = Integer::from(21);
        assert_eq!(div2(&m, x), Integer::from(25));
    }

    #[test]
    fn test_scalar_modular_inversion() {
        let one = Scalar::new(&SCALAR_ONE);
        let scalar = Scalar::from("deadbeef");
        let scalar_inv = scalar.clone().invert();
        let prod = scalar * &scalar_inv;
        assert!(one == prod);
    }

    #[test]
    fn test_ge_from_hex() {
        let g = GroupElement::from(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        );
        assert!(!g.is_zero)
    }

    #[test]
    fn test_ge_into() {
        let hex_str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let g = GroupElement::from(hex_str);
        let g_string: String = g.as_ref().into();
        assert!(hex_str == g_string)
    }

    #[test]
    fn test_cmp_neq() {
        let g1 = GroupElement::from(
            "0264f39fbee428ab6165e907b5d463a17e315b9f06f6200ed7e9c4bcbe0df73383",
        );
        let g2 = GroupElement::from(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        );
        assert!(g1 != g2);
    }

    #[test]
    fn test_ge_add_mul() {
        let g = GroupElement::from(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        );
        let scalar_2 = Scalar::from("02");
        let result = g.clone() + &g;
        let result_ = g * &scalar_2;
        assert!(result == result_)
    }

    #[test]
    fn test_ge_sub_mul() {
        let g = GroupElement::from(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        );
        let scalar_2 = Scalar::from("02");
        let result = g.clone() * &scalar_2 - &g;
        assert!(result == g)
    }
}
