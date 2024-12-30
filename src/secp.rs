use bitcoin::hashes::serde::{Serialize, Serializer};
use bitcoin::secp256k1::constants::CURVE_ORDER;
use bitcoin::secp256k1::{rand, All, PublicKey, Scalar as SecpScalar, Secp256k1, SecretKey};
use once_cell::sync::Lazy;
use rug::ops::RemRounding;
use rug::Integer;
use serde::{Deserialize, Deserializer};
use std::cmp::PartialEq;

use crate::errors::Error;

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

#[derive(Clone, Debug)]
pub struct Scalar {
    inner: Option<SecretKey>,
    is_zero: bool,
}

#[derive(Clone, Debug)]
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
            delta += 1;
        } else {
            g >>= 1;
            e = div2(m, e);
            delta += 1;
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
            self.inner = Some(other.inner.unwrap());
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
            Scalar {
                inner: Some(inner),
                is_zero: false,
            }
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

    pub fn combine_add(&mut self, other: &GroupElement) -> &Self {
        if other.is_zero {
            self
        } else if self.is_zero {
            self.inner = other.inner;
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
        self.tweak_add(other);
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
            self.tweak_mul(other);
            r.tweak_mul(other);
            self - &r
        }
    }
}

impl From<Scalar> for Vec<u8> {
    fn from(val: Scalar) -> Self {
        if val.is_zero {
            SCALAR_ZERO.to_vec()
        } else {
            val.inner.unwrap().secret_bytes().to_vec()
        }
    }
}

impl From<&Scalar> for [u8; 32] {
    fn from(val: &Scalar) -> Self {
        if val.is_zero {
            SCALAR_ZERO
        } else {
            val.inner
                .as_ref()
                .expect("Expected inner Scalar")
                .secret_bytes()
        }
    }
}

impl From<&Scalar> for u64 {
    fn from(val: &Scalar) -> Self {
        if val.is_zero {
            0
        } else {
            let bytes: [u8; 32] = val.into();
            let mut result: u64 = 0;
            for i in 0..8 {
                result <<= 8;
                result |= bytes[24 + i] as u64;
            }
            result
        }
    }
}

impl From<&Scalar> for String {
    fn from(val: &Scalar) -> Self {
        if val.is_zero {
            hex::encode(SCALAR_ZERO)
        } else {
            hex::encode(val.inner.unwrap().secret_bytes())
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

impl TryFrom<&str> for Scalar {
    type Error = Error;
    fn try_from(hex_string: &str) -> Result<Self, Error> {
        let bytes = hex::decode(hex_string)?;
        if bytes.len() > 32 {
            return Err(Error::HexStringTooLong);
        }
        let mut padded_bytes = [0u8; 32];
        padded_bytes[32 - bytes.len()..32].copy_from_slice(&bytes);
        Ok(Scalar::new(&padded_bytes))
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

impl Serialize for Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let scalar_hex: String = self.into();
        serializer.serialize_str(&scalar_hex)
    }
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex: String = String::deserialize(deserializer)?;
        let scalar = Scalar::try_from(hex.as_str())
            .map_err(|e| serde::de::Error::custom(format!("{}", e)))?;
        Ok(scalar)
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
            false
        } else {
            self.inner.unwrap().eq(&other.inner.unwrap())
        }
    }
}

impl TryFrom<&str> for GroupElement {
    type Error = Error;
    fn try_from(hex_string: &str) -> Result<Self, Error> {
        let bytes = hex::decode(hex_string)?;
        if bytes.len() > 33 {
            return Err(Error::HexStringTooLong);
        }
        let mut padded_bytes = [0u8; 33];
        padded_bytes[33 - bytes.len()..33].copy_from_slice(&bytes);
        Ok(GroupElement::new(&padded_bytes))
    }
}

impl From<&GroupElement> for [u8; 33] {
    fn from(val: &GroupElement) -> Self {
        if val.is_zero {
            GROUP_ELEMENT_ZERO
        } else {
            val.inner
                .as_ref()
                .expect("Expected inner PublicKey")
                .serialize()
        }
    }
}

impl From<&GroupElement> for String {
    fn from(val: &GroupElement) -> Self {
        if val.is_zero {
            hex::encode(GROUP_ELEMENT_ZERO)
        } else {
            hex::encode(
                val.inner
                    .as_ref()
                    .expect("Expected inner PublicKey")
                    .serialize(),
            )
        }
    }
}

impl AsRef<GroupElement> for GroupElement {
    fn as_ref(&self) -> &GroupElement {
        self
    }
}

impl Serialize for GroupElement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let ge_hex: String = self.into();
        serializer.serialize_str(&ge_hex)
    }
}

impl<'de> Deserialize<'de> for GroupElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex: String = String::deserialize(deserializer)?;
        let ge = GroupElement::try_from(hex.as_str())
            .map_err(|e| serde::de::Error::custom(format!("{}", e)))?;
        Ok(ge)
    }
}

#[cfg(test)]
mod tests {
    use crate::generators::hash_to_curve;

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
        let mut scalar1 = Scalar::try_from("02").unwrap();
        let scalar2 = Scalar::try_from("03").unwrap();
        let result = Scalar::try_from("06").unwrap();
        let result_ = scalar1.tweak_mul(&scalar2);
        assert!(*result_ == result);
    }

    #[test]
    fn test_scalar_tweak_add() {
        let mut scalar1 = Scalar::try_from("02").unwrap();
        let scalar2 = Scalar::try_from("03").unwrap();
        let result = Scalar::try_from("05").unwrap();
        let result_ = scalar1.tweak_add(&scalar2);
        assert!(result == *result_);
    }

    #[test]
    fn test_scalar_add() {
        let scalar1 = Scalar::try_from("02").unwrap();
        let scalar2 = Scalar::try_from("03").unwrap();
        let result = Scalar::try_from("05").unwrap();
        let result_ = scalar1 + &scalar2;
        assert!(result_ == result);
    }

    #[test]
    fn test_scalar_sub() {
        let scalar1 = Scalar::try_from("10").unwrap();
        let scalar2 = Scalar::try_from("02").unwrap();
        let result = Scalar::try_from("0e").unwrap();
        let result_ = scalar1 - &scalar2;
        assert!(result == result_);
    }

    #[test]
    fn test_scalar_mul() {
        let scalar1 = Scalar::try_from("02").unwrap();
        let scalar2 = Scalar::try_from("03").unwrap();
        let result = Scalar::try_from("06").unwrap();
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
        let scalar = Scalar::try_from("deadbeef").unwrap();
        let scalar_inv = scalar.clone().invert();
        let prod = scalar * &scalar_inv;
        assert!(one == prod);
    }

    #[test]
    fn test_scalar_serialization() {
        let scalar = Scalar::random();

        // Serialize the Scalar instance
        let serialized = serde_json::to_string(&scalar).expect("Failed to serialize");
        println!("{}", serialized);
        assert!(serialized.len() > 0);
    }

    #[test]
    fn test_scalar_deserialization() {
        let scalar = Scalar::random();

        // Serialize the Scalar instance to JSON
        let serialized = serde_json::to_string(&scalar).expect("Failed to serialize");

        // Deserialize back to Scalar
        let deserialized: Scalar =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        // Check that the deserialized Scalar matches the original
        assert_eq!(scalar.is_zero, deserialized.is_zero);
        assert_eq!(scalar.inner.is_some(), deserialized.inner.is_some());
    }

    #[test]
    fn test_ge_from_hex() {
        let g = GroupElement::try_from(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        assert!(!g.is_zero)
    }

    #[test]
    fn test_ge_into() {
        let hex_str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let g = GroupElement::try_from(hex_str).unwrap();
        let g_string: String = g.as_ref().into();
        assert!(hex_str == g_string)
    }

    #[test]
    fn test_cmp_neq() {
        let g1 = GroupElement::try_from(
            "0264f39fbee428ab6165e907b5d463a17e315b9f06f6200ed7e9c4bcbe0df73383",
        )
        .unwrap();
        let g2 = GroupElement::try_from(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        assert!(g1 != g2);
    }

    #[test]
    fn test_ge_add_mul() {
        let g = GroupElement::try_from(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        let scalar_2 = Scalar::try_from("02").unwrap();
        let result = g.clone() + &g;
        let result_ = g * &scalar_2;
        assert!(result == result_)
    }

    #[test]
    fn test_ge_sub_mul() {
        let g = GroupElement::try_from(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        let scalar_2 = Scalar::try_from("02").unwrap();
        let result = g.clone() * &scalar_2 - &g;
        assert!(result == g)
    }

    #[test]
    fn test_ge_serialization() {
        let ge = hash_to_curve(b"deadbeef").unwrap();

        // Serialize the Scalar instance
        let serialized = serde_json::to_string(&ge).expect("Failed to serialize");
        println!("{}", serialized);
        assert!(serialized.len() > 0);
    }

    #[test]
    fn test_ge_deserialization() {
        let ge = hash_to_curve(b"deadbeef").unwrap();

        let serialized = serde_json::to_string(&ge).expect("Failed to serialize");

        let deserialized: GroupElement =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        assert_eq!(ge.is_zero, deserialized.is_zero);
        assert_eq!(ge.inner.is_some(), deserialized.inner.is_some());
    }
}
