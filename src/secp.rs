use secp256k1::{rand, All, PublicKey, Secp256k1, SecretKey};
use std::ops::{Add, Sub, Mul, Neg};
use std::cmp::PartialEq;

pub const SCALAR_ZERO: [u8; 32] = [0; 32];
pub const SCALAR_ONE: [u8; 32] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

pub struct Scalar {
    inner: Option<SecretKey>,
    is_zero: bool,
}

impl Scalar{
    pub fn new(data: &[u8; 32]) -> Self {
        if *data == SCALAR_ZERO {
            Scalar {
                inner: None,
                is_zero: true,
            }
        } else {
            let inner = SecretKey::from_byte_array(data).expect("no");
            Scalar { inner: Some(inner), is_zero: false }
        }
    }

    pub fn random() -> Self {
        let inner = SecretKey::new(&mut rand::thread_rng());
        Scalar { inner: Some(inner), is_zero: false }
    }

    pub fn clone(&self) -> Self {
        Scalar {
            inner: self.inner.clone(),
            is_zero: self.is_zero,
        }
    }

    pub fn tweak_mul(&self, other: &Scalar) -> Self {
        if other.is_zero || self.is_zero {
           return self.clone();
        }
        let b = secp256k1::Scalar::from_be_bytes(other.inner.unwrap().secret_bytes()).unwrap();
        let result = self.clone();
        let _ = result.inner.unwrap().mul_tweak(&b);
        result
    }

    pub fn tweak_add(&self, other: &Scalar) -> Self {
        if other.is_zero {
            self.clone()
        } else if self.is_zero {
            other.clone()
        } else {
            let t_other = secp256k1::Scalar::from_be_bytes(other.inner.unwrap().secret_bytes()).unwrap();
            let result = self.clone();
            let _ = result.inner.unwrap().add_tweak(&t_other);
            result
        }
    }

    /*
    pub fn invert(&self) -> Self {
        if self.is_zero {
            self.clone()
        } else {

        }

    }
    */
}

impl Add for Scalar{
    type Output = Scalar;

    fn add(self, other: Scalar) -> Scalar {
        self.tweak_add(&other)
    }
}

impl Neg for Scalar{
    type Output = Scalar;

    fn neg(self) -> Scalar {
        if self.is_zero {
            self.clone()
        } else {
            let result = self.clone();
            let _ = result.inner.unwrap().negate();
            result
        }
    }
}

impl Sub for Scalar{
    type Output = Scalar;

    fn sub(self, other: Scalar) -> Scalar {
        if other.is_zero {
            self.clone()
        } else if self.is_zero {
            -other
        } else {
            self + (-other)
        }
    }
}

impl Mul for Scalar{
    type Output = Scalar;

    fn mul(self, other: Scalar) -> Scalar {
        if other.is_zero || self.is_zero {
            Scalar::new(&SCALAR_ZERO)
        } else {
            // Masked multiplication (constant time)
            let r = Scalar::random();
            let a_plus_r = self.tweak_add(&r);
            let a_plus_r_times_b = a_plus_r.tweak_mul(&r);
            let r_times_b = r.tweak_mul(&other);
            a_plus_r_times_b - r_times_b
        }
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
        for (x, y) in self.inner.as_ref().unwrap().secret_bytes().iter().zip(other.inner.as_ref().unwrap().secret_bytes().iter()) {
            b |= x ^ y;
        }
        b == 0
    }
}


impl From<u64> for Scalar {
    fn from(value: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[31] = (value >> 56) as u8;
        bytes[30] = (value >> 48) as u8;
        bytes[29] = (value >> 40) as u8;
        bytes[28] = (value >> 32) as u8;
        bytes[27] = (value >> 24) as u8;
        bytes[26] = (value >> 16) as u8;
        bytes[25] = (value >> 8) as u8;
        bytes[24] = value as u8;
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
        padded_bytes[32 - bytes.len()..].copy_from_slice(&bytes);
        Scalar::new(&padded_bytes)
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
    fn test_tweak_mul() {
        let scalar1 = Scalar::random();
        let scalar2 = Scalar::random();
        let result = scalar1.tweak_mul(&scalar2);
        assert!(!result.is_zero);
    }

    #[test]
    fn test_tweak_add() {
        let scalar1 = Scalar::random();
        let scalar2 = Scalar::random();
        let result = scalar1.tweak_add(&scalar2);
        assert!(!result.is_zero);
    }

    #[test]
    fn test_add() {
        let scalar1 = Scalar::random();
        let scalar2 = Scalar::random();
        let result = scalar1 + scalar2;
        assert!(!result.is_zero);
    }

    #[test]
    fn test_neg() {
        let scalar = Scalar::random();
        let neg_scalar = -scalar;
        assert!(!neg_scalar.is_zero);
    }

    #[test]
    fn test_sub() {
        let scalar1 = Scalar::random();
        let scalar2 = Scalar::random();
        let result = scalar1 - scalar2;
        assert!(!result.is_zero);
    }

    #[test]
    fn test_mul() {
        let scalar1 = Scalar::random();
        let scalar2 = Scalar::random();
        let result = scalar1 * scalar2;
        assert!(!result.is_zero);
    }

    #[test]
    fn test_mul_zero() {
        let scalar1 = Scalar::random();
        let scalar2 = Scalar::new(&SCALAR_ZERO);
        let result = scalar1 * scalar2;
        assert!(result.is_zero);
    }

    #[test]
    fn test_mul_by_zero() {
        let scalar1 = Scalar::new(&SCALAR_ZERO);
        let scalar2 = Scalar::random();
        let result = scalar1 * scalar2;
        assert!(result.is_zero);
    }

    #[test]
    fn test_mul_cmp() {
        let a = Scalar::random();
        let b = Scalar::random();
        let c = a.tweak_mul(&b);
        let c_ = a*b;
        assert!(c == c_);
    }
}











