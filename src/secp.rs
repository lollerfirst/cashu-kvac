use rug::ops::RemRounding;
use secp256k1::constants::CURVE_ORDER;
use secp256k1::{rand, PublicKey, SecretKey};
use std::ops::{Add, Sub, Mul, Neg};
use std::cmp::PartialEq;
use rug::Integer;

pub const SCALAR_ZERO: [u8; 32] = [0; 32];
pub const SCALAR_ONE: [u8; 32] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

pub struct Scalar {
    inner: Option<SecretKey>,
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
            inner: Some(self.inner.unwrap().clone()),
            is_zero: self.is_zero,
        }
    }

    pub fn tweak_mul(&self, other: &Scalar) -> Self {
        if other.is_zero || self.is_zero {
           return self.clone();
        }
        let b = secp256k1::Scalar::from_be_bytes(other.inner.unwrap().secret_bytes()).unwrap();
        let result = self.clone();
        let result = result.inner.unwrap().mul_tweak(&b).unwrap();
        Scalar{inner: Some(result), is_zero: false}
    }

    pub fn tweak_add(&self, other: &Scalar) -> Self {
        if other.is_zero {
            self.clone()
        } else if self.is_zero {
            other.clone()
        } else {
            let t_other = secp256k1::Scalar::from_be_bytes(other.inner.unwrap().secret_bytes()).unwrap();
            let result = self.clone();
            let result_key = result.inner.unwrap().add_tweak(&t_other).unwrap();
            Scalar{ inner:Some(result_key), is_zero: false }
        }
    }

    pub fn tweak_neg(&self) -> Self {
        if self.is_zero {
            self.clone()
        } else {
            let result = self.clone();
            let result_key = result.inner.unwrap().negate();
            Scalar{inner:Some(result_key), is_zero: false}
        }
    }

    pub fn invert(&self) -> Self {
        if self.is_zero {
            panic!("Scalar 0 doesn't have an inverse")
        } else {
            let x = Integer::from_digits(&self.inner.unwrap().secret_bytes(), rug::integer::Order::Msf);
            let q = Integer::from_digits(&CURVE_ORDER, rug::integer::Order::Msf);
            let x_inv = modinv(&q, &x);
            //let x_inv = x.clone().invert(&q).unwrap();
            let mut data = [0u8; 32];
            let vec = x_inv.to_digits(rug::integer::Order::Msf);
            data.copy_from_slice(&vec[0..32]);
            Scalar::new(&data)
        }
    }
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
        self.tweak_neg()
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
            let a_plus_r_times_b = a_plus_r.tweak_mul(&other);
            let r_times_b = r.tweak_mul(&other);
            a_plus_r_times_b - r_times_b
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

impl Into<String> for Scalar {
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
        padded_bytes[32-bytes.len()..32].copy_from_slice(&bytes);
        Scalar::new(&padded_bytes)
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
        let scalar1 = Scalar::from("02");
        let scalar2 = Scalar::from("03");
        let result = Scalar::from("06");
        let result_ = scalar1.tweak_mul(&scalar2);
        assert!(result_ == result);
    }

    #[test]
    fn test_tweak_add() {
        let scalar1 = Scalar::from("02");
        let scalar2 = Scalar::from("03");
        let result = Scalar::from("05");
        let result_ = scalar1.tweak_add(&scalar2);
        assert!(result == result_);
    }

    #[test]
    fn test_add() {
        let scalar1 = Scalar::from("02");
        let scalar2 = Scalar::from("03");
        let result = Scalar::from("05");
        let result_ = scalar1 + scalar2;
        assert!(result_ == result);
    }

    #[test]
    fn test_sub() {
        let scalar1 = Scalar::from("10");
        let scalar2 = Scalar::from("02");
        let result = Scalar::from("0e");
        let result_ = scalar1 - scalar2;
        assert!(result == result_);
    }

    #[test]
    fn test_mul() {
        let scalar1 = Scalar::from("02");
        let scalar2 = Scalar::from("03");
        let result = Scalar::from("06");
        let result_ = scalar1 * scalar2;
        assert!(result_ == result);
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
        let hex_str: String = scalar.into();
        assert_eq!(hex_str.len(), 64);
        assert!(hex::decode(&hex_str).is_ok());
    }

    #[test]
    fn test_zero_scalar_into_string() {
        let scalar = Scalar::new(&SCALAR_ZERO);
        let hex_str: String = scalar.into();
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
        let scalar_inv = scalar.invert();
        let prod = scalar * scalar_inv;
        assert!(one == prod);
    }
}











