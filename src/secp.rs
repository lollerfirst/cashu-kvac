use secp256k1::{rand, All, Error, PublicKey, Secp256k1, SecretKey};
use std::ops::{Add, Sub, Mul, Neg};
use once_cell::sync::Lazy;

pub const SCALAR_ZERO: [u8; 32] = [0; 32];

/// Secp256k1 global context
pub static SECP256K1: Lazy<Secp256k1<All>> = Lazy::new(|| {
    let mut ctx = Secp256k1::new();
    let mut rng = rand::thread_rng();
    ctx.randomize(&mut rng);
    ctx
});

pub struct Scalar {
    inner: Option<SecretKey>,
    is_zero: bool,
}

impl Scalar{
    pub fn new(data: &[u8; 32]) -> Result<Self, Error> {
        if *data == SCALAR_ZERO {
            Ok(Scalar {
                inner: None,
                is_zero: true,
            })
        } else {
            let inner = SecretKey::from_byte_array(data).expect("no");
            Ok(Scalar { inner: Some(inner), is_zero: false })
        }
    }

    pub fn random() -> Result<Self, Error> {
        let inner = SecretKey::new(&mut rand::thread_rng());
        Ok(Scalar { inner: Some(inner), is_zero: false })
    }

    pub fn clone(&self) -> Self {
        Scalar {
            inner: self.inner.clone(),
            is_zero: self.is_zero,
        }
    }
}

impl Add for Scalar{
    type Output = Result<Scalar, Error>;

    fn add(self, other: Scalar) -> Result<Scalar, Error> {
        if other.is_zero {
            Ok(self.clone())
        } else if self.is_zero {
            Ok(other.clone())
        } else {
            let t_other = secp256k1::Scalar::from_be_bytes(other.inner.unwrap().secret_bytes()).unwrap();
            let result = self.clone();
            result.inner.unwrap().add_tweak(&t_other)?;
            Ok(result)
        }
    }
}

impl Neg for Scalar{
    type Output = Result<Scalar, Error>;

    fn neg(self) -> Result<Scalar, Error> {
        if self.is_zero {
            Ok(self.clone())
        } else {
            let result = self.clone();
            let _ = result.inner.unwrap().negate();
            Ok(result)
        }
    }
}

impl Sub for Scalar{
    type Output = Result<Scalar, Error>;

    fn sub(self, other: Scalar) -> Result<Scalar, Error> {
        if other.is_zero {
            Ok(self.clone())
        } else if self.is_zero {
            -other
        } else {
            self + (-other)?
        }
    }
}

impl Mul for Scalar{
    type Output = Result<Scalar, Error>;

    fn mul(self, other: Scalar) -> Result<Scalar, Error> {
        if other.is_zero || self.is_zero {
            Scalar::new(&SCALAR_ZERO)
        } else {
            // Masked multiplication (constant time)
            let r = Scalar::random()?;
            let b = secp256k1::Scalar::from_be_bytes(other.inner.unwrap().secret_bytes())?;
            let a_r_times_b = (r+self)?.inner.unwrap().mul_tweak(&b)?;
            r.inner.unwrap().mul_tweak(&b);
            a_r_times_b - r
        }
    }
}










