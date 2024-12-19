use once_cell::sync::Lazy;
use crate::{generators::hash_to_curve, secp::{GroupElement, Scalar}};

// Maximum allowed for a single attribute
pub const LOG_RANGE_LIMIT: usize = 32;

pub static POWERS_OF_TWO: Lazy<Vec<Scalar>> = Lazy::new(|| {
    let mut result = Vec::new();
    for i in 0..LOG_RANGE_LIMIT {
        let pow = (1 << i) as u64;
        result.push(Scalar::from(pow));
    }
    result
});
pub static G: Lazy<Vec<GroupElement>> = Lazy::new(|| {
    let mut result = Vec::new();
    for i in 0..128 {
        result.push(hash_to_curve(format!("IPA_G_{}_", i).as_bytes()).expect("Couldn't map hash to point on the curve"));
    }
    result
});
pub static H: Lazy<Vec<GroupElement>> = Lazy::new(|| {
    let mut result = Vec::new();
    for i in 0..128 {
        result.push(hash_to_curve(format!("IPA_H_{}_", i).as_bytes()).expect("Couldn't map hash to point on the curve"));
    }
    result
});
pub static U: Lazy<GroupElement> = Lazy::new(|| hash_to_curve(b"IPA_U_").expect("Couldn't map hash to point on the curve"));

#[allow(non_snake_case)]
fn get_generators(n: usize) -> (Vec<GroupElement>, Vec<GroupElement>, GroupElement) {
    let (mut G_, mut H_, U_) = (G.clone(), H.clone(), U.clone());
    if n > G.len() {
        for i in G.len() .. n {
            G_.push(hash_to_curve(format!("IPA_G_{}_", i).as_bytes()).expect("Couldn't map hash to point on the curve"));
            H_.push(hash_to_curve(format!("IPA_H_{}_", i).as_bytes()).expect("Couldn't map hash to point on the curve"));
        }
    }
    (G_, H_, U_)
}
