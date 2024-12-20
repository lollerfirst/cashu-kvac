use once_cell::sync::Lazy;
use crate::{generators::{hash_to_curve, GENERATORS}, secp::{GroupElement, Scalar}, transcript::CashuTranscript};
use itertools::izip;

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

fn pad_zeros(mut l: Vec<Scalar>, to: usize) -> Vec<Scalar> {
    let pad_len = to - (l.len() % to);
    let scalar_zero = Scalar::from(0);
    l.extend(vec![scalar_zero.clone(); pad_len]);
    l
}

fn pad_ones(mut l: Vec<Scalar>, to: usize) -> Vec<Scalar> {
    let pad_len = to - (l.len() % to);
    let scalar_one = Scalar::from(1);
    l.extend(vec![scalar_one.clone(); pad_len]);
    l
}

fn inner_product(l: &[Scalar], r: &[Scalar]) -> Scalar {
    let mut result = Scalar::from(0);
    for (left, right) in l.iter().zip(r.iter()) {
        result = result + (left.clone() * right.as_ref()).as_ref();
    }
    result
}

pub struct InnerProductArgument {
    public_inputs: Vec<(GroupElement, GroupElement)>,
    tail_end_scalars: (Scalar, Scalar),
}

// https://eprint.iacr.org/2017/1066.pdf
#[allow(non_snake_case)]
impl InnerProductArgument {
    pub fn new(
        transcript: &mut CashuTranscript,
        generators: (Vec<GroupElement>, Vec<GroupElement>, GroupElement),
        P: GroupElement,
        mut a: Vec<Scalar>,
        mut b: Vec<Scalar>,
    ) -> Self {
        assert!(a.len() == b.len());

        // Extract generators
        let (mut G_, mut H_, U_) = generators;

        // ## PROTOCOL 1 ##
        // `get_folded_IPA` implements Protocol 2, a proof system for relation (3).
        // Protocol 1 (here) makes Protocol 2 into a proof system for relation (2).
        transcript.append_element(b"Com(P)_", &P);
        let tetha = transcript.get_challenge(b"tetha_chall_");

        // Switch generator U
        let U_ = U_*tetha.as_ref();
        // ## END PROTOCOL 1 ##

        // Ensure len is a power of 2
        assert!(a.len().count_ones() == 1);
        let mut n = a.len();

        let mut ipa = Vec::new();

        // Recursive subdivision
        while n > 1 {
            n >>= 1;
            let c_left = inner_product(&a[..n], &b[n..]);
            let c_right = inner_product(&a[n..], &b[..n]);
            let mut L = U_.clone() * &c_left;
            for (a_i, G_i, b_i, H_i) in izip!(a[..n].iter(), G_[n..2*n].iter(), b[n..].iter(), H_[..n].iter()) {
                L = L + &(G_i.clone() * &a_i + &(H_i.clone() * &b_i))
            }
            let mut R = U_.clone() * &c_right;
            for (a_i, G_i, b_i, H_i) in izip!(a[n..].iter(), G_[..n].iter(), b[..n].iter(), H_[n..2*n].iter()) {
                R = R + &(G_i.clone() * &a_i + &(H_i.clone() * &b_i))
            }

            // Prover -> Verifier : L, R
            // Verifier -> Prover : x (challenge)

            transcript.append_element(b"IPA_L_", &L);
            transcript.append_element(b"IPA_R_", &R);
            ipa.push((L, R));

            let x = transcript.get_challenge(b"IPA_chall_");
            let x_inv = x.clone().invert();

            // fold a and b
            let mut new_a: Vec<Scalar> = Vec::new();
            for (a_i, a_n_i) in izip!(a[..n].into_iter(), a[n..].into_iter()) {
                new_a.push(a_i.clone() * &x + &(a_n_i.clone() * &x_inv));
            }
            let mut new_b: Vec<Scalar> = Vec::new();
            for (b_i, b_n_i) in izip!(b[n..].into_iter(), b[..n].into_iter()) {
                new_b.push(b_i.clone() * &x_inv + &(b_n_i.clone() * &x));
            }

            a = new_a;
            b = new_b;

            // fold generators
            let mut new_G: Vec<GroupElement> = Vec::new();
            for (G_i, G_n_i) in izip!(G_[..n].into_iter(), G_[n..].into_iter()) {
                new_G.push(G_i.clone() * &x_inv + &(G_n_i.clone() * &x));
            }
            let mut new_H: Vec<GroupElement> = Vec::new();
            for (H_i, H_n_i) in izip!(H_[..n].into_iter(), H_[n..].into_iter()) {
                new_H.push(H_i.clone() * &x + &(H_n_i.clone() * &x_inv));
            }

            G_ = new_G;
            H_ = new_H;
        }

        assert!(a.len() == 1 && b.len() == 1);
        
        InnerProductArgument { public_inputs: ipa, tail_end_scalars: (a[0].clone(), b[0].clone())}
    }
}