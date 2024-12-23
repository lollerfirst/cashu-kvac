use once_cell::sync::Lazy;
use crate::{generators::{hash_to_curve, GENERATORS}, secp::{GroupElement, Scalar, SCALAR_ONE, SCALAR_ZERO}, transcript::CashuTranscript};
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
    let scalar_zero = Scalar::new(&SCALAR_ZERO);
    l.extend(vec![scalar_zero.clone(); pad_len].into_iter());
    l
}

fn pad_ones(mut l: Vec<Scalar>, to: usize) -> Vec<Scalar> {
    let pad_len = to - (l.len() % to);
    let scalar_one = Scalar::new(&SCALAR_ONE);
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
        let U_ = U_*&tetha;
        // ## END PROTOCOL 1 ##

        // Ensure len is a power of 2
        assert!(a.len().count_ones() == 1);
        let mut n = a.len();

        let mut inputs = Vec::new();

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
            inputs.push((L, R));

            let x = transcript.get_challenge(b"IPA_chall_");
            let x_inv = x.clone().invert();

            // fold a and b
            // TODO: Avoid cloning vector elements by iterating over an index and
            // moving the elements out of the vectors
            let mut new_a: Vec<Scalar> = Vec::new();
            for (a_i, a_n_i) in izip!(a[..n].iter(), a[n..].iter()) {
                new_a.push(a_i.clone() * &x + &(a_n_i.clone() * &x_inv));
            }
            let mut new_b: Vec<Scalar> = Vec::new();
            for (b_i, b_n_i) in izip!(b[..n].iter(), b[n..].iter()) {
                new_b.push(b_i.clone() * &x_inv + &(b_n_i.clone() * &x));
            }

            a = new_a;
            b = new_b;

            // fold generators
            // TODO: Same here
            let mut new_G: Vec<GroupElement> = Vec::new();
            for (G_i, G_n_i) in izip!(G_[..n].iter(), G_[n..2*n].iter()) {
                new_G.push(G_i.clone() * &x_inv + &(G_n_i.clone() * &x));
            }
            let mut new_H: Vec<GroupElement> = Vec::new();
            for (H_i, H_n_i) in izip!(H_[..n].iter(), H_[n..2*n].iter()) {
                new_H.push(H_i.clone() * &x + &(H_n_i.clone() * &x_inv));
            }

            G_ = new_G;
            H_ = new_H;
        }

        assert!(a.len() == 1 && b.len() == 1);
        
        InnerProductArgument { public_inputs: inputs, tail_end_scalars: (a.pop().unwrap(), b.pop().unwrap()) }
    }

    pub fn verify(self,
        transcript: &mut CashuTranscript,
        generators: (Vec<GroupElement>, Vec<GroupElement>, GroupElement),
        mut P: GroupElement,
        c: Scalar,
    ) -> bool {
        // Extract generators
        let (G_, H_, U_) = generators;

        // ## PROTOCOL 1 ##
        // `verify_folded_IPA` implements Protocol 2, a proof system for relation (3).
        // Protocol 1 (here) makes Protocol 2 into a proof system for relation (2).
        transcript.append_element(b"Com(P)_", &P);
        let tetha = transcript.get_challenge(b"tetha_chall_");

        // Switch generator U
        let U_ = U_*&tetha;
        // Tweak commitment P
        P = P + &(U_.clone()*&c);
        // ## END PROTOCOL 1 ##

        // ## PROTOCOL 2 ##
        // Extract scalars of the recursion end from IPA
        let (a, b) = self.tail_end_scalars;

        // Get challenges
        let mut challenges = Vec::new();
        for (L, R) in self.public_inputs.into_iter() {
            transcript.append_element(b"IPA_L_", &L);
            transcript.append_element(b"IPA_R_", &R);
            let x = transcript.get_challenge(b"IPA_chall_");
            let x_inv = x.clone().invert();

            P = P + &(L * &(x.clone()*&x)) + &(R * &(x_inv.clone()*&x_inv));
            challenges.push((x, x_inv));
        }

        // Recursion unrolling - We reduce O(n*log_2(n)) GroupElement multiplications
        // to O(n) by unrolling the prover's loop (we have the challenges) and
        // performing the O(log_2(n)) arithmetic operations on scalars instead.
        let mut G_aH_b = GENERATORS.O.clone();
        for (i, (G_i, H_i)) in G_.into_iter().zip(H_.into_iter()).enumerate() {
            let mut s = Scalar::new(&SCALAR_ONE);
            for (j, x) in challenges.iter().rev().enumerate() {
                // Use x if the j-th bit of i is 1
                // else use x^-1
                let bit = ((i>>j) & 1) == 1;
                if bit {
                    s = s * &x.0;
                } else {
                    s = s * &x.1;
                }
            }
            G_aH_b = G_aH_b + &(G_i * &(s.clone()*&a)) + &(H_i * &(s.invert()*&b));
        }

        G_aH_b + &(U_ * &(a*&b)) == P
    }
}
#[allow(unused_imports)]
mod tests{
    use itertools::izip;
    use crate::{generators::GENERATORS, secp::Scalar, transcript::CashuTranscript};
    use super::{get_generators, inner_product, pad_zeros, InnerProductArgument};

    #[allow(non_snake_case)]
    #[test]
    fn test_ipa() {
        let mut cli_tscr = CashuTranscript::new();
        let mut mint_tscr = CashuTranscript::new();

        let a = vec![Scalar::random(); 96];
        let b = vec![Scalar::random(); 96];
        let a = pad_zeros(a, 128);
        let b = pad_zeros(b, 128);
        let (G_, H_, _) = get_generators(128);
        let mut P = GENERATORS.O.clone();
        for (G_i, a_i, H_i, b_i) in izip!(G_.into_iter(), a.iter(), H_.into_iter(), b.iter()) {
            P = P + &(G_i * a_i) + &(H_i * b_i);
        }

        let ipa = InnerProductArgument::new(
            &mut cli_tscr,
            get_generators(128),
            P.clone(),
            a.clone(),
            b.clone(),
        );

        let c = inner_product(&a, &b);
        assert!(ipa.verify(&mut mint_tscr, get_generators(128), P, c))
    }
}