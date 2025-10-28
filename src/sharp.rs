use num_bigint::BigInt;
use num_traits::FromBytes;

use crate::{ errors::Error, generators::{hash_to_curve, GENERATORS}, models::AmountAttribute, secp::{GroupElement, Scalar, SCALAR_ZERO}, transcript::CashuTranscript
};
use bitcoin::{secp256k1::constants::CURVE_ORDER};
use bitcoin::hashes::sha512_256::Hash as Sha512_256;
use bitcoin::hashes::Hash;

pub fn find_3_squares(value: u64) -> Result<(u64, u64, u64), Error> {
    // Fast check using Legendre's three-square theorem:
    // n is representable iff it's NOT of the form 4^a (8b+7).
    fn is_excluded_by_legendre(mut n: u64) -> bool {
        while n % 4 == 0 {
            n /= 4;
        }
        n % 8 == 7
    }

    if value == 0 {
        return Ok((0, 0, 0));
    }
    if is_excluded_by_legendre(value) {
        return Err(Error::ThreeSquaresFailure);
    }

    // Try to find integers 0 <= x <= y <= z with x^2 + y^2 + z^2 = value.
    // Iterate x from 0..=sqrt(value), then y from x..=sqrt(value - x^2),
    // compute remaining rem = value - x^2 - y^2 and check if it's a perfect square.
    let vmax = (value as f64).sqrt() as u64;
    for x in 0..=vmax {
        let x2 = (x as u128) * (x as u128);
        if x2 > value as u128 { break; }
        let rem1 = value as u128 - x2;
        let ymax = (rem1 as f64).sqrt() as u64;
        for y in x..=ymax {
            let y2 = (y as u128) * (y as u128);
            if y2 > rem1 { break; }
            let rem2 = rem1 - y2;
            // check if rem2 is a perfect square
            let z = (rem2 as f64).sqrt() as u64;
            for candidate_z in z..=z+1 {
                let z2 = (candidate_z as u128) * (candidate_z as u128);
                if z2 == rem2 {
                    // return sorted tuple (x,y,z) where x<=y<=z
                    return Ok((x, y, candidate_z));
                }
                if z2 > rem2 { break; }
            }
        }
    }

    // In theory, Legendre check should have excluded impossible cases.
    // If no decomposition found (shouldn't happen), return failure.
    Err(Error::ThreeSquaresFailure)
}

fn get_rast_3dec_generators(n: u64) -> Vec<GroupElement> {
    (0..n*3).map(|m| {
        let j = m % 3;
        let i = m / 3;
        hash_to_curve(format!("CASHU_SHARP_RAST_3DEC_{i}_{j}").as_bytes())
                .expect("Couldn't map hash to point on the curve")
    }).collect()
}

fn get_masks_generators(n: u64) -> Vec<GroupElement> {
    (0..n+1).map(|m| {
        hash_to_curve(format!("CASHU_SHARP_MASKS_{m}").as_bytes())
                .expect("Couldn't map hash to point on the curve")
    }).collect()
}

fn get_rast_3dec_masks_generators(n: u64) -> Vec<GroupElement> {
    (0..n+1).map(|m| {
        hash_to_curve(format!("CASHU_SHARP_RAST_3DEC_MASKS_{m}").as_bytes())
                .expect("Couldn't map hash to point on the curve")
    }).collect()
}

fn get_generators_second_phase(n: u64) -> Vec<GroupElement> {
    (0..n+1).map(|m| {
        hash_to_curve(format!("CASHU_SHARP_OPENINGS_{m}").as_bytes())
                .expect("Couldn't map hash to point on the curve")
    }).collect()
}
#[allow(non_snake_case)]
pub struct SharpPOSO {
    //pub C_x: GroupElement,
}

// Paper: https://eprint.iacr.org/2022/1153.pdf
#[allow(non_snake_case)]
impl SharpPOSO {
    pub fn new(
        transcript: &mut CashuTranscript,
        amount_attributes: &[AmountAttribute],
        range_max: u64,
    ) -> Result<Self, Error> {
        // PARAMETER SETUP:
        // We use the same group for proof of short opening and proof of decomposition   
        if amount_attributes.len() == 0 {
            return Err(Error::EmptyList);
        }
        // N is the number of attributes to prove the range of
        let N = amount_attributes.len() as u64;

        if range_max == 0 {
            return Err(Error::InvalidRangeBound)
        }
        let B = range_max;
        let P = BigInt::from_be_bytes(&CURVE_ORDER);
        
        // Y is the challenge space size. For exact [0, B] membership, it must be Y < 4B
        let Y = BigInt::from(4 * B - 1);
        // R is the number of repetitions. It must be that (Y + 1)^R - 1 <= CURVE_ORDER
        let mut R = 1;
        let mut tmp: BigInt = &Y + 1;
        while &tmp - 1 <= P {
            R += 1;
            tmp *= &Y + 1;
        }
        R -= 1;

        // L_x is the masking overhead for the short witnesses
        // We have that 18((BY+1)*L_x)^2 <= P must hold
        let mut L_x = BigInt::from(1);
        tmp = (B*&Y+1) * &L_x;
        tmp.pow(2);
        tmp *= 18;
        while tmp <= P {
            L_x <<= 1;
            tmp = (B*&Y+1) * &L_x;
            tmp.pow(2);
            tmp *= 18;
        }
        L_x >>= 1;

        if L_x == BigInt::from(0) {
            return Err(Error::ParameterSetupFailure)
        }

        let apply_mask = |value: Scalar, mask: Scalar, V: &BigInt, L: &BigInt| -> Result<Scalar, Error> {
            let r = (BigInt::from_be_bytes(&mask.to_bytes())) % (((V + 1)*L) + 1);
            let v = BigInt::from_be_bytes(&value.to_bytes());
            let z = v + r;
            if z > (((V + 1)*L) + 1) {
                return Err(Error::MaskingFailure);
            }
            Ok(Scalar::try_from(&z)?)
        };

        let get_mask = |V: &BigInt, L: &BigInt| -> Result<Scalar, Error> {
            let nonce = Scalar::random();
            let r = (BigInt::from_be_bytes(&nonce.to_bytes())) % (((V + 1)*L) + 1);
            Ok(Scalar::try_from(&r)?)
        };

        transcript.domain_sep(b"SharpPOSO_Statement_");


        // MARK: - PHASE 1

        // C_x is our aggregate commitment: C_x = 𝜮i r_i*G_blind + 𝜮i a_i*G_amount
        // r_x = 𝜮i r_i*G_blind, so C_x = r_x*G_blind + 𝜮i a_i*G_amount
        let mut C_x: GroupElement = GENERATORS.O;
        let mut r_x: Scalar = Scalar::new(&SCALAR_ZERO);
        for attribute in amount_attributes.iter() {
            C_x = C_x + &attribute.commitment();
            r_x = r_x + &attribute.r;
        }
        transcript.append_element(b"C_x", &C_x);

        // (Algorithm 2, Phase 1, line 1)
        // For each attribute's amount a_i, find y_(i,1), y_(i,2), y_(i,3)
        // s.t. 4 * a_i(B - a_i) + 1 = 𝜮j y_(i,j)^2.
        let mut y_list: Vec<Scalar> = vec![];
        for attribute in amount_attributes.iter() {
            let a_i = u64::from(&attribute.a);
            if a_i > B {
                return Err(Error::OutOfRangeError)
            }
            let v_i = 4 * a_i * (B - a_i) + 1;
            let (y_i1, y_i2, y_i3) = find_3_squares(v_i)?;

            // We insert a_i itself inside this tuple
            y_list.extend_from_slice(&[Scalar::from(a_i), Scalar::from(y_i1), Scalar::from(y_i2), Scalar::from(y_i3)]);
        }

        // (Algorithm 2, Phase 1, line 2)
        // We need to get generators and masking factors
        let masks_generators = get_masks_generators(N);
        let rast_3dec_masks_generators = get_rast_3dec_masks_generators(R);
        let rast_3dec_generators = get_rast_3dec_generators(N);
        let r_y = Scalar::random();


        let mut C_y = masks_generators[0] * &r_y;
        for i in 0..N {
            let y_1 = y_list[(i*4+1) as usize];
            let y_2 = y_list[(i*4+2) as usize];
            let y_3 = y_list[(i*4+3) as usize];
            C_y = C_y + &(rast_3dec_generators[(3*i) as usize] * &y_1)
                + &(rast_3dec_generators[(3*i+1) as usize] * &y_2)
                + &(rast_3dec_generators[(3*i+2) as usize] * &y_3)
        }
        let mut mu_list: Vec<Scalar>;
        let mut gamma_list: Vec<Scalar>;
        let mut zeta_list: Vec<Scalar>;
        let R_x = 4*N*B*&Y;

        // Masking can succeed with probability 1-1/(L+1), and (1-1/(L+1))^R over all R repetitions
        // Therefore, we should be looking at the following probability of failure at iteration i of this loop:
        // (1-(1-1/(L+1))^R)^i
        loop {
            // We carry out operations on a cloned transcript,
            // so we don't write on the real one. If successful,
            // apply the same operations to the real one.
            let mut tmp_transcript = transcript.clone();
            let mut tmp_C_y = C_y;

            let mut tmp_mu_list: Vec<Scalar> = vec![];           
            for i in 0..R {
                let mu_k = get_mask(&R_x, &L_x)?;

                tmp_C_y = tmp_C_y + &(rast_3dec_masks_generators[i as usize] * &mu_k);
                tmp_mu_list.push(mu_k);
            }
            
            tmp_transcript.append_element(b"C_y", &tmp_C_y);

            // Get the challenges for every integer in the sq-decomp, for every x in the batch,
            // for every k in the repetitions R
            let tmp_gamma_list: Vec<Scalar> = (0..4*N*R).map(|_| tmp_transcript.get_challenge(b"short_chall")).collect();
            
            let mut shortness_failure = false;
            let mut tmp_zeta_list: Vec<Scalar> = vec![];
            for k in 0..R {
                let mut sum = Scalar::new(&SCALAR_ZERO);
                for i in 0..N {
                    for j in 0..4 {
                        let gamma_index = k*N*4 + i*4 + j;
                        let gamma_ijk = tmp_gamma_list[gamma_index as usize];
                        let y_ij = y_list[(i*4 + j) as usize];
                        sum = sum + &(y_ij * &gamma_ijk);
                    }
                }
                // Try and mask the sum. If it fails we break out of the this for and set `too_big = true`
                let masked_sum = apply_mask(sum, tmp_mu_list[k as usize], &R_x, &L_x);
                match masked_sum {
                    Ok(m) => tmp_zeta_list.push(m),
                    Err(Error::MaskingFailure) => { shortness_failure = true; break; },
                    Err(e) => return Err(e)
                };
            };

            // If we get a masking failure, retry.
            if shortness_failure {
                continue;
            }

            // Otherwise, apply the changes to the trascript, C_y, mu_list and gamma_list.
            // And break out of the loop
            C_y = tmp_C_y;
            mu_list = tmp_mu_list;
            gamma_list = tmp_gamma_list;
            zeta_list = tmp_zeta_list;

            transcript.append_element(b"C_y", &C_y);
            let _ = (0..4*N*R).map(|_| transcript.get_challenge(b"short_chall"));

            break;
        }
        
        // ### END PHASE 1 ###

        // MARK: - PHASE 2

        Ok(Self {

        })
    }
}

#[cfg(test)]
mod tests {
    use super::*; // or crate::path::to::find_3_squares

    #[test]
    fn test_find_3_squares() {
        // sample values of the form 4*x + 1 (including small and larger ones)
        let samples: &[u64] = &[
            1,      // 4*0+1
            5,      // 4*1+1
            9,      // 4*2+1
            13,     // 4*3+1
            21,     // 4*5+1
            101,    // 4*25+1
            1001,   // 4*250+1
            4*12345 + 1,
            4*1_000_000 + 1,
        ];

        for &n in samples {
            match find_3_squares(n) {
                Ok((a,b,c)) => {
                    // ensure they are valid and sum correctly
                    let sum = (a as u128)*(a as u128) + (b as u128)*(b as u128) + (c as u128)*(c as u128);
                    assert_eq!(sum as u64, n, "Decomposition incorrect for n={}", n);
                }
                Err(err) => panic!("find_3_squares failed for n={} with error {:?}", n, err),
            }
        }
    }
}