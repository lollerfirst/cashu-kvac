use num_bigint::BigInt;
use num_traits::FromBytes;

use crate::{
    errors::Error,
    generators::{hash_to_curve, GENERATORS},
    models::AmountAttribute,
    secp::{GroupElement, Scalar, SCALAR_ZERO},
    transcript::CashuTranscript,
};
use bitcoin::secp256k1::constants::CURVE_ORDER;
use num_traits::Zero;

/// Finds three squares that sum to a given value using Legendre's three-square theorem.
/// 
/// This function implements a solution to represent a given positive integer as a sum of three squares,
/// i.e., find x, y, z such that x² + y² + z² = value. The implementation uses Legendre's three-square
/// theorem which states that a positive integer can be represented as a sum of three squares if and
/// only if it is not of the form 4ᵃ(8b + 7).
/// 
/// # Arguments
/// * `value` - The positive integer to decompose into three squares
/// 
/// # Returns
/// * `Ok((x, y, z))` - A tuple of three non-negative integers whose squares sum to `value`
/// * `Err(Error::ThreeSquaresFailure)` - If the value cannot be represented as sum of three squares
/// 
/// # Examples
/// ```
/// let (x, y, z) = find_3_squares(21)?;
/// assert_eq!(x*x + y*y + z*z, 21);
/// ```
///
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
        if x2 > value as u128 {
            break;
        }
        let rem1 = value as u128 - x2;
        let ymax = (rem1 as f64).sqrt() as u64;
        for y in x..=ymax {
            let y2 = (y as u128) * (y as u128);
            if y2 > rem1 {
                break;
            }
            let rem2 = rem1 - y2;
            // check if rem2 is a perfect square
            let z = (rem2 as f64).sqrt() as u64;
            for candidate_z in z..=z + 1 {
                let z2 = (candidate_z as u128) * (candidate_z as u128);
                if z2 == rem2 {
                    // return sorted tuple (x,y,z) where x<=y<=z
                    return Ok((x, y, candidate_z));
                }
                if z2 > rem2 {
                    break;
                }
            }
        }
    }

    // In theory, Legendre check should have excluded impossible cases.
    // If no decomposition found (shouldn't happen), return failure.
    Err(Error::ThreeSquaresFailure)
}

/// Generates a sequence of group elements for use in RAST 3-decomposition proof.
/// 
/// # Arguments
/// * `n` - The number of elements needed (will generate 3n generators)
/// 
/// # Returns
/// * `Vec<GroupElement>` - Vector of group elements used as generators
/// 
/// This is an internal function used by the SharpPOSO proof system.
fn get_rast_3dec_generators(n: u64) -> Vec<GroupElement> {
    (0..n * 3)
        .map(|m| {
            let j = m % 3;
            let i = m / 3;
            hash_to_curve(format!("CASHU_SHARP_RAST_3DEC_{i}_{j}").as_bytes())
                .expect("Couldn't map hash to point on the curve")
        })
        .collect()
}

/// Generates mask generators for the RAST 3-decomposition proof.
/// 
/// # Arguments
/// * `n` - The number of masks needed (will generate n+1 generators)
/// 
/// # Returns
/// * `Vec<GroupElement>` - Vector of group elements used as mask generators
/// 
/// This is an internal function used by the SharpPOSO proof system.
fn get_rast_3dec_masks_generators(n: u64) -> Vec<GroupElement> {
    (0..n + 1)
        .map(|m| {
            hash_to_curve(format!("CASHU_SHARP_RAST_3DEC_MASKS_{m}").as_bytes())
                .expect("Couldn't map hash to point on the curve")
        })
        .collect()
}

/// Generates generators for the second phase of the proof.
/// 
/// # Arguments
/// * `n` - The number of generators needed (will generate n+1 generators)
/// 
/// # Returns
/// * `Vec<GroupElement>` - Vector of group elements used as generators in phase 2
/// 
/// This is an internal function used by the SharpPOSO proof system.
fn get_generators_second_phase(n: u64) -> Vec<GroupElement> {
    (0..n + 1)
        .map(|m| {
            hash_to_curve(format!("CASHU_SHARP_OPENINGS_{m}").as_bytes())
                .expect("Couldn't map hash to point on the curve")
        })
        .collect()
}

/// Implementation of Short Relaxed Range Proofs (SharpPOSO).
/// 
/// This struct implements the proof system described in the paper:
/// "Short Relaxed Range Proofs" (https://eprint.iacr.org/2022/1153.pdf)
/// 
/// The proof system allows proving that a committed value lies within a specific range [0, B]
/// without revealing the actual value. This implementation supports batch proofs for multiple
/// values simultaneously.
/// 
/// The proof is split into two phases:
/// 1. A phase for handling the range proof using three-square decomposition
/// 2. A phase for proving the consistency of the decomposition
#[allow(non_snake_case)]
pub struct SharpPOSO {
    /// C_y
    pub C_y: GroupElement,
    /// 𝛇_k
    pub zeta_list: Vec<Scalar>,
    /// C*
    pub C_star: GroupElement,
    /// z_x_i for each x_i
    pub z_x_list: Vec<Scalar>,
    /// z_y_ij for each y_ij (3 squares of x_i)
    pub z_y_list: Vec<Scalar>,
    pub t_x_list: Vec<Scalar>,
    pub t_y: Scalar,
    pub t_star: Scalar,
    pub tau_list: Vec<Scalar>,
    pub d_h: Scalar,
}

// Implementation based on "Short Relaxed Range Proofs" (https://eprint.iacr.org/2022/1153.pdf)
#[allow(non_snake_case)]
impl SharpPOSO {
    /// Creates a new SharpPOSO proof for a batch of amount commitments.
    /// 
    /// # Arguments
    /// * `transcript` - A mutable reference to the Cashu transcript for the proof
    /// * `amount_attributes` - Slice of amount attributes to prove are in range
    /// * `range_max` - The upper bound B of the range [0, B] to prove
    /// 
    /// # Returns
    /// * `Ok(Self)` - A new SharpPOSO proof if successful
    /// * `Err(Error)` - If the proof creation fails
    /// 
    /// # Note
    /// The proof follows the algorithm described in Section 4 of the Short Relaxed Range Proofs paper.
    pub fn new(
        transcript: &mut CashuTranscript,
        amount_attributes: &[AmountAttribute],
        range_max: u64,
    ) -> Result<Self, Error> {
        // MARK: - PARAMETERS SETUP
        // We use the same group for short opening and decomposition
        if amount_attributes.is_empty() {
            return Err(Error::EmptyList);
        }
        // N is the number of attributes to prove the range of
        let N = amount_attributes.len() as u64;

        if range_max == 0 {
            return Err(Error::InvalidRangeBound);
        }
        let B = range_max;
        let P = BigInt::from_be_bytes(&CURVE_ORDER);

        // Y is the challenge space size. For exact [0, B] membership, Y < 4B
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
        // 18((B·Y+1)·L_x)^2 ≤ SECP256K1_ORDER
        let mut L_x = BigInt::from(1);
        tmp = (B * &Y + 1) * &L_x;
        tmp.pow(2);
        tmp *= 18;
        while tmp <= P {
            L_x <<= 1;
            tmp = (B * &Y + 1) * &L_x;
            tmp.pow(2);
            tmp *= 18;
        }
        L_x >>= 1;

        if L_x.is_zero() {
            return Err(Error::ParameterSetupFailure);
        }

        let apply_mask =
            |value: Scalar, mask: Scalar, V: &BigInt, L: &BigInt| -> Result<Scalar, Error> {
                let r = (BigInt::from_be_bytes(&mask.to_bytes())) % (((V + 1) * L) + 1);
                let v = BigInt::from_be_bytes(&value.to_bytes());
                let z = v + r;
                if z > (((V + 1) * L) + 1) {
                    return Err(Error::MaskingFailure);
                }
                Scalar::try_from(&z)
            };

        let get_mask = |V: &BigInt, L: &BigInt| -> Result<Scalar, Error> {
            let nonce = Scalar::random();
            let r = (BigInt::from_be_bytes(&nonce.to_bytes())) % (((V + 1) * L) + 1);
            Scalar::try_from(&r)
        };

        transcript.domain_sep(b"SharpPOSO_Statement_");

        // MARK: - PHASE 1

        // A list with all the amount commitments C_x_i = [C_x_0, C_x_1, ...]
        // A list with all the blinding factors r_x_i = [r_x_0, r_x_1, ...]
        let C_x_list: Vec<GroupElement> = amount_attributes
            .iter()
            .map(|att| att.commitment())
            .collect();
        let x_list: Vec<Scalar> = amount_attributes.iter().map(|att| att.a).collect();
        let r_x_list: Vec<Scalar> = amount_attributes.iter().map(|att| att.r).collect();
        for C_x_i in C_x_list.iter() {
            transcript.append_element(b"C_x_i", C_x_i);
        }

        // (Algorithm 2, Phase 1, line 1)
        // For each attribute's amount a_i, find y_(i,1), y_(i,2), y_(i,3)
        // s.t. 4 * a_i(B - a_i) + 1 = 𝜮j y_(i,j)^2.
        let mut y_list: Vec<Scalar> = vec![];
        for attribute in amount_attributes.iter() {
            let a_i = u64::from(&attribute.a);
            let v_i = 4 * a_i * (B - a_i) + 1;
            let (y_i1, y_i2, y_i3) = find_3_squares(v_i)?;

            // We insert a_i itself inside this tuple
            y_list.extend_from_slice(&[Scalar::from(y_i1), Scalar::from(y_i2), Scalar::from(y_i3)]);
        }

        // (Algorithm 2, Phase 1, line 2)
        // We need to get generators and masking factors
        let rast_3dec_masks_generators = get_rast_3dec_masks_generators(R);
        let rast_3dec_generators = get_rast_3dec_generators(N);
        let r_y = Scalar::random();

        let mut C_y = GENERATORS.G_blind * &r_y;
        for i in 0..N {
            let y_1 = y_list[(i * 3) as usize];
            let y_2 = y_list[(i * 3 + 1) as usize];
            let y_3 = y_list[(i * 3 + 2) as usize];
            C_y += &((rast_3dec_generators[(3 * i) as usize] * &y_1)
                + &(rast_3dec_generators[(3 * i + 1) as usize] * &y_2)
                + &(rast_3dec_generators[(3 * i + 2) as usize] * &y_3))
        }
        let mu_list: Vec<Scalar>;
        let gamma_list: Vec<Scalar>;
        let zeta_list: Vec<Scalar>;
        let R_x = 4 * N * B * &Y;

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

                tmp_C_y += &(rast_3dec_masks_generators[i as usize] * &mu_k);
                tmp_mu_list.push(mu_k);
            }

            tmp_transcript.append_element(b"C_y", &tmp_C_y);

            // Get short challenges for every integer in the sq-decomp, for every x in the batch,
            // for every k in the repetitions R
            let tmp_gamma_list: Vec<Scalar> = (0..4 * N * R)
                .map(|_| {
                    let big_chall = BigInt::from_be_bytes(
                        &tmp_transcript.get_challenge(b"short_chall").to_bytes(),
                    );
                    Scalar::try_from(&(big_chall % &Y)) // short chall
                })
                .collect::<Result<Vec<Scalar>, Error>>()?;

            let mut shortness_failure = false;
            let mut tmp_zeta_list: Vec<Scalar> = vec![];
            for k in 0..R {
                let mut sum = Scalar::new(&SCALAR_ZERO);
                for i in 0..N {
                    for j in 0..4 {
                        let gamma_index = k * N * 4 + i * 4 + j;
                        let gamma_ijk = tmp_gamma_list[gamma_index as usize];
                        let y_ij = y_list[(i * 4 + j) as usize];
                        sum += &(y_ij * &gamma_ijk);
                    }
                }
                // Try and mask the sum. If it fails we break out of this for and set `too_big = true`
                let masked_sum = apply_mask(sum, tmp_mu_list[k as usize], &R_x, &L_x);
                match masked_sum {
                    Ok(m) => tmp_zeta_list.push(m),
                    Err(Error::MaskingFailure) => {
                        shortness_failure = true;
                        break;
                    }
                    Err(e) => return Err(e),
                };
            }

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
            (0..4 * N * R).for_each(|_| {
                transcript.get_challenge(b"short_chall");
            });

            break;
        }

        // ### END PHASE 1 ###

        // MARK: - PHASE 2

        // Get masking factor for r_y
        let rr_y = Scalar::random();

        // Get masking factors for amount masking factors (xr_list)
        let rr_x_list = (0..N).map(|_| Scalar::random()).collect::<Vec<Scalar>>();

        // Get masking factors for x_i and y_i decomposition
        let xr_list: Vec<Scalar> = (0..N).map(|_| Scalar::random()).collect();
        let yr_list: Vec<Scalar> = (0..3 * N).map(|_| Scalar::random()).collect();
        let mu_r_list: Vec<Scalar> = (0..R).map(|_| Scalar::random()).collect();

        let mut d_list: Vec<Scalar> = vec![];
        for k in 0..R {
            let mut sum = Scalar::new(&SCALAR_ZERO);

            for i in 0..N {
                // x_i == y_i0, therefore xr_i == yr_i0
                let gamma_index = k * N * 4 + i * 4;
                let gamma_i0k = gamma_list[gamma_index as usize];
                let yr_i0 = xr_list[i as usize];
                sum += &(yr_i0 * &gamma_i0k);

                for j in 0..3 {
                    let gamma_index = k * N * 4 + i * 4 + j + 1;
                    let gamma_ijk = gamma_list[gamma_index as usize];
                    let yr_ij = yr_list[(i * 3 + j) as usize];
                    sum += &(yr_ij * &gamma_ijk);
                }
            }

            let d_k = sum + &mu_r_list[k as usize];
            d_list.push(d_k);
        }

        // Set D_x_list = [r_x_0 * G_blind + xr_i * G_amount, ...]
        // Set D_y = rr_y * G_blind + 𝜮{i=1 to N} 𝜮{j=1 to 3} yr_{i,j} * G_{i,j} + 𝜮{k=1 to R} mu_r_k * G_k
        let D_x: Vec<GroupElement> = (0..N)
            .map(|i| {
                GENERATORS.G_blind * &rr_x_list[i as usize]
                    + &(GENERATORS.G_amount * &xr_list[i as usize])
            })
            .collect();
        let mut D_y = GENERATORS.G_blind * &rr_y;
        for i in 1..N + 1 {
            for j in 0..3 {
                D_y += &(rast_3dec_generators[(i * 3 + j) as usize]
                    * &yr_list[(i * 4 + j + 1) as usize]);
            }
        }
        for k in 0..R {
            D_y += &(rast_3dec_masks_generators[k as usize] * &mu_r_list[k as usize]);
        }

        let (r_star, rr_star) = (Scalar::random(), Scalar::random());

        let scalar_4B = Scalar::from(4_u64) * &Scalar::from(B);
        let scalar_8 = Scalar::from(8_u64);
        let scalar_4 = Scalar::from(4_u64);
        let scalar_2 = Scalar::from(2_u64);

        let H_list = get_generators_second_phase(N);

        // C* = r* · H0 + 𝜮 𝛼(*)_1,i·Hi
        // D* = rr* · H0 + 𝜮 𝛼(*)_0,i·Hi
        let mut C_star = H_list[0] * &r_star;
        let mut D_star = H_list[0] * &rr_star;

        for i in 0..N {
            // alpha_*_1_i = 4·B·rr_x_i - 8·a_i·rr_x_i - 2𝜮 y_ij · yr_ij
            // alpha_*_0_i = -(4·xr_i^2 + 𝜮 yr_ij^2)
            let mut alpha_star_1_i = xr_list[i as usize] * &scalar_4B
                - &(xr_list[i as usize] * &amount_attributes[i as usize].a * &scalar_8);
            let mut alpha_star_0_i = -(scalar_4 * &xr_list[i as usize] * &xr_list[i as usize]);
            let mut sigma_1: Scalar = Scalar::new(&SCALAR_ZERO);
            let mut sigma_2: Scalar = Scalar::new(&SCALAR_ZERO);
            for j in 1..4 {
                sigma_1 += &(y_list[(i * 4 + j + 1) as usize] * &yr_list[(i * 4 + j + 1) as usize]);
                sigma_2 +=
                    &(yr_list[(i * 4 + j + 1) as usize] * &yr_list[(i * 4 + j + 1) as usize]);
            }
            alpha_star_1_i += &(-sigma_1 * &scalar_2);
            alpha_star_0_i += &-sigma_2;

            C_star += &(H_list[(i + 1) as usize] * &alpha_star_1_i);
            D_star += &(H_list[(i + 1) as usize] * &alpha_star_0_i);
        }

        // Prover sends (C*, {Dx_i}_1^N, Dy, D*, {d_k}_1^R) to verifier
        transcript.append_element(b"C_*", &C_star);

        // Verifier responds with a challenge
        let gamma = transcript.get_challenge(b"gamma_large_chall");

        // t_y  = 𝜸 · r_y + rr_y
        let t_y = gamma * &r_y + &rr_y;

        // t_x_i  = 𝜸 · r_x_i + rr_x_i
        let t_x_list: Vec<Scalar> = (0..N)
            .map(|i| gamma * &r_x_list[i as usize] + &rr_x_list[i as usize])
            .collect();

        // z_i = 𝜸 · x_i + xr_i
        let z_x_list: Vec<Scalar> = (0..N)
            .map(|i| gamma * &x_list[i as usize] + &xr_list[i as usize])
            .collect();

        // z_i_j = 𝜸 · y_i_j + yr_i
        let mut z_y_list: Vec<Scalar> = vec![];
        for i in 0..N {
            for j in 1..4 {
                let z_ij =
                    gamma * &y_list[(i * 4 + j) as usize] + &yr_list[(i * 3 + j - 1) as usize];
                z_y_list.push(z_ij);
            }
        }

        // t* = 𝜸 · r* + rr*
        let t_star = gamma * &r_star + &rr_star;

        // 𝜏_k = 𝜸 · μ + μr
        let tau_list: Vec<Scalar> = (0..R)
            .map(|k| gamma * &mu_list[k as usize] + &mu_r_list[k as usize])
            .collect();

        // Saving proof size by compressing {Dx, Dy, D*, d_}
        (0..N).for_each(|i| transcript.append_element(b"Dx", &D_x[i as usize]));
        transcript.append_element(b"Dy", &D_y);
        transcript.append_element(b"D*", &D_star);
        (0..R).for_each(|k| {
            transcript.append_element(
                b"d_k",
                &hash_to_curve(&d_list[k as usize].to_bytes()).unwrap(),
            )
        });

        let d_h = transcript.get_challenge(b"D_h");

        Ok(Self {
            C_y,
            zeta_list,
            C_star,
            z_x_list,
            z_y_list,
            t_x_list,
            t_y,
            t_star,
            tau_list,
            d_h,
        })
    }

    /// Verifies a SharpPOSO proof.
    /// 
    /// This method verifies that all committed amounts in the proof lie within the range [0, B].
    /// 
    /// # Arguments
    /// * `transcript` - A mutable reference to the Cashu transcript used in proof creation
    /// * `amount_commitments` - Slice of group elements representing the amount commitments
    /// * `range_max` - The upper bound B of the range [0, B] being proved
    /// 
    /// # Returns
    /// * `bool` - true if the proof verifies correctly, false otherwise
    /// 
    /// # Note
    /// The verification follows the algorithm described in Section 4 of the Short Relaxed Range Proofs paper.
    pub fn verify(
        &self,
        transcript: &mut CashuTranscript,
        amount_commitments: &[GroupElement],
        range_max: u64,
    ) -> bool {
        // MARK: - PARAMETERS SETUP
        // We use the same group for short opening and decomposition
        if amount_commitments.is_empty() {
            return false;
        }
        // N is the number of attributes to prove the range of
        let N = amount_commitments.len() as u64;

        if range_max == 0 {
            return false;
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
        // 18((B·Y+1)·L_x)^2 ≤ SECP256K1_ORDER
        let mut L_x = BigInt::from(1);
        tmp = (B * &Y + 1) * &L_x;
        tmp.pow(2);
        tmp *= 18;
        while tmp <= P {
            L_x <<= 1;
            tmp = (B * &Y + 1) * &L_x;
            tmp.pow(2);
            tmp *= 18;
        }
        L_x >>= 1;

        if L_x == BigInt::from(0) {
            return false;
        }

        transcript.domain_sep(b"SharpPOSO_Statement_");

        for C_x_i in amount_commitments.iter() {
            transcript.append_element(b"C_x_i", C_x_i);
        }

        // Extract C_y and get challenges
        let C_y = self.C_y;

        transcript.append_element(b"C_y", &C_y);
        (0..4 * N * R).for_each(|_| {
            transcript.get_challenge(b"short_chall");
        });

        // Get short challenges for every integer in the sq-decomp, for every x in the batch,
        // for every k in the repetitions R
        let gamma_list: Vec<Scalar> = (0..4 * N * R)
            .map(|_| {
                let big_chall =
                    BigInt::from_be_bytes(&transcript.get_challenge(b"short_chall").to_bytes());
                Scalar::try_from(&(big_chall % &Y)) // short chall
            })
            .collect::<Result<Vec<Scalar>, Error>>()
            .unwrap();

        // Verify each 𝛇_k is short
        if (self.zeta_list.len() as u64) < R {
            return false;
        }

        let upper_bound = 4 * N * B * Y;
        for zeta_k in self.zeta_list.iter() {
            // 𝛇_k ≤ (4·N·B·Y + 1)L_x
            if BigInt::from_be_bytes(&zeta_k.to_bytes()) > upper_bound {
                return false;
            }
        }

        // Prover sends (C*, {Dx_i}_1^N, Dy, D*, {d_k}_1^R) to verifier
        transcript.append_element(b"C_*", &self.C_star);

        // Verifier responds with a challenge
        let gamma = transcript.get_challenge(b"gamma_large_chall");

        // Compute Fx_i = -𝜸·C_x_i + t_x_i·G_blind + z_x_i·G_amount
        let mut Fx_list = vec![];

        // No surprises
        if N != self.t_x_list.len() as u64 || N != self.z_x_list.len() as u64 {
            return false;
        }

        for i in 0..N {
            let Fx_i = -amount_commitments[i as usize] * &gamma
                + &(GENERATORS.G_blind * &self.t_x_list[i as usize])
                + &(GENERATORS.G_amount * &self.z_x_list[i as usize]);
            Fx_list.push(Fx_i);
        }

        let generators_3dec = get_rast_3dec_generators(N);
        let generators_3dec_masks = get_rast_3dec_masks_generators(R);
        let mut F_y = -self.C_y * &gamma + &(GENERATORS.G_blind * &self.t_y);
        for i in 0..N {
            for j in 0..3 {
                F_y +=
                    &(generators_3dec[(i * 3 + j) as usize] * &self.z_y_list[(i * 3 + j) as usize]);
            }
        }
        for k in 0..R {
            F_y += &(generators_3dec_masks[k as usize] * &self.tau_list[k as usize]);
        }

        // No surprises
        if self.z_y_list.len() != (3 * N) as usize {
            return false;
        }

        // Verify the correctness of the short witnesses 𝛇_k
        let mut f_list = vec![];
        for k in 0..R {
            let mut f_k = -(self.zeta_list[k as usize] * &gamma);
            for i in 0..N {
                // y_i0 = x_i0
                f_k += &(self.z_x_list[i as usize] * &gamma_list[(k * N * 4 + i * 4) as usize]);

                for j in 0..3 {
                    f_k += &(self.z_y_list[(i * 3 + j) as usize]
                        * &gamma_list[(k * N * 4 + i * 4 + j + 1) as usize]);
                }
            }

            f_k += &self.tau_list[k as usize];
            f_list.push(f_k);
        }

        let mut f_star_list = vec![];

        let scalar_4 = Scalar::from(4);
        let scalar_B = Scalar::from(B);
        let gamma_squared = gamma * &gamma;

        // f_i* = 4·z_x_i·(𝜸B - z_x_i) + 𝜸^2 - 𝜮 z_y_ij^2
        for i in 0..N {
            let z_x_i = self.z_x_list[i as usize];
            let mut f_star_i = scalar_4 * &z_x_i * &(gamma * &scalar_B - &z_x_i) + &gamma_squared;
            for j in 0..3 {
                let z_y_ij = self.z_y_list[(i * 3 + j) as usize];
                f_star_i += &(-z_y_ij * &z_y_ij);
            }
            f_star_list.push(f_star_i);
        }

        let H_list = get_generators_second_phase(N);

        // F* = -𝜸C* + t* · H0 + 𝜮 f_i* · H_i
        let mut F_star = -self.C_star * &gamma + &(H_list[0] * &self.t_star);
        for i in 0..N {
            F_star += &(H_list[(i + 1) as usize] * &f_star_list[i as usize]);
        }

        // Verify we get the same value from shamir transform {Dx = Fx, Dy = Fy, D* = F*, d_k = f_k}
        (0..N).for_each(|i| transcript.append_element(b"Dx", &Fx_list[i as usize]));
        transcript.append_element(b"Dy", &F_y);
        transcript.append_element(b"D*", &F_star);
        (0..R).for_each(|k| {
            transcript.append_element(
                b"d_k",
                &hash_to_curve(&f_list[k as usize].to_bytes()).unwrap(),
            )
        });

        let f_h = transcript.get_challenge(b"D_h");

        if f_h.to_bytes() != self.d_h.to_bytes() {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_3_squares() {
        // sample values of the form 4*x + 1 (including small and larger ones)
        let samples: &[u64] = &[
            1,    // 4*0+1
            5,    // 4*1+1
            9,    // 4*2+1
            13,   // 4*3+1
            21,   // 4*5+1
            101,  // 4*25+1
            1001, // 4*250+1
            4 * 12345 + 1,
            4 * 1_000_000 + 1,
        ];

        for &n in samples {
            match find_3_squares(n) {
                Ok((a, b, c)) => {
                    // ensure they are valid and sum correctly
                    let sum = (a as u128) * (a as u128)
                        + (b as u128) * (b as u128)
                        + (c as u128) * (c as u128);
                    assert_eq!(sum as u64, n, "Decomposition incorrect for n={}", n);
                }
                Err(err) => panic!("find_3_squares failed for n={} with error {:?}", n, err),
            }
        }
    }
}
